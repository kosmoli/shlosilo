//! Sign-request review view — what the operator sees *before* signing.
//!
//! ## Why this exists (and why it is a gate, not a nicety)
//!
//! Until now the product flow went scan → sign: the device signed whatever it
//! decoded, and the only thing on screen was the UR type and a byte count. For
//! XMR that was survivable (the KI legs are exchange legs, and the shipped Cake
//! flow was validated end to end). For BTC/EVM it is not: a PSBT or an EVM
//! transaction is *arbitrary spend authority*, and an air-gapped signer that
//! cannot show the amount and the destination is a blind-signature oracle.
//!
//! This module is the data half of the gate: a **pure, zero-heap** conversion
//! from a request payload into a bounded list of ASCII lines plus risk flags.
//! The platform layer renders the lines and must not call the sign entry until
//! the operator has confirmed them.
//!
//! ## Display safety (UI red line, read this before adding text)
//!
//! Every line here is either a **fixed vocabulary** word ("fee", "in", "out",
//! "to:", "warn: high fee") or a string **re-encoded from decoded structure**
//! (an address rendered from a scriptPubKey, a decimal amount). We never echo
//! raw payload bytes, the UR type name, internal error codes or paths — an
//! attacker controls the request, so anything echoed verbatim becomes a way to
//! draw text on our screen. Addresses are the one place payload-derived data is
//! shown on purpose: the destination is exactly what the operator must verify,
//! and it is safe to show *because* it is canonically re-encoded (charset and
//! length constrained by base58check / bech32 / hex rules), not because the
//! payload said so. Anything that cannot be canonically rendered degrades to
//! the fixed words `unknown script` / `address unavailable`.
//!
//! ## Scope
//!
//! v0 covers BTC (PSBT: fee, input/output counts, per-output address + amount,
//! change marking against our master fingerprint, risk flags) and EVM
//! (chain id, destination, value, calldata size, decoded ERC-20 selector).
//! XMR keeps the shipped flow: its legs are session-bound and were validated
//! with a real wallet, so a review page is a separate product decision, not a
//! by-product of this module.

use crate::address::{btc_script, eth};
use crate::chain::btc::psbt::{self, KvRec, Psbt};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use crate::ur::ur_encode::UrTypeTag;

/// Maximum lines in one review view (paging budget, not a display budget).
pub const REVIEW_LINES_MAX: usize = 16;
/// Maximum ASCII characters per line (the platform wraps anything longer).
pub const REVIEW_LINE_MAX: usize = 48;
/// Outputs summarized in detail; beyond this we only say "many outputs".
pub const REVIEW_OUTPUTS_MAX: usize = 4;

/// Risk flags — every one of them must be rendered as a fixed word by the
/// platform layer; none of them may be silently dropped.
pub mod flag {
    /// At least one input carries no UTXO we can price → fee is a lower bound.
    pub const FEE_UNKNOWN: u16 = 1 << 0;
    /// Fee above the "clearly too much" threshold (see `HIGH_FEE_SATS`).
    pub const HIGH_FEE: u16 = 1 << 1;
    /// Fee larger than every single output amount.
    pub const FEE_GT_AMOUNT: u16 = 1 << 2;
    /// RBF-signalling input (nSequence < 0xfffffffe).
    pub const RBF: u16 = 1 << 3;
    /// An output script we cannot render as an address.
    pub const UNKNOWN_SCRIPT: u16 = 1 << 5;
    /// A sighash other than ALL / DEFAULT (NONE, SINGLE, ANYONECANPAY).
    pub const SIGHASH_UNSAFE: u16 = 1 << 6;
    /// More outputs than we can itemize.
    pub const MANY_OUTPUTS: u16 = 1 << 7;
    /// EVM: the destination is a contract (calldata present) we cannot decode.
    pub const UNKNOWN_CALLDATA: u16 = 1 << 8;
}

/// Fee (in sats) above which we always warn: 0.01 BTC.
pub const HIGH_FEE_SATS: u64 = 1_000_000;

/// One rendered line.
#[derive(Clone)]
pub struct Line {
    text: heapless::String<REVIEW_LINE_MAX>,
}

impl Line {
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }
}

/// A bounded, reviewable view of a sign request.
pub struct ReviewView {
    lines: heapless::Vec<Line, REVIEW_LINES_MAX>,
    pub flags: u16,
    pub input_count: u8,
    pub output_count: u8,
}

impl ReviewView {
    fn new() -> Self {
        ReviewView {
            lines: heapless::Vec::new(),
            flags: 0,
            input_count: 0,
            output_count: 0,
        }
    }

    /// Rendered lines, in display order.
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    fn push_str(&mut self, s: &str) -> Result<()> {
        let mut text = heapless::String::<REVIEW_LINE_MAX>::new();
        text.push_str(s)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        self.lines
            .push(Line { text })
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))
    }

    fn push_fmt(&mut self, args: core::fmt::Arguments<'_>) -> Result<()> {
        use core::fmt::Write;
        let mut text = heapless::String::<REVIEW_LINE_MAX>::new();
        text.write_fmt(args)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        self.lines
            .push(Line { text })
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))
    }

    /// Push a string, splitting it across lines rather than truncating it.
    ///
    /// Addresses are the reason this exists: a P2TR address is 62 characters and
    /// a truncated address is worse than no address (nobody can verify a prefix).
    fn push_wrapped(&mut self, s: &str) -> Result<()> {
        if s.len() <= REVIEW_LINE_MAX {
            return self.push_str(s);
        }
        for chunk in s.as_bytes().chunks(REVIEW_LINE_MAX) {
            let part = core::str::from_utf8(chunk)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            self.push_str(part)?;
        }
        Ok(())
    }
}

/// Build the review view for a decoded sign request.
///
/// `master_fingerprint` (optional) is used to mark outputs that come back to
/// this wallet (change). Without it every output renders as a payment.
pub fn build(
    type_tag: UrTypeTag,
    payload: &[u8],
    network: Network,
    master_fingerprint: Option<&[u8; 4]>,
    arena: &mut [u8],
    recs: &mut [KvRec],
) -> Result<ReviewView> {
    match type_tag {
        UrTypeTag::CryptoPsbt | UrTypeTag::Psbt => {
            build_btc(payload, network, master_fingerprint, arena, recs)
        }
        UrTypeTag::EthSignRequest => build_eth(payload),
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::ChainKindUnsupported)),
    }
}

/// PSBT review. `payload` is either the CBOR byte-string shell or the bare PSBT
/// (the UR exits strip the shell; both shapes are legal — same rule as the sign
/// path).
pub fn build_btc(
    payload: &[u8],
    network: Network,
    master_fingerprint: Option<&[u8; 4]>,
    arena: &mut [u8],
    recs: &mut [KvRec],
) -> Result<ReviewView> {
    use crate::encoding::cbor;
    let psbt_bytes: &[u8] = match cbor::decode(payload) {
        Ok(cbor::Cbor::Bytes(b)) => b,
        _ => payload,
    };
    let psbt = psbt::parse_psbt_any(psbt_bytes, Some(arena), Some(recs))?;
    // The PSBT is authoritative about its own network: the derivation coin type
    // (BIP-44 second component, 1 = testnet/signet) decides the address prefix,
    // so a signet wallet's recipients never render as `bc1…`. The caller's
    // value is only the fallback when no derivation is present.
    let network = infer_network(&psbt).unwrap_or(network);
    summarize_psbt(&psbt, network, master_fingerprint)
}

fn summarize_psbt(
    psbt: &Psbt<'_>,
    network: Network,
    master_fingerprint: Option<&[u8; 4]>,
) -> Result<ReviewView> {
    let mut view = ReviewView::new();
    let in_count = psbt.unsigned_tx.inputs.len();
    let out_count = psbt.unsigned_tx.outputs.len();
    view.input_count = in_count as u8;
    view.output_count = out_count as u8;

    // ── inputs: total value + RBF signalling ──
    let mut total_in: Option<u64> = Some(0);
    let mut rbf = false;
    for i in 0..in_count {
        let map = psbt
            .input_map_checked(i)
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        match psbt::get_witness_utxo(map) {
            Some((amount, _spk)) => {
                total_in = total_in.and_then(|acc| acc.checked_add(amount));
            }
            None => total_in = None,
        }
        if psbt.unsigned_tx.inputs[i].sequence < 0xffff_fffe {
            rbf = true;
        }
        // A sighash other than ALL needs the operator's eyes: NONE and SINGLE let
        // the coordinator rewrite outputs after our signature.
        //
        // Taproot is the exception: BIP-341 defines 0x00 as SIGHASH_DEFAULT, which
        // means exactly ALL (every wallet emits it), so flagging it would fire on
        // every taproot PSBT and train the operator to ignore the line. 0x00 stays
        // unsafe for a non-taproot input, where it is not a legal sighash at all.
        let taproot = map
            .iter()
            .any(|kv| kv.key.first() == Some(&psbt::input_type::TAP_INTERNAL_KEY));
        let sighash = map
            .iter()
            .find(|kv| kv.key.first() == Some(&psbt::input_type::SIGHASH_TYPE))
            .and_then(|kv| kv.value.first().copied());
        if let Some(v) = sighash {
            let all = v == 0x01 || (taproot && v == 0x00);
            if !all {
                view.flags |= flag::SIGHASH_UNSAFE;
            }
        }
    }

    // ── outputs: total + per-output rendering ──
    let mut total_out: u64 = 0;
    let mut out_lines_pushed = 0usize;
    for (i, out) in psbt.unsigned_tx.outputs.iter().enumerate() {
        total_out = total_out.saturating_add(out.value);
        if i >= REVIEW_OUTPUTS_MAX || out_lines_pushed >= REVIEW_OUTPUTS_MAX {
            continue;
        }
        let spk = crate::types::wire_bytes::wire_slice(&out.script_pubkey);
        let owner = match (master_fingerprint, psbt.output_map_checked(i)) {
            (Some(ours), Some(map)) => output_ownership(map, ours),
            _ => Ownership::Foreign,
        };
        // One labelled row per output: the amount carries its unit and the
        // role (send / change) so a page never shows a bare number, and the
        // address follows on its own line (wrapped, never truncated).
        view.push_fmt(format_args!(
            "{} {} sats",
            match owner {
                Ownership::OwnChange => "change",
                Ownership::OwnReceive => "to you",
                Ownership::Foreign => "send",
            },
            out.value
        ))?;
        match btc_script::render(spk, network) {
            Ok(addr) => view.push_wrapped(<_ as AsRef<str>>::as_ref(&addr))?,
            Err(_) => {
                view.flags |= flag::UNKNOWN_SCRIPT;
                view.push_str("address unknown")?;
            }
        }
        out_lines_pushed += 2;
    }
    if out_count > REVIEW_OUTPUTS_MAX {
        view.flags |= flag::MANY_OUTPUTS;
    }

    // ── fee + totals (pushed first, so the summary is at the top) ──
    let mut head: heapless::Vec<Line, 5> = heapless::Vec::new();
    let mut push_head = |args: core::fmt::Arguments<'_>| -> Result<()> {
        use core::fmt::Write;
        let mut text = heapless::String::<REVIEW_LINE_MAX>::new();
        text.write_fmt(args)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        head.push(Line { text })
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))
    };
    // No title line: the page header already says "review"; every body line
    // must carry information (first real-device layout review, 2026-11-05).
    push_head(format_args!("in {} / out {}", in_count, out_count))?;
    match total_in {
        Some(ti) if ti >= total_out => {
            let fee = ti - total_out;
            push_head(format_args!("fee {} sats", fee))?;
            if fee > HIGH_FEE_SATS {
                view.flags |= flag::HIGH_FEE;
            }
            // "Fee larger than any single payment" is the classic drain shape.
            if psbt.unsigned_tx.outputs.iter().all(|o| o.value < fee) {
                view.flags |= flag::FEE_GT_AMOUNT;
            }
        }
        Some(_) => {
            // outputs exceed inputs: the coordinator built an invalid tx
            view.flags |= flag::FEE_GT_AMOUNT;
            push_head(format_args!("fee: outputs exceed inputs"))?;
        }
        None => {
            view.flags |= flag::FEE_UNKNOWN;
            push_head(format_args!("fee unknown (input value missing)"))?;
        }
    }
    // Fee rate: an ESTIMATE, and labelled as one. The witness of an unsigned
    // transaction is not written yet, so the exact vsize does not exist; we weight
    // each input by its script type from the witness UTXO (the standard estimates:
    // P2WPKH 272 WU, P2TR 230, P2SH-P2WPKH 364, P2PKH 592). Any input or output
    // whose type we cannot price drops the line entirely rather than guessing.
    if let (Some(ti), true) = (total_in, total_in.is_some()) {
        if ti >= total_out {
            let fee = ti - total_out;
            if let Some(wu) = estimated_weight(psbt) {
                let vb = wu.div_ceil(4);
                if vb > 0 {
                    let hundredths = fee_rate_hundredths(fee, wu);
                    // Two decimals, matching what wallets display: a whole-number
                    // truncation once reported 1.317 sat/vB as "1".
                    push_head(format_args!(
                        "fee rate ~{}.{:02} sat/vB",
                        hundredths / 100,
                        hundredths % 100
                    ))?;
                }
            }
        }
    }

    // RBF is an OPERATIONAL property, not a security one: it only says the
    // transaction can still be fee-bumped, which wallets advertise as "speed
    // up" and therefore enable by default. Warning on it would fire on most
    // transactions and dilute the warnings that matter (sighash, fee anomalies).
    // Both states are reported instead, because the notable one is the ABSENCE:
    // a non-replaceable transaction is locked in — if the fee is too low it
    // cannot be fixed. The operator decides; we do not label it a risk.
    view.flags |= if rbf { flag::RBF } else { 0 };

    // Locktime is REPORTED, not judged. Bitcoin Core — and therefore Sparrow —
    // stamps every transaction with the current block height (anti-fee-sniping),
    // and offline we cannot tell that height from a deliberately future one. The
    // honest move is to show the value and its domain so the operator can judge;
    // suppressing it would hide a real time-lock, and warning on every tx would
    // train the operator to ignore warnings.
    if psbt.unsigned_tx.lock_time != 0 {
        let lock = psbt.unsigned_tx.lock_time;
        let domain = match locktime_domain(lock) {
            LocktimeDomain::Height => "height",
            LocktimeDomain::Time => "time",
        };
        if all_inputs_final(psbt) {
            // nLockTime is inert when every input is final (consensus).
            push_head(format_args!("locktime {} {} ignored", lock, domain))?;
        } else {
            push_head(format_args!("locktime {} {}", lock, domain))?;
        }
    }
    push_head(format_args!(
        "replaceable {}",
        if rbf { "yes" } else { "no" }
    ))?;

    // head -> warnings -> body. The warnings sit directly under the totals so
    // they are never below the fold of a one-page review.
    let mut merged: heapless::Vec<Line, REVIEW_LINES_MAX> = heapless::Vec::new();
    for line in head.iter() {
        merged
            .push(line.clone())
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    for warn in warn_lines(view.flags).into_iter().flatten() {
        let mut text = heapless::String::<REVIEW_LINE_MAX>::new();
        text.push_str(warn)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        merged
            .push(Line { text })
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    for line in view.lines.iter() {
        merged
            .push(line.clone())
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    view.lines = merged;
    Ok(view)
}

/// Fee rate in **hundredths** of a sat/vB, rounded.
///
/// Two decimals because that is the resolution wallets show (Sparrow prints 1.45)
/// and the operator compares our line against theirs: `1.4` next to their `1.45`
/// reads as a disagreement when it is only rounding.
///
/// Integer arithmetic on purpose (no_std, no floats, deterministic): `fee * 100` is
/// carried in weight units so the division rounds exactly once. Calibrated against
/// real transactions on chain: (105 sat, 860 WU) -> 12 = 0.12? no: 100ths,
/// (55 sat, 446 WU) -> 49 = 0.49 (chain 0.495), (218 sat, 664 WU) -> 131 = 1.31
/// (chain 1.317), (225 sat, ~155 vB) -> 145 = 1.45 (operator's mainnet run).
pub fn fee_rate_hundredths(fee: u64, wu: u32) -> u64 {
    let wu = u64::from(wu);
    if wu == 0 {
        return 0;
    }
    // fee / (wu/4) * 100 = fee * 400 / wu
    (fee * 400 + wu / 2) / wu
}

/// Estimated transaction weight from the script types the PSBT discloses.
///
/// Standard per-input weights (witness included): P2WPKH 272, P2TR key-path 230,
/// P2SH-P2WPKH 364, P2PKH 592. Per-output: P2WPKH 124, P2SH 128, P2TR 172,
/// P2PKH 136. Base overhead (version, locktime, counts, segwit marker) 44.
///
/// `None` when any input or output has a script type we cannot price: a fee rate
/// computed from a partial picture is worse than no fee rate.
fn estimated_weight(psbt: &Psbt<'_>) -> Option<u32> {
    // Base overhead = 10 bytes × 4 + 2 (segwit marker/flag) = 42 WU:
    // version 4 + locktime 4 + the two count varints 1+1 = 10 base bytes, plus the
    // marker/flag pair that exists only in the witness serialization.
    //
    // 44 was an over-estimate that cost a full sat/vB step on small transactions:
    // 192 sat over a 1-in/2-out nested-segwit tx read `~1.16` while Sparrow showed
    // 1.17 (operator report, 2026-11-11). With 42 those agree.
    let mut wu: u32 = 42;
    for i in 0..psbt.unsigned_tx.inputs.len() {
        let map = psbt.input_map_checked(i)?;
        let (_, spk) = psbt::get_witness_utxo(map)?;
        wu = wu.checked_add(script_weight(
            crate::types::wire_bytes::wire_slice(&spk),
            true,
        )?)?;
    }
    for out in psbt.unsigned_tx.outputs.iter() {
        let spk = crate::types::wire_bytes::wire_slice(&out.script_pubkey);
        wu = wu.checked_add(script_weight(spk, false)?)?;
    }
    Some(wu)
}

/// Weight unit cost of spending (input) or creating (output) one script type.
fn script_weight(spk: &[u8], input: bool) -> Option<u32> {
    let kind = match spk {
        [0x00, 0x14, h @ ..] if h.len() == 20 => {
            if input {
                272
            } else {
                124
            }
        } // P2WPKH
        [0x51, 0x20, x @ ..] if x.len() == 32 => {
            if input {
                230
            } else {
                172
            }
        } // P2TR key path
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => {
            if input {
                364
            } else {
                128
            }
        } // P2SH(-P2WPKH)
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => {
            if input {
                592
            } else {
                136
            }
        } // P2PKH
        _ => return None,
    };
    Some(kind)
}

/// Network implied by the inputs' BIP-44 coin type (1 → testnet/signet).
///
/// Reviewed as "the PSBT tells us where it lives": wallets put the coin type in
/// the derivation path they hand the signer, and a mismatched address prefix is
/// exactly the kind of error the operator would mis-read.
fn infer_network(psbt: &Psbt<'_>) -> Option<Network> {
    for i in 0..psbt.unsigned_tx.inputs.len() {
        let map = psbt.input_map_checked(i)?;
        let mut coin: Option<u32> = None;
        // A taproot-only PSBT carries its paths under 0x16; reading just 0x02 would
        // fall back to the caller's network and render a signet address as `bc1…`.
        if coin.is_none() {
            if let Some((_, tap)) = psbt::get_tap_bip32_derivation(map) {
                let d = tap.depth as usize;
                if d >= 2 {
                    coin = Some(tap.elements[1] & 0x7fff_ffff);
                }
            }
        }
        for kv in map.iter() {
            if kv.key.first() != Some(&psbt::input_type::BIP32_DERIVATION) || kv.value.len() < 12 {
                continue;
            }
            // value = fingerprint(4) || path elements (u32 LE each)
            let elems = &kv.value[4..];
            if elems.len() >= 8 {
                coin = Some(
                    u32::from_le_bytes([elems[4], elems[5], elems[6], elems[7]]) & 0x7fff_ffff,
                );
                break;
            }
        }
        if let Some(c) = coin {
            return Some(if c == 1 {
                Network::BitcoinTestnet
            } else {
                Network::BitcoinMainnet
            });
        }
    }
    None
}

/// `nLockTime` >= this value is a unix timestamp, below it a block height
/// (Bitcoin consensus; same constant as `chain::btc::summary`).
const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Every input final? Then `nLockTime` is ignored by consensus entirely.
fn all_inputs_final(psbt: &Psbt<'_>) -> bool {
    psbt.unsigned_tx
        .inputs
        .iter()
        .all(|i| i.sequence == 0xffff_ffff)
}

/// Which consensus domain a non-zero `nLockTime` belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LocktimeDomain {
    /// Block height: final once the chain passes it.
    Height,
    /// Unix timestamp: final once wall-clock time passes it.
    Time,
}

/// Classify `nLockTime` (>= 500M is a timestamp, below is a height).
pub fn locktime_domain(lock_time: u32) -> LocktimeDomain {
    if lock_time >= LOCKTIME_THRESHOLD {
        LocktimeDomain::Time
    } else {
        LocktimeDomain::Height
    }
}

/// Fixed-vocabulary warning rows for the risk flags.
///
/// One flag = one row, and the row is emitted only when the flag is set. Text is
/// a closed vocabulary (ASCII, no payload content): the operator reads "what
/// kind of risk", not a rendered payload field. Ordering is fixed so the eye
/// finds the same warning in the same place on every transaction.
fn warn_lines(flags: u16) -> [Option<&'static str>; 5] {
    [
        if flags & flag::SIGHASH_UNSAFE != 0 {
            Some("warn: sighash not all")
        } else {
            None
        },
        if flags & flag::FEE_GT_AMOUNT != 0 {
            Some("warn: fee over amount")
        } else {
            None
        },
        if flags & flag::HIGH_FEE != 0 {
            Some("warn: high fee")
        } else {
            None
        },
        if flags & flag::UNKNOWN_CALLDATA != 0 {
            Some("warn: unknown call")
        } else {
            None
        },
        if flags & flag::MANY_OUTPUTS != 0 {
            Some("warn: outputs not listed")
        } else {
            None
        },
    ]
}

/// An output belongs to us when its output-map BIP32_DERIVATION carries our
/// master fingerprint. Absent fingerprint or absent record → treated as foreign
/// (a payment), which is the conservative reading for a review screen.
/// Who owns an output, as far as the PSBT itself can tell us.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ownership {
    /// No derivation record for us: money leaving to someone else.
    Foreign,
    /// Our own key on the **external** chain (`…/0/i`): a payment to one of our
    /// own receive addresses.
    OwnReceive,
    /// Our own key on the **internal** chain (`…/1/i`): change coming back.
    OwnChange,
}

/// Classify an output by the BIP-32 derivation record in its output map.
///
/// The chain index (second-to-last path element) is the wallet's own statement
/// about what the output is for: 0 = receive chain, 1 = change chain. Trusting
/// "has our fingerprint" alone lumps a self-payment together with change — the
/// first real-device review (2026-11-05) showed both outputs labelled `change`
/// on a payment to our own receive address.
fn output_ownership(map: psbt::KvMap<'_>, ours: &[u8; 4]) -> Ownership {
    // Taproot outputs record their path under 0x16, not 0x02. Without this the
    // change of a P2TR spend comes back as a fresh payment - the operator sees an
    // outgoing amount that is really their own money returning.
    if let Some((fingerprint, path)) = psbt::get_output_tap_bip32_derivation(map) {
        if fingerprint == *ours {
            return ownership_from_elements(&path.elements[..path.depth as usize]);
        }
    }
    for kv in map.iter() {
        // OUTPUT map: BIP-174 assigns the output-side derivation a different
        // key byte (0x02) than the input side (0x06). Using the input constant
        // here silently matched nothing, so change outputs were reported as
        // payments forever (caught by change_output_is_labelled_…, 2026-11-05).
        if kv.key.first() != Some(&psbt::output_type::BIP32_DERIVATION)
            || kv.value.len() < 8
            || kv.value[..4] != ours[..]
        {
            continue;
        }
        // value = fingerprint(4) || path elements as u32 LE each
        let elems = &kv.value[4..];
        let depth = elems.len() / 4;
        let mut path = [0u32; crate::derivation::path::MAX_DEPTH];
        if depth > path.len() {
            return Ownership::OwnReceive;
        }
        for (i, chunk) in elems.as_chunks::<4>().0.iter().enumerate().take(depth) {
            path[i] = u32::from_le_bytes(*chunk);
        }
        return ownership_from_elements(&path[..depth]);
    }
    Ownership::Foreign
}

/// Change vs receive from a derivation path: the **second-to-last** element is
/// the chain/index component that BIP-44 fixes to 0 = receive, 1 = change.
fn ownership_from_elements(elements: &[u32]) -> Ownership {
    if elements.len() < 2 {
        return Ownership::OwnReceive; // too short to tell: assume not change
    }
    let chain = elements[elements.len() - 2] & 0x7fff_ffff;
    if chain == 1 {
        Ownership::OwnChange
    } else {
        Ownership::OwnReceive
    }
}

/// EVM review: chain id, destination, value, calldata size.
pub fn build_eth(payload: &[u8]) -> Result<ReviewView> {
    use crate::chain::eth::from_rlp;
    use crate::ur::codec::eth_sign_request::{parse_eth_sign_request, EthSignDataType};

    let req = parse_eth_sign_request(payload)?;
    let mut view = ReviewView::new();
    match req.data_type {
        EthSignDataType::Transaction | EthSignDataType::TypedTransaction => {}
        EthSignDataType::TypedData => {
            view.push_str("eth typed data")?;
            view.push_str("cannot display on this screen")?;
            view.push_str("review in your wallet")?;
            return Ok(view);
        }
        EthSignDataType::PersonalMessage => {
            view.push_str("eth message sign")?;
            view.push_str("cannot display on this screen")?;
            view.push_str("review in your wallet")?;
            return Ok(view);
        }
    }

    let tx = from_rlp::parse_eip1559_raw(req.sign_data)?;
    view.push_str("eth send request")?;
    // Name the chain when we know it: `chain 1` alone does not tell the operator
    // which network they are spending on, and a wrong-network send is not
    // recoverable. Unknown ids are printed raw - we do not guess a name.
    match crate::chain::eth::chain_names::chain_name(tx.chain_id) {
        Some(name) => view.push_fmt(format_args!("chain {} {}", tx.chain_id, name))?,
        None => view.push_fmt(format_args!("chain {}", tx.chain_id))?,
    }
    match tx.destination {
        Some(dest) => {
            let rendered = eth::encode_bytes(&dest)?;
            view.push_str("to:")?;
            view.push_wrapped(<_ as AsRef<str>>::as_ref(&rendered))?;
        }
        None => view.push_str("to: contract creation")?,
    }
    view.push_fmt(format_args!("value {}", tx.amount))?;
    view.push_fmt(format_args!("gas limit {}", tx.gas_limit))?;
    let calldata = crate::types::wire_bytes::wire_slice(&tx.data);
    if calldata.is_empty() {
        view.push_str("data: none")?;
    } else {
        view.push_fmt(format_args!("data {} bytes", calldata.len()))?;
        match crate::chain::eth::calldata::decode_calldata(calldata) {
            Ok(decoded) => view.push_fmt(format_args!("call {}", decoded.kind_str()))?,
            Err(_) => {
                view.flags |= flag::UNKNOWN_CALLDATA;
                view.push_str("call: unknown contract")?;
            }
        }
    }
    Ok(view)
}
