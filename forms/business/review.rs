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
pub const REVIEW_LINES_MAX: usize = crate::limits::REVIEW_LINES_MAX;
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
        // `get_utxo_any`, not `get_witness_utxo`: a legacy (P2PKH) input carries
        // NON_WITNESS_UTXO (0x00) instead of a witness UTXO, and the operator must
        // still see the fee total for exactly those requests.
        let prev_out = psbt.unsigned_tx.inputs[i].prev_out.clone();
        match psbt::get_utxo_any(map, &prev_out) {
            Some((amount, _spk)) => {
                total_in = total_in.and_then(|acc| acc.checked_add(amount));
            }
            None => {
                // A request the device already knows it cannot sign must not be
                // presented for confirmation: refuse here, at the boundary, so the
                // operator is never asked to authorise the impossible. The platform
                // shows the failure page for this code ("request input data
                // missing") and the flow ends at welcome.
                return Err(ShlosiloError::new(ShlosiloErrorKind::PrevoutMissing));
            }
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
        // BTC-2 (external audit 2026-11-19): read the declaration through the SAME
        // accessor the signer uses. The old code matched the key's first byte and took the
        // value's first byte, so a malformed key could show the operator a different
        // sighash than the one the device would sign. An entry that exists but cannot be
        // read is treated as unsafe, never as "absent".
        match psbt::input_sighash_type(map) {
            Ok(Some(v)) => {
                let all = v == 0x01 || (taproot && v == 0x00);
                if !all {
                    view.flags |= flag::SIGHASH_UNSAFE;
                }
            }
            Ok(None) => {}
            Err(_) => view.flags |= flag::SIGHASH_UNSAFE,
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
                // Neutral, not a warning: the operator sees what happened (a derivation
                // record we could not read) and judges it. Filtering it into "send"
                // would be a claim we cannot support.
                Ownership::Unreadable => "unclassified",
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
/// The model is the same one Sparrow uses (`drongo Transaction.getWeightUnits()`:
/// version 16 WU + marker/flag 2 + count varints × 4 + serialized inputs × 4 +
/// serialized outputs × 4 + witness bytes + locktime 16), applied to *estimated*
/// element sizes because an unsigned transaction has no witness yet.
///
/// ECDSA signatures are taken as **71 bytes** (low-S DER + sighash byte): our device
/// normalises S, so its own signature is 70-71 bytes rather than the 72 a naive model
/// assumes. That single byte is worth ~4 WU on a 1-in/2-out transaction, and it is the
/// whole difference the operator saw between our 1.74 and Sparrow's 1.75 (which the
/// wallet measured on the signed bytes).
///
/// Per-input weights: P2WPKH 271, P2TR key-path 230 (schnorr is fixed 64 + sighash,
/// no DER slack), P2SH-P2WPKH 363, P2PKH 588. Per-output: P2WPKH 124, P2SH 128,
/// P2TR 172, P2PKH 136. Base overhead 42 (10.5 vB).
///
/// `None` when any input or output has a script type we cannot price: a fee rate
/// computed from a partial picture is worse than no fee rate.
fn estimated_weight(psbt: &Psbt<'_>) -> Option<u32> {
    // Base overhead = 10 bytes × 4 = 40 WU (version 4 + locktime 4 + the two count
    // varints 1+1), plus the 2 WU marker/flag pair **only when the transaction has a
    // witness section at all**. A spend whose inputs are all legacy P2PKH serializes
    // without marker/flag, so charging 42 was 2 WU of pure fiction — measured on a
    // real mainnet legacy spend (2026-11-14): 1 P2PKH in / 1 P2WPKH out weighs 756 WU
    // (vs 756 with 40 + 592 + 124, 758 with 42 + 588 + 124).
    //
    // 44 was an over-estimate that cost a full sat/vB step on small transactions:
    // 192 sat over a 1-in/2-out nested-segwit tx read `~1.16` while Sparrow showed
    // 1.17 (operator report, 2026-11-11). With 42 those agree.
    let mut wu: u32 = 40;
    let mut any_witness_input = false;
    for i in 0..psbt.unsigned_tx.inputs.len() {
        let map = psbt.input_map_checked(i)?;
        // 0x00 (NON_WITNESS_UTXO) accepts legacy inputs as well; without it the
        // fee-rate line would vanish for every P2PKH request.
        let prev_out = psbt.unsigned_tx.inputs[i].prev_out.clone();
        let (_, spk) = psbt::get_utxo_any(map, &prev_out)?;
        let spk = crate::types::wire_bytes::wire_slice(&spk);
        if !matches!(spk, [0x76, 0xa9, 0x14, _h @ .., 0x88, 0xac] if _h.len() == 20) {
            any_witness_input = true;
        }
        wu = wu.checked_add(script_weight(spk, true)?)?;
    }
    if any_witness_input {
        wu = wu.checked_add(2)?;
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
                271
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
                363
            } else {
                128
            }
        } // P2SH(-P2WPKH)
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => {
            if input {
                // 148 serialized bytes: outpoint 36 + scriptSig len 1 + scriptSig 107
                // + sequence 4. The scriptSig is `<push 72-byte sig><push 33-byte key>`,
                // i.e. the sig element is modelled at its low-S maximum (DER 71 +
                // hash type) rather than the 71 a witness element gets away with:
                // a legacy signature byte costs 4 WU (base serialization), not 1.
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
            if let Ok(Some((_, tap))) = psbt::get_tap_bip32_derivation(map) {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ownership {
    /// No derivation record for us: money leaving to someone else.
    Foreign,
    /// Our own key on the **external** chain (`…/0/i`): a payment to one of our
    /// own receive addresses.
    OwnReceive,
    /// Our own key on the **internal** chain (`…/1/i`): change coming back.
    OwnChange,
    /// The map has a derivation record for us, but its path cannot be read exactly
    /// (a length that is not a whole number of `u32`s, or more elements than we can hold).
    ///
    /// A2-05 (external audit 2026-11-19): both cases used to fall through to a verdict —
    /// the remainder bytes were dropped and the truncated path still classified, and a
    /// too-deep path returned `OwnReceive` without reading anything. A review screen must
    /// not present a guess as evidence, so the row now says it could not classify.
    Unreadable,
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
    // A malformed/ambiguous record is not evidence about ownership (F-6): the review row says
    // `unclassified` instead of picking one record by map order.
    if let Ok(Some((fingerprint, path))) = psbt::get_output_tap_bip32_derivation(map) {
        if fingerprint == *ours || psbt::fingerprint_is_unspecified(fingerprint) {
            let depth = path.depth as usize;
            if depth > path.elements.len() {
                return Ownership::Unreadable;
            }
            return ownership_from_elements(&path.elements[..depth]);
        }
    }
    for kv in map.iter() {
        // OUTPUT map: BIP-174 assigns the output-side derivation a different
        // key byte (0x02) than the input side (0x06). Using the input constant
        // here silently matched nothing, so change outputs were reported as
        // payments forever (caught by change_output_is_labelled_…, 2026-11-05).
        if kv.key.first() != Some(&psbt::output_type::BIP32_DERIVATION) || kv.value.len() < 8 {
            continue;
        }
        // A zeroed fingerprint is "unspecified", not "foreign": without this a
        // Cake-built PSBT labelled its own change as an outgoing payment.
        let rec_fp = [kv.value[0], kv.value[1], kv.value[2], kv.value[3]];
        if rec_fp != *ours && !psbt::fingerprint_is_unspecified(rec_fp) {
            continue;
        }
        // value = fingerprint(4) || path elements as u32 LE each
        let elems = &kv.value[4..];
        // The path must be a whole number of u32s: a stray tail means the record is not
        // what we think it is, and classifying a truncated path would invent a chain index.
        if elems.len() % 4 != 0 {
            return Ownership::Unreadable;
        }
        let depth = elems.len() / 4;
        let mut path = [0u32; crate::derivation::path::MAX_DEPTH];
        if depth > path.len() {
            return Ownership::Unreadable;
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
/// Render a decoded EVM call so the operator sees WHO and HOW MUCH, not just a method
/// name.
///
/// ETH-10 (external audit 2026-11-19): the review page printed `call erc20 transfer` and
/// nothing else. Two different recipients — or an `approve` of 1 unit versus an unlimited
/// allowance — produced byte-identical screens, so the confirmation gate could not tell a
/// payment from a different payment. Amounts are printed as RAW integers (hex, or the
/// words "unlimited" for 2^256-1); token decimals are not guessed, because a wrong decimal
/// point is worse than no decimal point.
fn push_decoded_calldata(
    view: &mut ReviewView,
    decoded: &crate::chain::eth::calldata::DecodedCalldata,
) -> Result<()> {
    use crate::chain::eth::calldata::DecodedCalldata as D;

    /// 20-byte address → the same EIP-55 checksummed form the destination line uses.
    fn push_addr(view: &mut ReviewView, label: &str, addr: &[u8; 20]) -> Result<()> {
        let rendered = crate::address::eth::encode_bytes(addr)?;
        view.push_str(label)?;
        view.push_wrapped(<_ as AsRef<str>>::as_ref(&rendered))
    }

    /// 256-bit big-endian → "unlimited" for 2^256-1, else 0x-hex without leading zeros.
    fn push_amount(view: &mut ReviewView, label: &str, amount: &[u8; 32]) -> Result<()> {
        view.push_str(label)?;
        if amount.iter().all(|&b| b == 0xff) {
            return view.push_str("unlimited");
        }
        let first = amount
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(amount.len() - 1);
        let mut text = heapless::String::<REVIEW_LINE_MAX>::new();
        use core::fmt::Write as _;
        text.push_str("0x")
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        for &b in &amount[first..] {
            write!(&mut text, "{b:02x}")
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        }
        view.push_wrapped(text.as_str())
    }

    match decoded {
        D::Empty => view.push_str("call: no calldata"),
        D::Transfer { to, amount } => {
            view.push_str("erc20 transfer")?;
            push_addr(view, "recipient", to)?;
            push_amount(view, "amount", amount)
        }
        D::Approve { spender, amount } => {
            view.push_str("erc20 approve")?;
            push_addr(view, "spender", spender)?;
            push_amount(view, "allowance", amount)
        }
        D::IncreaseAllowance { spender, added } => {
            view.push_str("erc20 increase allowance")?;
            push_addr(view, "spender", spender)?;
            push_amount(view, "added", added)
        }
        D::TransferFrom { from, to, amount } => {
            view.push_str("erc20 transfer from")?;
            push_addr(view, "from", from)?;
            push_addr(view, "recipient", to)?;
            push_amount(view, "amount", amount)
        }
        D::SetApprovalForAll { operator, approved } => {
            view.push_str("set approval for all")?;
            push_addr(view, "operator", operator)?;
            view.push_str(if *approved {
                "approved: yes"
            } else {
                "approved: no"
            })
        }
        // Selector recognised, arguments NOT split: say so instead of implying a full
        // decode (an NFT transfer and an NFT approval must not look the same).
        D::KnownSelector { name, .. } => {
            view.push_str(name)?;
            view.push_str("args not decoded")
        }
        // A3c-F12 (2026-11-20): the calldata has a known selector but NOT that call's canonical
        // length. The extra bytes are signed too, so this must not read like a clean transfer.
        D::ShapeMismatch { name, .. } => {
            view.push_str(name)?;
            view.push_str("shape does not match")
        }
        D::Unknown { .. } => view.push_str("call: unknown contract"),
    }
}

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
            Ok(decoded) => {
                if matches!(
                    decoded,
                    crate::chain::eth::calldata::DecodedCalldata::Unknown { .. }
                        | crate::chain::eth::calldata::DecodedCalldata::ShapeMismatch { .. }
                ) {
                    view.flags |= flag::UNKNOWN_CALLDATA;
                }
                push_decoded_calldata(&mut view, &decoded)?;
            }
            Err(_) => {
                view.flags |= flag::UNKNOWN_CALLDATA;
                view.push_str("call: unknown contract")?;
            }
        }
    }
    Ok(view)
}

#[cfg(test)]
mod output_ownership_pins {
    use super::*;
    use crate::chain::btc::psbt::{output_type, KeyValue};

    const OURS: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    /// Control: a well-formed change record still classifies as change.
    #[test]
    fn well_formed_change_path_classifies() {
        // fingerprint(4) || 84' / 0' / 0' / 1 / 5 — the second-to-last element is the
        // chain index, and 1 is the change chain.
        let mut value = alloc::vec![0u8; 4 + 5 * 4];
        value[..4].copy_from_slice(&OURS);
        for (i, elem) in [0x8000_0054u32, 0x8000_0000, 0x8000_0000, 1, 5]
            .iter()
            .enumerate()
        {
            value[4 + i * 4..8 + i * 4].copy_from_slice(&elem.to_le_bytes());
        }
        let kv = [KeyValue {
            key: alloc::vec![output_type::BIP32_DERIVATION].into(),
            value: value.clone().into(),
        }];
        assert_eq!(
            output_ownership(psbt::KvMap::from_slice(&kv), &OURS),
            Ownership::OwnChange
        );
    }

    /// A2-05 (external audit 2026-11-19): a path tail that is not a whole `u32` must not be
    /// chopped off and classified anyway — that invents a chain index out of a short read.
    /// The row says `unclassified` instead of claiming `change` or `send`.
    #[test]
    fn truncated_path_is_not_classified() {
        // fingerprint(4) || one full element || 3 stray bytes
        let mut value = value_with(&[0x8000_0000u32]);
        value.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let kv = [KeyValue {
            key: alloc::vec![output_type::BIP32_DERIVATION].into(),
            value: value.into(),
        }];
        assert_eq!(
            output_ownership(psbt::KvMap::from_slice(&kv), &OURS),
            Ownership::Unreadable
        );
    }

    /// Same item, second shape: more path elements than the fixed array holds used to return
    /// `OwnReceive` without reading a single element — "ours" as a guess. It now refuses to
    /// classify.
    #[test]
    fn over_deep_path_is_not_classified() {
        let too_deep = alloc::vec![0u32; crate::derivation::path::MAX_DEPTH + 1];
        let value = value_with(&too_deep);
        let kv = [KeyValue {
            key: alloc::vec![output_type::BIP32_DERIVATION].into(),
            value: value.into(),
        }];
        assert_eq!(
            output_ownership(psbt::KvMap::from_slice(&kv), &OURS),
            Ownership::Unreadable
        );
    }

    fn value_with(path: &[u32]) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![0u8; 4];
        v[..4].copy_from_slice(&OURS);
        for e in path {
            v.extend_from_slice(&e.to_le_bytes());
        }
        v
    }
}

#[cfg(test)]
mod calldata_render_pins {
    use super::*;

    /// ETH-10 (external audit 2026-11-19): the confirmation page must distinguish
    /// payments. Before this pin it printed only `call erc20 transfer`, so two different
    /// recipients — or an approve of 1 vs. an unlimited allowance — were the same screen.
    #[test]
    fn eth_calldata_rendering_distinguishes_who_and_how_much() {
        use crate::chain::eth::calldata::DecodedCalldata as D;

        fn render(d: &D) -> alloc::string::String {
            let mut v = ReviewView::new();
            push_decoded_calldata(&mut v, d).expect("fits");
            let mut out = alloc::string::String::new();
            for line in v.lines() {
                out.push_str(line.as_str());
                out.push('|');
            }
            out
        }

        let mut a = [0u8; 20];
        a[19] = 0x11;
        let mut b = [0u8; 20];
        b[19] = 0x22;
        let mut one = [0u8; 32];
        one[31] = 1;
        let unlimited = [0xffu8; 32];

        let ta = render(&D::Transfer { to: a, amount: one });
        let tb = render(&D::Transfer { to: b, amount: one });
        assert_ne!(ta, tb, "two recipients rendered identically");

        let ap = render(&D::Approve {
            spender: a,
            amount: one,
        });
        assert_ne!(ta, ap);
        assert!(ta.contains("erc20 transfer"), "{ta}");
        assert!(ap.contains("erc20 approve"), "{ap}");

        let un = render(&D::Approve {
            spender: a,
            amount: unlimited,
        });
        assert!(
            un.contains("unlimited"),
            "unlimited allowance not called out: {un}"
        );
        assert_ne!(un, ap, "1 unit and 2^256-1 rendered identically");

        let ks = render(&D::KnownSelector {
            name: "nft transfer",
            selector: [1, 2, 3, 4],
        });
        assert!(ks.contains("args not decoded"), "{ks}");
    }
}
