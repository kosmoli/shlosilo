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
//! Every line here is either a **fixed vocabulary** word ("fee", "fee >=", "in",
//! "out", "to:", "warn: high fee") or a string **re-encoded from decoded structure**
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
//!
//! ## Chain axis (design note §9.3-2, batch 1)
//!
//! The page renders BTC (PSBT) and ETH (EVM) requests, so each renderer is gated by
//! its own `chain-*` feature and the module survives on either one alone. With
//! both switches off the module has nothing left to render: `build` keeps its
//! ABI-shaped signature and answers `ChainKindUnsupported`, and the shared page
//! scaffolding (`ReviewView`, paging) is dead by construction — hence the targeted
//! `dead_code` allowance below. It is scoped to exactly that combination, so a
//! build that carries either chain still gets the lint.
#![cfg_attr(
    not(any(feature = "chain-btc", feature = "chain-eth")),
    allow(dead_code)
)]

#[cfg(feature = "chain-btc")]
use crate::address::btc_script;
#[cfg(feature = "chain-eth")]
use crate::address::eth;
#[cfg(feature = "chain-btc")]
use crate::chain::btc::psbt::{self, KvRec, Psbt};
#[cfg(feature = "chain-eth")]
use crate::chain::eth::eip712_pool::{self, Eip712Node, Eip712Pool, KIND_ARRAY, KIND_STRUCT};
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
    /// At least one input amount came from a `WITNESS_UTXO` declaration, so nothing binds it to the
    /// outpoint (BIP-174) and the fee shown is a LOWER BOUND, not an exact figure.
    pub const FEE_UNVERIFIED: u16 = 1 << 9;
}

/// Fee (in sats) above which we always warn: 0.01 BTC.
pub const HIGH_FEE_SATS: u64 = 1_000_000;

/// One rendered line.
#[derive(Clone)]
pub struct Line {
    text: heapless::String<REVIEW_LINE_MAX>,
    /// This line must not open a page: it belongs with the one above it (a label and
    /// its value). The platform paginator asks [`page_span`] where a page ends, so the
    /// semantic half of "keep these together" lives here and the layout half (how many
    /// rows fit) stays with the carrier.
    no_break_before: bool,
}

impl Line {
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }
}

/// A bounded, reviewable view of a sign request.
pub struct ReviewView {
    lines: heapless::Vec<Line, REVIEW_LINES_MAX>,
    /// Set by [`glue_next_line`](ReviewView::glue_next_line): the next pushed line rides
    /// with the one just pushed instead of opening a page.
    glue_next: bool,
    pub flags: u16,
    pub input_count: u8,
    pub output_count: u8,
}

impl ReviewView {
    fn new() -> Self {
        ReviewView {
            lines: heapless::Vec::new(),
            glue_next: false,
            flags: 0,
            input_count: 0,
            output_count: 0,
        }
    }

    /// Rendered lines, in display order.
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// The next pushed line belongs with the one above it (label → value).
    ///
    /// Called right after a label so the paginator cannot open a page between them.
    #[cfg(feature = "chain-eth")]
    fn glue_next_line(&mut self) {
        self.glue_next = true;
    }

    fn push_str(&mut self, s: &str) -> Result<()> {
        let mut text = heapless::String::<REVIEW_LINE_MAX>::new();
        text.push_str(s)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        let no_break_before = core::mem::replace(&mut self.glue_next, false);
        self.lines
            .push(Line {
                text,
                no_break_before,
            })
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))
    }

    fn push_fmt(&mut self, args: core::fmt::Arguments<'_>) -> Result<()> {
        use core::fmt::Write;
        let mut text = heapless::String::<REVIEW_LINE_MAX>::new();
        text.write_fmt(args)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        let no_break_before = core::mem::replace(&mut self.glue_next, false);
        self.lines
            .push(Line {
                text,
                no_break_before,
            })
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
        // Only the FIRST chunk carries the glue flag (push_str consumes it); the
        // continuation chunks may break, or one long address could own a whole page.
        for chunk in s.as_bytes().chunks(REVIEW_LINE_MAX) {
            let part = core::str::from_utf8(chunk)
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            self.push_str(part)?;
        }
        Ok(())
    }

    /// Bit `i` set = line `i` must not open a page. See [`Line::no_break_before`].
    pub fn break_mask(&self) -> u64 {
        let mut mask = 0u64;
        for (i, line) in self.lines.iter().enumerate() {
            if line.no_break_before && i < 64 {
                mask |= 1u64 << i;
            }
        }
        mask
    }
}

/// Whether a page may end at line index `at` (i.e. line `at` may open a page).
///
/// `break_mask` bit `i` set means line `i` must stay with the line above it — the
/// semantic half of pagination, produced by the renderer. Bit 0 is meaningless (the
/// first line always opens page one) and lines past bit 63 are treated as breakable,
/// which is safe because `REVIEW_LINES_MAX` caps the view well under 64.
fn break_allowed(break_mask: u64, at: usize) -> bool {
    at == 0 || at >= 64 || (break_mask >> at) & 1 == 0
}

/// Where the page starting at `start` ends (exclusive), honouring the glue mask.
///
/// The natural end is `start + page_lines`; if the line there must stay with its
/// label, the break walks back to the last allowed boundary. A group longer than a
/// page cannot be kept together — the break then falls at `start + 1` so a page is
/// never empty and the operator can always page forward.
fn next_page_end(start: usize, count: usize, page_lines: usize, break_mask: u64) -> usize {
    if page_lines == 0 {
        return count;
    }
    let mut end = core::cmp::min(start + page_lines, count);
    if end >= count {
        return count;
    }
    while end > start + 1 && !break_allowed(break_mask, end) {
        end -= 1;
    }
    end
}

/// Number of pages the operator will page through.
pub fn page_count(count: usize, break_mask: u64, page_lines: usize) -> usize {
    if count == 0 || page_lines == 0 {
        return 1;
    }
    let mut pages = 0usize;
    let mut start = 0usize;
    while start < count {
        start = next_page_end(start, count, page_lines, break_mask);
        pages += 1;
    }
    if pages == 0 {
        1
    } else {
        pages
    }
}

/// `(first, len)` of `page`, honouring the glue mask. Out-of-range pages are empty.
pub fn page_span(count: usize, break_mask: u64, page_lines: usize, page: usize) -> (usize, usize) {
    if count == 0 || page_lines == 0 {
        return (0, 0);
    }
    let mut start = 0usize;
    let mut p = 0usize;
    while start < count && p < page {
        start = next_page_end(start, count, page_lines, break_mask);
        p += 1;
    }
    if start >= count {
        return (start, 0);
    }
    let end = next_page_end(start, count, page_lines, break_mask);
    (start, end - start)
}

/// One amount line: `"<label> <amount> wei"`, in the units the wire carries.
///
/// Fails closed when the line cannot fit the 48-column frame: a truncated number is a
/// *wrong* number on a screen whose only job is to let someone authorize an exact
/// value, so the review refuses instead of printing a partial figure. (u128 wei
/// values that are absurd for a transfer are the only way to reach that branch.)
#[cfg(feature = "chain-eth")]
fn push_wei(view: &mut ReviewView, label: &str, amount: u128) -> Result<()> {
    view.push_fmt(format_args!("{} {} wei", label, amount))
}

/// Longest prefix of a signed message the review screen shows. Six full lines is
/// enough for the login/attestation messages EIP-191 is used for, and it bounds the
/// stack buffer in [`push_sanitized_message`].
#[cfg(feature = "chain-eth")]
const PERSONAL_MESSAGE_SHOWN_MAX: usize = REVIEW_LINE_MAX * 6;

/// Render arbitrary message bytes as displayable text.
///
/// Printable ASCII is kept as-is and every other byte becomes `.`: a raw newline,
/// escape sequence or Unicode bidi control drawn literally would let a message display
/// as something other than what is signed, and that difference is exactly what this
/// screen exists to expose. The caller always prints the true byte length, and a
/// truncated tail is marked at the end rather than silently cut.
#[cfg(feature = "chain-eth")]
fn push_sanitized_message(view: &mut ReviewView, msg: &[u8]) -> Result<()> {
    let shown = msg.len().min(PERSONAL_MESSAGE_SHOWN_MAX);
    let mut text = heapless::String::<{ PERSONAL_MESSAGE_SHOWN_MAX + 16 }>::new();
    for &b in &msg[..shown] {
        let ch = if (0x20..0x7f).contains(&b) {
            b as char
        } else {
            '.'
        };
        text.push(ch)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    if shown < msg.len() {
        text.push_str(" ..truncated")
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    view.push_wrapped(&text)
}

/// The PSBT map pool the review parse writes into (an alias so `build` keeps ONE
/// signature on every chain combination).
///
/// `chain-btc` off: there is no record type to carve and every PSBT arm is gone, so
/// the pool degrades to an unused byte span — the ABI shape survives without
/// pretending a BTC type exists.
#[cfg(feature = "chain-btc")]
pub type PsbtRecs<'a> = &'a mut [KvRec];
#[cfg(not(feature = "chain-btc"))]
pub type PsbtRecs<'a> = &'a mut [u8];

/// Build the review view for a decoded sign request.
///
/// `master_fingerprint` (optional) is used to mark outputs that come back to
/// this wallet (change). Without it every output renders as a payment.
///
/// `arena` / `recs` are the PSBT map pools; `typed_data` is the EIP-712 workspace (the
/// pool region followed by the formatter scratch). Every face parses the request into
/// caller memory, so the page adds no allocation of its own — the C-ABI carves all four
/// spans out of one review workspace (`review_ws_len`).
///
/// Chain axis: the arms for chains this build does not carry do not exist, so the
/// request answers the pre-existing `ChainKindUnsupported` instead of being rendered.
pub fn build(
    type_tag: UrTypeTag,
    payload: &[u8],
    network: Network,
    master_fingerprint: Option<&[u8; 4]>,
    arena: &mut [u8],
    recs: PsbtRecs<'_>,
    typed_data: &mut [u8],
) -> Result<ReviewView> {
    match type_tag {
        #[cfg(feature = "chain-btc")]
        UrTypeTag::CryptoPsbt | UrTypeTag::Psbt => {
            build_btc(payload, network, master_fingerprint, arena, recs)
        }
        // EIP-712 re-parses the request into the same zero-heap container the sign path
        // uses, so what the page can show and what the signer can sign are decided by one
        // container.
        #[cfg(feature = "chain-eth")]
        UrTypeTag::EthSignRequest => build_eth(payload, typed_data),
        _ => {
            // A chain-less build still has to name what it was handed.
            let _ = (
                arena.len(),
                recs.len(),
                typed_data.len(),
                &payload,
                network,
                master_fingerprint,
            );
            Err(ShlosiloError::new(ShlosiloErrorKind::ChainKindUnsupported))
        }
    }
}

/// PSBT review. `payload` is either the CBOR byte-string shell or the bare PSBT
/// (the UR exits strip the shell; both shapes are legal — same rule as the sign
/// path).
#[cfg(feature = "chain-btc")]
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

#[cfg(feature = "chain-btc")]
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
    // BTC-1 follow-up (external audit 2026-11-19): track whether any input's amount is merely
    // declared. The fee line must not claim exactness it does not have.
    let mut any_amount_declared = false;
    let mut rbf = false;
    for i in 0..in_count {
        let map = psbt
            .input_map_checked(i)
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        // `get_utxo_any`, not `get_witness_utxo`: a legacy (P2PKH) input carries
        // NON_WITNESS_UTXO (0x00) instead of a witness UTXO, and the operator must
        // still see the fee total for exactly those requests.
        let prev_out = psbt.unsigned_tx.inputs[i].prev_out.clone();
        match psbt::get_utxo_any_bound(map, &prev_out) {
            Some((amount, _spk, binding)) => {
                if binding == psbt::AmountBinding::Declared {
                    any_amount_declared = true;
                }
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
        head.push(Line {
            text,
            no_break_before: false,
        })
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))
    };
    // No title line: the page header already says "review"; every body line
    // must carry information (first real-device layout review, 2026-11-05).
    push_head(format_args!("in {} / out {}", in_count, out_count))?;
    match total_in {
        Some(ti) if ti >= total_out => {
            let fee = ti - total_out;
            // A declared input amount can only understate the true total, so the fee computed from
            // it is a lower bound. Say so in the value itself (`>=`) rather than adding a warning:
            // every segwit request has declared amounts, and a permanent banner would dilute the
            // markers that do point at real risk.
            if any_amount_declared {
                view.flags |= flag::FEE_UNVERIFIED;
                push_head(format_args!("fee >= {} sats", fee))?;
            } else {
                push_head(format_args!("fee {} sats", fee))?;
            }
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
            .push(Line {
                text,
                no_break_before: false,
            })
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
#[cfg(feature = "chain-btc")]
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
#[cfg(feature = "chain-btc")]
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
#[cfg(feature = "chain-btc")]
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
#[cfg(feature = "chain-btc")]
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
#[cfg(feature = "chain-btc")]
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
#[cfg(feature = "chain-btc")]
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
#[cfg(feature = "chain-btc")]
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
#[cfg(feature = "chain-btc")]
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
#[cfg(feature = "chain-eth")]
fn push_decoded_calldata(
    view: &mut ReviewView,
    decoded: &crate::chain::eth::calldata::DecodedCalldata,
) -> Result<()> {
    use crate::chain::eth::calldata::DecodedCalldata as D;

    /// 20-byte address → the same EIP-55 checksummed form the destination line uses.
    fn push_addr(view: &mut ReviewView, label: &str, addr: &[u8; 20]) -> Result<()> {
        let rendered = crate::address::eth::encode_bytes(addr)?;
        view.push_str(label)?;
        view.glue_next_line(); // the address is the label's value, not a new item
        view.push_wrapped(<_ as AsRef<str>>::as_ref(&rendered))
    }

    /// The raw 4-byte selector as `selector 0x????????`.
    ///
    /// Printed whenever the name alone does not settle what the call is — unknown
    /// selector, known name with an unexpected shape, or a name whose arguments were
    /// not split. It is the one fact that lets an operator diff our screen against the
    /// dApp's confirmation page without trusting either side.
    fn push_selector(view: &mut ReviewView, selector: &[u8; 4]) -> Result<()> {
        let mut text = heapless::String::<REVIEW_LINE_MAX>::new();
        use core::fmt::Write as _;
        text.push_str("selector 0x")
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        for b in selector {
            write!(&mut text, "{b:02x}")
                .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
        }
        view.push_str(text.as_str())
    }

    /// 256-bit big-endian → **decimal** raw units, or "unlimited" for 2^256-1.
    ///
    /// Decimal, not hex: this is the number the token contract will move, and the
    /// operator compares it against "1.0 USDC" by eye. Hex (`0x0f4240`) is exact but
    /// forces mental arithmetic on the one screen that must be readable at a glance —
    /// measured on the real acceptance run (2026-11-24), where a 1.0 USDC transfer
    /// rendered as `0x0f4240`. Token decimals are still not guessed (a wrong decimal
    /// point is a wrong amount), so the figure stays in raw units; a `max cost`-style
    /// fail-closed applies when 78 digits cannot fit the line.
    fn push_amount(view: &mut ReviewView, label: &str, amount: &[u8; 32]) -> Result<()> {
        view.push_str(label)?;
        view.glue_next_line(); // the figure belongs to the label above it
        if amount.iter().all(|&b| b == 0xff) {
            return view.push_str("unlimited");
        }
        let mut digits = [0u8; 78];
        let n = u256_decimal(amount, &mut digits);
        // ASCII digits by construction; the conversion is here only because `push_str`
        // takes a `&str`.
        let text = core::str::from_utf8(&digits[..n])
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        view.push_str(text)
    }

    /// Big-endian 256-bit → ASCII decimal digits; returns the digit count.
    ///
    /// Repeated division by ten over a scratch copy: 78 digits is the u256 worst case,
    /// which is why the buffer is sized 78 and nothing here allocates.
    fn u256_decimal(amount: &[u8; 32], out: &mut [u8; 78]) -> usize {
        let mut v = *amount;
        if v.iter().all(|&b| b == 0) {
            out[0] = b'0';
            return 1;
        }
        let mut reversed = [0u8; 78];
        let mut n = 0usize;
        while v.iter().any(|&b| b != 0) {
            let mut rem: u32 = 0;
            for byte in v.iter_mut() {
                let cur = (rem << 8) | u32::from(*byte);
                *byte = (cur / 10) as u8;
                rem = cur % 10;
            }
            reversed[n] = b'0' + rem as u8;
            n += 1;
        }
        for i in 0..n {
            out[i] = reversed[n - 1 - i];
        }
        n
    }

    match decoded {
        D::Empty => view.push_str("call: no calldata"),
        D::Transfer { to, amount } => {
            view.push_str("erc20 transfer")?;
            push_addr(view, "recipient", to)?;
            push_amount(view, "amount", amount)
        }
        // `approve(address,uint256)` is the SAME selector for ERC-20 (allowance, in
        // token units) and ERC-721 (a token id), so the label must not claim a family
        // and the value must not be called an allowance: an operator who reads
        // "erc20 approve / allowance 1" on an NFT approval is being told the wrong
        // thing about what they are signing. Measured on Sepolia 2026-11-25.
        D::Approve { spender, amount } => {
            view.push_str("approve")?;
            push_addr(view, "spender", spender)?;
            push_amount(view, "amount or token id", amount)
        }
        D::IncreaseAllowance { spender, added } => {
            view.push_str("erc20 increase allowance")?;
            push_addr(view, "spender", spender)?;
            push_amount(view, "added", added)
        }
        // `transferFrom(address,address,uint256)` is shared the same way (ERC-20
        // amount, ERC-721 token id).
        D::TransferFrom { from, to, amount } => {
            view.push_str("transfer from")?;
            push_addr(view, "from", from)?;
            push_addr(view, "recipient", to)?;
            push_amount(view, "amount or token id", amount)
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
        D::KnownSelector { name, selector } => {
            view.push_str(name)?;
            view.push_str("args not decoded")?;
            push_selector(view, selector)
        }
        // A3c-F12 (2026-11-20): the calldata has a known selector but NOT that call's canonical
        // length. The extra bytes are signed too, so this must not read like a clean transfer.
        D::ShapeMismatch { selector, name } => {
            view.push_str(name)?;
            view.push_str("shape does not match")?;
            push_selector(view, selector)
        }
        // Unknown selector: the operator's only cross-check is comparing the four bytes
        // with what the dApp showed them, so print them instead of a bare verdict.
        D::Unknown { selector } => {
            view.push_str("call: unknown contract")?;
            push_selector(view, selector)
        }
    }
}

/// One chain line: `chain <id> <name>`, or just the id when this firmware does not
/// know the chain.
///
/// `chain 1` alone does not tell the operator which network they are spending on,
/// and a wrong-network send is not recoverable; an unknown id is printed raw because
/// we do not guess names. Shared by the typed and the legacy send pages so the two
/// cannot name the same chain differently.
#[cfg(feature = "chain-eth")]
fn push_chain(view: &mut ReviewView, chain_id: u64) -> Result<()> {
    match crate::chain::eth::chain_names::chain_name(chain_id) {
        Some(name) => view.push_fmt(format_args!("chain {} {}", chain_id, name)),
        None => view.push_fmt(format_args!("chain {}", chain_id)),
    }
}

/// Destination line: `to:` + EIP-55 address (glued, so the label never opens a page
/// alone), or `to: contract creation` when there is no callee.
///
/// Shared by both send pages: the destination is the single thing the operator must
/// verify, so it is rendered identically no matter which transaction type carried it.
#[cfg(feature = "chain-eth")]
fn push_destination(view: &mut ReviewView, destination: Option<[u8; 20]>) -> Result<()> {
    match destination {
        Some(dest) => {
            let rendered = eth::encode_bytes(&dest)?;
            view.push_str("to:")?;
            view.glue_next_line();
            view.push_wrapped(<_ as AsRef<str>>::as_ref(&rendered))
        }
        None => view.push_str("to: contract creation"),
    }
}

/// Calldata lines: byte count, then either the deploy verdict or the decoded call.
///
/// Shared by both send pages — the same bytes must not be described one way for an
/// EIP-1559 send and another way for a legacy one (an ERC-20 transfer looks the same
/// to a wallet either way). `destination` is needed because with none of it the
/// calldata IS the deploy bytecode: there is no callee to name and no ABI to decode,
/// and calling that "unknown contract" reads like a failed lookup against a contract
/// that exists (measured on Sepolia 2026-11-25).
#[cfg(feature = "chain-eth")]
fn push_calldata(
    view: &mut ReviewView,
    calldata: &[u8],
    destination: Option<[u8; 20]>,
) -> Result<()> {
    if calldata.is_empty() {
        return view.push_str("data: none");
    }
    view.push_fmt(format_args!("data {} bytes", calldata.len()))?;
    if destination.is_none() {
        return view.push_str("call: contract deploy");
    }
    match crate::chain::eth::calldata::decode_calldata(calldata) {
        Ok(decoded) => {
            if matches!(
                decoded,
                crate::chain::eth::calldata::DecodedCalldata::Unknown { .. }
                    | crate::chain::eth::calldata::DecodedCalldata::ShapeMismatch { .. }
            ) {
                view.flags |= flag::UNKNOWN_CALLDATA;
            }
            push_decoded_calldata(view, &decoded)?;
        }
        Err(_) => {
            view.flags |= flag::UNKNOWN_CALLDATA;
            view.push_str("call: unknown contract")?;
        }
    }
    Ok(())
}

// ─── EIP-712 typed data (E-3 P3) ─────────────────────────────────────────────
//
// The page is built from the same zero-heap container the signer uses, and it applies
// the same refusal gate (`typed_data_fold_gate`), so "the operator saw the whole
// document" and "the device signed it" are one decision, not two.
//
// What decide the layout: the operator has to be able to check the four things an
// EIP-712 signature actually authorizes — which primary type, which domain (chain,
// contract, name), which top-level fields and their values — plus the SIZE of anything
// the page does not itemize. Nothing on this page is chosen by the payload: labels are
// a fixed vocabulary (`sign`, `domain`, `chain`, `verifying contract`, `<field name>`,
// `items`, `and N more`), and values are re-encoded (EIP-55 addresses, decimal
// integers) or sanitized ASCII, never echoed raw.

/// Array elements the page itemizes before it folds the rest into `and N more`.
#[cfg(feature = "chain-eth")]
const TD_SHOWN_MAX: usize = 3;
/// Struct nesting the page expands below the message root. A struct met at this depth is
/// printed as `struct <Type>` plus its field count instead of being expanded.
#[cfg(feature = "chain-eth")]
const TD_EXPAND_MAX: usize = 2;
/// Bytes of one value the page renders (three lines) before it marks the tail.
#[cfg(feature = "chain-eth")]
const TD_VALUE_MAX: usize = REVIEW_LINE_MAX * 3;

/// The typed-data refusal gate: one rule, two faces.
///
/// **A struct-element array longer than [`TD_SHOWN_MAX`] is refused** — the whole request
/// with `FeatureNotImplemented`. **An atom array of the same length is folded and stays
/// signable**, with `and N more (3 of 8)` printed. **A struct deeper than
/// [`TD_EXPAND_MAX`] is truncated, not refused**, and the page still names its type and
/// field count.
///
/// The line between the refusal and the two truncations is *how many things the screen
/// cannot show*, not how much data it omits:
///
/// - A folded struct array hides N **distinct authorizations**. Every element is a value
///   the operator would have to accept one by one (a permit, a transfer, an order), and
///   an attacker only has to make element 4 hostile. A count is not a summary of a list
///   like that, so this device declines to sign it.
/// - A truncated struct hides exactly **one** value, and the page prints its type name and
///   its field count — the same facts a one-element fold would give. The operator is asked
///   to trust the contents of a single named, counted position, which is the trust every
///   wallet already asks for at the point where its own screen runs out of room.
/// - A folded atom array hides repeated instances of **one scalar** whose type and length
///   are printed; there is no per-element meaning to judge (`uint256[] ids` of a claim).
///
/// Changing that balance one way or the other breaks a pin
/// (`tests/eip712_review_page.rs`), and it is the sign face's rule too: `sign_eth` calls
/// this same function, so a direct sign call cannot sign a document the page would have
/// refused.
#[cfg(feature = "chain-eth")]
pub(crate) fn typed_data_fold_gate(pool: &Eip712Pool<'_>) -> Result<()> {
    let mut view: Option<&mut ReviewView> = None;
    let mut display = [0u8; 0];
    walk_typed_data(pool, &mut view, &mut display)
}

/// Refuse a typed-data request whose own `chain_id` (key 4) disagrees with the chain its
/// document names.
///
/// This is a **payload-internal** consistency check, deliberately not part of
/// `sign::check_network`: that gate compares the payload against the network the *caller*
/// declared, and a carrier with no network selection (the product device passes a
/// placeholder, and the session-view entry has no such parameter) never reaches it. Key 4
/// is metadata the wallet fills in; the digest is built from `domain.chainId`. Letting the
/// two disagree means a request can claim one chain in the envelope and sign another, and
/// the operator's only evidence for the mismatch would be reading both screens.
///
/// Only a *readable* domain chain is compared: a domain that omits `chainId` has nothing to
/// compare (EIP-712 allows it), and the digest layer already refuses a declared-but-absent
/// value.
#[cfg(feature = "chain-eth")]
pub(crate) fn typed_data_request_chain_gate(req_chain_id: Option<i128>, json: &[u8]) -> Result<()> {
    let Some(envelope_chain) = req_chain_id else {
        return Ok(());
    };
    let Some(domain_chain) = crate::chain::eth::eip712_pool::domain_chain_id(json)? else {
        return Ok(());
    };
    if envelope_chain != i128::from(domain_chain) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::NetworkUnrecognized));
    }
    Ok(())
}

/// Push through the optional view: `None` is the gate's face, where the walk runs for its
/// refusal rules and writes nothing.
#[cfg(feature = "chain-eth")]
fn td_fmt(view: &mut Option<&mut ReviewView>, args: core::fmt::Arguments<'_>) -> Result<()> {
    match view.as_deref_mut() {
        Some(view) => view.push_fmt(args),
        None => Ok(()),
    }
}

#[cfg(feature = "chain-eth")]
fn td_str(view: &mut Option<&mut ReviewView>, s: &str) -> Result<()> {
    match view.as_deref_mut() {
        Some(view) => view.push_str(s),
        None => Ok(()),
    }
}

#[cfg(feature = "chain-eth")]
fn td_wrapped(view: &mut Option<&mut ReviewView>, s: &str) -> Result<()> {
    match view.as_deref_mut() {
        Some(view) => view.push_wrapped(s),
        None => Ok(()),
    }
}

#[cfg(feature = "chain-eth")]
fn td_chain(view: &mut Option<&mut ReviewView>, chain_id: u64) -> Result<()> {
    match view.as_deref_mut() {
        Some(view) => push_chain(view, chain_id),
        None => Ok(()),
    }
}

/// `<label> <value>` on one line when it fits, else the label alone with the value glued
/// under it. A label never opens a page without its value.
#[cfg(feature = "chain-eth")]
fn td_labeled(view: &mut Option<&mut ReviewView>, label: &str, value: &str) -> Result<()> {
    if label.len() + 1 + value.len() <= REVIEW_LINE_MAX {
        return td_fmt(view, format_args!("{} {}", label, value));
    }
    td_str(view, label)?;
    if let Some(view) = view.as_deref_mut() {
        view.glue_next_line();
    }
    td_wrapped(view, value)
}

/// Render an atom's value into the display scratch and answer the byte count.
///
/// Canonical where the declared type has a canonical form — an `address` is re-written as
/// EIP-55 (so a document sending lowercase or a checksum-broken mix prints as the one form
/// every wallet shows), everything else keeps the decimal/hex text the wire carried — and
/// sanitized everywhere: printable ASCII is kept, every other byte becomes `.`, exactly
/// like the personal-message page. A raw newline or a bidi control drawn literally would
/// let the value describe something other than what is signed.
///
/// The scratch bounds the rendering ([`TD_VALUE_MAX`], three lines); a longer value is
/// marked at the cut (`..`) instead of being silently shortened. A scratch too small for
/// the render is `BufferTooSmall` with the length needed — capacity, never truncation.
#[cfg(feature = "chain-eth")]
fn td_atom_text(pool: &Eip712Pool<'_>, node: &Eip712Node, display: &mut [u8]) -> Result<usize> {
    use crate::chain::eth::eip712_pool::KIND_ADDRESS;
    let payload = pool.payload(node)?;
    if node.kind == KIND_ADDRESS {
        // `0x` is required on a value and optional on a domain path (`HexForm`), so the
        // prefix is stripped when present rather than demanded.
        let hex = payload.strip_prefix(b"0x".as_slice()).unwrap_or(payload);
        let mut raw = [0u8; 20];
        if hex.len() != 40 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        for (i, slot) in raw.iter_mut().enumerate() {
            let pair = hex.get(i * 2..i * 2 + 2).unwrap_or(&[]);
            let hi = hex_nibble(pair.first().copied()).unwrap_or(0xff);
            let lo = hex_nibble(pair.get(1).copied()).unwrap_or(0xff);
            if hi == 0xff || lo == 0xff {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            *slot = (hi << 4) | lo;
        }
        let rendered = eth::encode_bytes(&raw)?;
        let text = <_ as AsRef<str>>::as_ref(&rendered).as_bytes();
        let dst = display.get_mut(..text.len()).ok_or_else(|| {
            ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(text.len()),
            )
        })?;
        dst.copy_from_slice(text);
        return Ok(text.len());
    }
    if matches!(node.kind, KIND_STRUCT | KIND_ARRAY) {
        // Not a value this renderer itemizes; the walk routes those.
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let cap = display.len().min(TD_VALUE_MAX);
    if cap < payload.len() {
        // Room for the cut marker (` ..`) plus at least one byte of value.
        if cap < 4 {
            return Err(ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(payload.len().min(TD_VALUE_MAX)),
            ));
        }
        let shown = cap - 3;
        for (i, &byte) in payload.iter().take(shown).enumerate() {
            display[i] = sanitize_byte(byte);
        }
        for (i, &byte) in b" ..".iter().enumerate() {
            display[shown + i] = byte;
        }
        return Ok(cap);
    }
    for (i, &byte) in payload.iter().enumerate() {
        display[i] = sanitize_byte(byte);
    }
    Ok(payload.len())
}

/// Push one atom value line, or nothing at all when the walk is running for the gate.
///
/// The gate's face renders no values, so it must not touch the scratch either: an empty
/// scratch is not a capacity failure there, it is "nobody asked for this line".
#[cfg(feature = "chain-eth")]
fn td_atom_labeled(
    pool: &Eip712Pool<'_>,
    view: &mut Option<&mut ReviewView>,
    display: &mut [u8],
    label: &str,
    node: &Eip712Node,
) -> Result<()> {
    if view.is_none() {
        return Ok(());
    }
    let n = td_atom_text(pool, node, display)?;
    let text = core::str::from_utf8(&display[..n]).map_err(|_| invalid_doc())?;
    td_labeled(view, label, text)
}

/// Displayable form of one payload byte (same rule as the personal-message page).
#[cfg(feature = "chain-eth")]
fn sanitize_byte(byte: u8) -> u8 {
    if (0x20..0x7f).contains(&byte) {
        byte
    } else {
        b'.'
    }
}

#[cfg(feature = "chain-eth")]
fn hex_nibble(byte: Option<u8>) -> Option<u8> {
    match byte? {
        b @ b'0'..=b'9' => Some(b - b'0'),
        b @ b'a'..=b'f' => Some(b - b'a' + 10),
        b @ b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The message tree: `primaryType`, one `sign` line, then every top-level field.
#[cfg(feature = "chain-eth")]
fn walk_typed_data(
    pool: &Eip712Pool<'_>,
    view: &mut Option<&mut ReviewView>,
    display: &mut [u8],
) -> Result<()> {
    let primary = pool.primary_type()?;
    td_str(view, "eth typed data")?;
    td_labeled(view, "sign", primary)?;
    walk_domain(pool, view, display)?;
    let root = pool.message()?;
    let root_idx = pool
        .message_root()
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?
        as usize;
    if root.kind != KIND_STRUCT {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    walk_struct_fields(pool, primary, root_idx, "", 1, view, display)
}

/// The domain block: name, version, chain, verifying contract, salt — whichever the
/// document filled, always in the canonical slot order so the same domain always reads
/// the same way.
#[cfg(feature = "chain-eth")]
fn walk_domain(
    pool: &Eip712Pool<'_>,
    view: &mut Option<&mut ReviewView>,
    display: &mut [u8],
) -> Result<()> {
    use crate::chain::eth::eip712_pool::{domain_slot_field, DOMAIN_SLOTS};
    if view.is_none() {
        // The gate reads the message tree only: the domain has no rule of its own (the
        // digest layer already refuses a domain whose declared fields have no values).
        return Ok(());
    }
    let root_idx = match pool.domain_root() {
        Some(idx) => idx as usize,
        None => return Ok(()),
    };
    let root = *pool.node(root_idx).ok_or_else(invalid_doc)?;
    if root.kind != KIND_STRUCT {
        return Err(invalid_doc());
    }
    td_str(view, "domain")?;
    let mask = pool.domain_mask();
    let children = pool.children_of(root_idx)?;
    // The children hold only the filled slots, in canonical order, so the nth set bit
    // owns the nth child.
    let mut child = 0usize;
    let mut contract_shown = false;
    for slot in 0..DOMAIN_SLOTS {
        let present = u32::try_from(slot)
            .ok()
            .and_then(|shift| 1u8.checked_shl(shift))
            .is_some_and(|bit| mask & bit != 0);
        if !present {
            continue;
        }
        let node = *children.get(child).ok_or_else(invalid_doc)?;
        child += 1;
        let Some((name, _declared)) = domain_slot_field(slot) else {
            continue;
        };
        let n = td_atom_text(pool, &node, display)?;
        let text = core::str::from_utf8(&display[..n]).map_err(|_| invalid_doc())?;
        match name {
            "chainId" => match parse_decimal(text) {
                // The shared chain renderer, so an id reads the same on every page.
                Some(id) => td_chain(view, id)?,
                // A chain id outside u64 cannot be named; it is still shown, raw.
                None => td_labeled(view, "chain", text)?,
            },
            "verifyingContract" => {
                contract_shown = true;
                td_labeled(view, "verifying contract", text)?;
            }
            other => td_labeled(view, other, text)?,
        }
    }
    if !contract_shown {
        // A domain without a `verifyingContract` binds the signature to no contract at
        // all. Saying so is not decoration: a line that is simply absent reads like a
        // page that ran out of room, and this is the one domain field that decides which
        // contract will accept the signature.
        td_str(view, "verifying contract none")?;
    }
    Ok(())
}

/// The page labels a value with the pool's own domain slot names, so the two lists cannot
/// drift; this constant is what makes a sixth domain slot fail the build here.
#[cfg(feature = "chain-eth")]
const _: () = assert!(crate::chain::eth::eip712_pool::DOMAIN_SLOTS == 5);

/// Longest label the page builds: `parent.field` (two capped names) or `label[N]`.
///
/// Spelled `heapless::String<TD_LABEL_MAX>` at each use rather than behind a type alias:
/// cbindgen walks item-level aliases into its opaque-type graph and refuses a const-generic
/// `heapless::String` there (it panics, which would turn the C-header gate red).
#[cfg(feature = "chain-eth")]
const TD_LABEL_MAX: usize = 2 * crate::chain::eth::eip712_pool::NAME_BYTES + 2 + 8;

#[cfg(feature = "chain-eth")]
fn overflow() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow)
}

#[cfg(feature = "chain-eth")]
fn invalid_doc() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// The message's fields, in declaration order.
///
/// `prefix` is empty for the message root and `parent` (or `parent[2]`) for a nested
/// struct, so a value buried one level down still shows which field it belongs to.
#[allow(clippy::too_many_arguments)] // pool + node + label parts + two sinks
#[cfg(feature = "chain-eth")]
fn walk_struct_fields(
    pool: &Eip712Pool<'_>,
    ty_name: &str,
    node_idx: usize,
    prefix: &str,
    depth: usize,
    view: &mut Option<&mut ReviewView>,
    display: &mut [u8],
) -> Result<()> {
    let type_idx = pool.type_index(ty_name).ok_or_else(invalid_doc)?;
    let declared = *pool.type_at(type_idx as usize).ok_or_else(invalid_doc)?;
    let fields = pool.fields_of(&declared)?;
    let children = pool.children_of(node_idx)?;
    if fields.len() != children.len() {
        // `encode_data` refuses the same mismatch: a value list that does not match the
        // declaration is not a document this device can hash, so the page cannot render
        // it either.
        return Err(invalid_doc());
    }
    for (i, field) in fields.iter().enumerate() {
        let child_idx = (pool.node(node_idx).ok_or_else(invalid_doc)?.first_child as usize)
            .checked_add(i)
            .ok_or_else(invalid_doc)?;
        walk_field(
            pool,
            pool.field_name(field)?,
            pool.field_type(field)?,
            child_idx,
            prefix,
            depth,
            view,
            display,
        )?;
    }
    Ok(())
}

/// One declared field: an atom, an array or a struct.
#[allow(clippy::too_many_arguments)] // the walk's parameter shape, one call site per arm
#[cfg(feature = "chain-eth")]
fn walk_field(
    pool: &Eip712Pool<'_>,
    name: &str,
    declared: &str,
    node_idx: usize,
    prefix: &str,
    depth: usize,
    view: &mut Option<&mut ReviewView>,
    display: &mut [u8],
) -> Result<()> {
    let node = *pool.node(node_idx).ok_or_else(invalid_doc)?;
    let label = join_label(prefix, name)?;
    if let Some(open) = declared.find('[') {
        // Same array test the hash layer uses (`encode_value_pool`).
        let elem = declared.get(..open).ok_or_else(invalid_doc)?;
        return walk_array(pool, &label, elem, &node, depth, view, display);
    }
    match node.kind {
        KIND_STRUCT => walk_struct_value(pool, &label, declared, node_idx, depth, view, display),
        // An array value under a type that declares no array suffix: the hash layer
        // refuses it, so it never reaches a screen.
        KIND_ARRAY => Err(invalid_doc()),
        _ => td_atom_labeled(pool, view, display, &label, &node),
    }
}

/// One array value: its length always, its elements itemized up to [`TD_SHOWN_MAX`].
///
/// A struct-element array longer than that is refused by
/// [`typed_data_fold_gate`] before this runs, so the only fold that can happen here is
/// the atom one.
#[cfg(feature = "chain-eth")]
fn walk_array(
    pool: &Eip712Pool<'_>,
    label: &str,
    elem: &str,
    node: &Eip712Node,
    depth: usize,
    view: &mut Option<&mut ReviewView>,
    display: &mut [u8],
) -> Result<()> {
    if node.kind != KIND_ARRAY {
        return Err(invalid_doc());
    }
    let len = node.n_children as usize;
    let first = node.first_child as usize;
    // A declared type in the table means a struct element: a list of values the operator
    // would have to accept one by one.
    let elem_is_struct = pool.type_index(elem).is_some();
    if elem_is_struct && len > TD_SHOWN_MAX {
        return Err(ShlosiloError::new(ShlosiloErrorKind::FeatureNotImplemented));
    }
    td_fmt(view, format_args!("{} {} items", label, len))?;
    let shown = len.min(TD_SHOWN_MAX);
    for i in 0..shown {
        let child_idx = first.checked_add(i).ok_or_else(invalid_doc)?;
        let child = *pool.node(child_idx).ok_or_else(invalid_doc)?;
        let mut item = heapless::String::<TD_LABEL_MAX>::new();
        use core::fmt::Write;
        write!(item, "{}[{}]", label, i).map_err(|_| overflow())?;
        if elem_is_struct {
            walk_struct_value(pool, &item, elem, child_idx, depth, view, display)?;
            continue;
        }
        if matches!(child.kind, KIND_ARRAY | KIND_STRUCT) {
            // Nested arrays and unexpected structs under an atom element type are shapes
            // the digest layer refuses (the pool reads `uint256[2][3]` as one dimension;
            // that request is not signable).
            return Err(invalid_doc());
        }
        td_atom_labeled(pool, view, display, &item, &child)?;
    }
    if len > TD_SHOWN_MAX {
        td_fmt(
            view,
            format_args!("and {} more ({} of {})", len - shown, shown, len),
        )?;
    }
    Ok(())
}

/// One struct value: its type name, then either its fields or — past [`TD_EXPAND_MAX`] —
/// its field count.
#[cfg(feature = "chain-eth")]
fn walk_struct_value(
    pool: &Eip712Pool<'_>,
    label: &str,
    ty_name: &str,
    node_idx: usize,
    depth: usize,
    view: &mut Option<&mut ReviewView>,
    display: &mut [u8],
) -> Result<()> {
    let node = *pool.node(node_idx).ok_or_else(invalid_doc)?;
    if node.kind != KIND_STRUCT {
        return Err(invalid_doc());
    }
    td_fmt(view, format_args!("{} struct {}", label, ty_name))?;
    if depth >= TD_EXPAND_MAX {
        // Depth truncation, NOT a refusal: the type is named and the number of values
        // hidden behind it is printed (see `typed_data_fold_gate` for why this is
        // allowed where a folded struct array is not).
        let type_idx = pool.type_index(ty_name).ok_or_else(invalid_doc)?;
        let declared = *pool.type_at(type_idx as usize).ok_or_else(invalid_doc)?;
        let n_fields = pool.fields_of(&declared)?.len();
        return td_fmt(
            view,
            format_args!("{} {} fields not shown", label, n_fields),
        );
    }
    walk_struct_fields(pool, ty_name, node_idx, label, depth + 1, view, display)
}

/// `prefix` + `.` + `name`, or just `name` at the message root.
#[cfg(feature = "chain-eth")]
fn join_label(prefix: &str, name: &str) -> Result<heapless::String<TD_LABEL_MAX>> {
    let mut out = heapless::String::<TD_LABEL_MAX>::new();
    if !prefix.is_empty() {
        out.push_str(prefix).map_err(|_| overflow())?;
        out.push('.').map_err(|_| overflow())?;
    }
    out.push_str(name).map_err(|_| overflow())?;
    Ok(out)
}

/// Decimal text → `u64`, or `None` when it is not a decimal integer in range.
#[cfg(feature = "chain-eth")]
fn parse_decimal(text: &str) -> Option<u64> {
    let mut value: u64 = 0;
    if text.is_empty() {
        return None;
    }
    for byte in text.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

/// Bytes the typed-data page needs: the container's region plus the formatter scratch
/// (`limits::EIP712_DISPLAY_BYTES`, which is exactly the span the review workspace
/// reserves for it).
#[cfg(feature = "chain-eth")]
pub(crate) const TYPED_DATA_WS_BYTES: usize =
    crate::chain::eth::eip712_pool::WS_BYTES + crate::limits::EIP712_DISPLAY_BYTES;

/// `(container region, formatter scratch)` out of one typed-data workspace.
///
/// The whole workspace is either big enough for both spans or the page refuses: a
/// half-sized region would fail deep inside the walk, and the caller must see "request too
/// large" with the size that would have worked (the B-7 rule the pool applies too).
#[cfg(feature = "chain-eth")]
fn split_typed_data_ws(ws: &mut [u8]) -> Result<(&mut [u8], &mut [u8])> {
    let region_bytes = crate::chain::eth::eip712_pool::WS_BYTES;
    if ws.len() < TYPED_DATA_WS_BYTES {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(TYPED_DATA_WS_BYTES),
        ));
    }
    let (region, display) = ws.split_at_mut(region_bytes);
    Ok((region, display))
}

/// `build_eth` over a fresh typed-data workspace — what the C-ABI carve hands over, so the
/// unit pins drive the same path the device does instead of a widened test-only one.
#[cfg(test)]
#[cfg(feature = "chain-eth")]
fn build_eth_ws(payload: &[u8]) -> Result<ReviewView> {
    let mut ws = alloc::vec![0u8; TYPED_DATA_WS_BYTES];
    build_eth(payload, &mut ws)
}

/// ETH request review.
///
/// Typed data (`data_type` 2) renders the EIP-712 page out of `ws`: the first
/// [`TYPED_DATA_WS_BYTES`] minus the display scratch is the container region, the rest is
/// the scratch the page formats values into. One slice because the caller carves one
/// tail, and because a face that hands over a region too small must be refused here —
/// `BufferTooSmall` with the size needed, not a page drawn from leftover bytes.
#[cfg(feature = "chain-eth")]
pub fn build_eth(payload: &[u8], ws: &mut [u8]) -> Result<ReviewView> {
    use crate::chain::eth::from_rlp;
    use crate::ur::codec::eth_sign_request::{parse_eth_sign_request, EthSignDataType};

    let req = parse_eth_sign_request(payload)?;
    let mut view = ReviewView::new();
    // `data_type` selects the scheme before the payload is read (same dispatch as
    // `sign_eth`). The review gate is fail-closed: a request this signer cannot
    // sign must never render as a send.
    match req.data_type {
        // data_type 1 = legacy, EIP-155 protected (bare RLP preimage, no type byte).
        //
        // E-1 (2026-11-25): this used to be refused as unimplemented. The page is the
        // same skeleton as the typed send with ONE fee — legacy has no base fee and no
        // priority tip, only `gas price`, so calling it "max fee" would describe a
        // scheme the operator is not signing.
        EthSignDataType::Transaction => {
            let tx = from_rlp::parse_eip155_signing_request(req.sign_data)?;
            // Fail closed before rendering: a request whose own chain_id disagrees with
            // the transaction is one this device refuses to sign (same rule, same code
            // as the sign path), so it must not reach the screen as a send.
            if let Some(req_chain) = req.chain_id {
                if req_chain != tx.chain_id as i128 {
                    return Err(ShlosiloError::new(ShlosiloErrorKind::NetworkUnrecognized));
                }
            }
            view.push_str("eth send request")?;
            push_chain(&mut view, tx.chain_id)?;
            push_destination(&mut view, tx.destination)?;
            push_wei(&mut view, "value", tx.amount)?;
            view.push_fmt(format_args!("gas limit {}", tx.gas_limit))?;
            // The single fee this scheme pays, in the units the wire carries.
            push_wei(&mut view, "gas price", tx.gas_price)?;
            // Worst case the operator is authorizing: gas_limit × gas price + value.
            let fee_ceiling = tx
                .gas_price
                .checked_mul(u128::from(tx.gas_limit))
                .and_then(|ceiling| ceiling.checked_add(tx.amount));
            match fee_ceiling {
                Some(total) => push_wei(&mut view, "max cost", total)?,
                // Same rule as the typed page: a number nobody can print is a
                // transaction nobody may confirm.
                None => return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
            }
            let calldata = crate::types::wire_bytes::wire_slice(&tx.data);
            push_calldata(&mut view, calldata, tx.destination)?;
            return Ok(view);
        }
        EthSignDataType::TypedTransaction => {
            // data_type 4: only EIP-1559 (first byte 0x02) is rendered or signed;
            // EIP-2930 / 4844 / 7702 and unknown/empty payloads stay refused.
            match req.sign_data.first() {
                Some(0x02) => {}
                Some(0x01) | Some(0x03) | Some(0x04) => {
                    return Err(ShlosiloError::new(ShlosiloErrorKind::FeatureNotImplemented));
                }
                _ => return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
            }
        }
        EthSignDataType::TypedData => {
            // E-3 P3: the real typed-data page. The request is re-parsed into the same
            // zero-heap container the signer uses, and the digest is recomputed before a
            // single line is rendered: a document this device cannot hash is a document
            // it will not sign, so it must not render as a confirmable request either
            // (fail closed — the review gate exists to stop exactly that).
            // Same envelope-vs-document consistency rule the signer applies (the two
            // faces must refuse the same requests): the page must not render a document
            // the signer would refuse for naming a different chain than the request.
            typed_data_request_chain_gate(req.chain_id, req.sign_data)?;
            let (region, display) = split_typed_data_ws(ws)?;
            let pool = eip712_pool::parse_in(req.sign_data, region)?;
            typed_data_fold_gate(&pool)?;
            let _digest = eip712_pool::signing_hash_pool(&pool)?;
            {
                let mut sink = Some(&mut view);
                walk_typed_data(&pool, &mut sink, display)?;
            }
            return Ok(view);
        }
        EthSignDataType::PersonalMessage => {
            // This scheme IS signed (EIP-191, the exit returns r||s||v with v=27/28),
            // so the operator has to see what they are putting their key behind: a
            // message the screen cannot show is a message nobody can judge. The bytes
            // are rendered as printable ASCII with everything else escaped, wrapped
            // across lines, and capped so a huge payload cannot crowd out the rest.
            view.push_str("eth message sign")?;
            view.push_fmt(format_args!("message {} bytes", req.sign_data.len()))?;
            push_sanitized_message(&mut view, req.sign_data)?;
            return Ok(view);
        }
    }

    // Review mirrors the sign path's policy: a pre-signed payload is not a request.
    let tx = from_rlp::parse_eip1559_signing_request(req.sign_data)?;
    view.push_str("eth send request")?;
    // Name the chain when we know it (shared with the legacy page).
    push_chain(&mut view, tx.chain_id)?;
    push_destination(&mut view, tx.destination)?;
    push_wei(&mut view, "value", tx.amount)?;
    view.push_fmt(format_args!("gas limit {}", tx.gas_limit))?;
    // EIP-1559 pays two fees, and the one that decides what a send actually costs is
    // the max fee. Both are printed in wei as the wire carries them: no unit
    // conversion, because a rounded gwei figure would be a guess where the operator
    // needs the exact number they are authorizing.
    push_wei(&mut view, "max fee", tx.max_fee_per_gas)?;
    push_wei(&mut view, "priority fee", tx.max_priority_fee_per_gas)?;
    // The worst case is what the operator is actually authorizing: the fee ceiling
    // multiplied by the gas limit, plus the value. Shown whenever it is representable;
    // an amount that would overflow u128 is refused below rather than guessed.
    let gas_limit_u128 = u128::from(tx.gas_limit);
    let fee_ceiling = tx
        .max_fee_per_gas
        .checked_mul(gas_limit_u128)
        .and_then(|ceiling| ceiling.checked_add(tx.amount));
    match fee_ceiling {
        Some(total) => push_wei(&mut view, "max cost", total)?,
        // A value the model cannot represent is not a transaction this device may
        // review: the operator would be confirming a number nobody can show them.
        None => return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
    }
    // The signer refuses a request whose own chain_id disagrees with the transaction
    // it carries; the review must refuse it too, or the operator would confirm a
    // network this device will not sign for.
    if let Some(req_chain) = req.chain_id {
        if req_chain != tx.chain_id as i128 {
            return Err(ShlosiloError::new(ShlosiloErrorKind::NetworkUnrecognized));
        }
    }
    let calldata = crate::types::wire_bytes::wire_slice(&tx.data);
    push_calldata(&mut view, calldata, tx.destination)?;
    Ok(view)
}

#[cfg(test)]
#[cfg(feature = "chain-btc")]
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
#[cfg(feature = "chain-eth")]
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
        // `approve(address,uint256)` is shared by ERC-20 and ERC-721, so the label names
        // no family and the value is not called an allowance. (Before 2026-11-25 this
        // asserted "erc20 approve" — the Sepolia run showed an ERC-721 approve wearing
        // that label, which tells the operator the wrong thing.)
        assert!(ap.contains("approve"), "{ap}");
        assert!(!ap.contains("erc20"), "{ap}");
        assert!(ap.contains("amount or token id"), "{ap}");

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

#[cfg(test)]
#[cfg(feature = "chain-eth")]
mod review_pagination_pins {
    use super::*;

    /// Every line on its own page boundary: the geometry must be exactly the old
    /// `ceil(count / page_lines)`, so a request whose content has no glued pairs pages
    /// identically to before this feature.
    #[test]
    fn without_glue_the_geometry_is_the_plain_ceil() {
        for count in [1usize, 5, 12, 13, 24, 25, 37] {
            assert_eq!(
                page_count(count, 0, 12),
                count.div_ceil(12),
                "count {count}"
            );
            for page in 0..page_count(count, 0, 12) {
                let (first, len) = page_span(count, 0, 12, page);
                assert_eq!(first, page * 12, "count {count} page {page}");
                assert_eq!(len, core::cmp::min(12, count - first));
            }
        }
    }

    /// The defect this exists for: a label on the last row of a page with its value on
    /// the next. The page now ends one row earlier so both travel together.
    #[test]
    fn a_glued_value_never_opens_a_page() {
        let count = 30usize;
        // line 12 is the value of line 11 → it must not start page 2
        let mask = 1u64 << 12;
        let (first0, len0) = page_span(count, mask, 12, 0);
        assert_eq!((first0, len0), (0, 11), "page 1 must stop before the label");
        let (first1, len1) = page_span(count, mask, 12, 1);
        assert_eq!(first1, 11, "page 2 starts at the label");
        assert_eq!(len1, 12, "and carries label + value");
        // the whole view is still covered exactly once, in order
        let mut covered = alloc::vec::Vec::new();
        for p in 0..page_count(count, mask, 12) {
            let (f, l) = page_span(count, mask, 12, p);
            covered.extend(f..f + l);
        }
        assert_eq!(covered, (0..count).collect::<alloc::vec::Vec<_>>());
    }

    /// Consecutive glued lines walk the break back as far as needed.
    #[test]
    fn a_chain_of_glued_lines_moves_the_break_further() {
        let count = 30usize;
        let mask = (1u64 << 11) | (1u64 << 12) | (1u64 << 13); // 10 is the label
        let (first, len) = page_span(count, mask, 12, 0);
        assert_eq!(
            (first, len),
            (0, 10),
            "page 1 stops before the 3-line group"
        );
        let (next_first, _) = page_span(count, mask, 12, 1);
        assert_eq!(next_first, 10);
    }

    /// A group longer than a page cannot be kept together; the paginator must still
    /// make progress and never render an empty page (a dead `wire` key on a device is
    /// worse than a split group).
    #[test]
    fn an_unglueable_run_still_pages_forward() {
        let count = 40usize;
        // every line glues to the previous one: no allowed break anywhere past 0
        let mask = !1u64;
        let pages = page_count(count, mask, 12);
        assert!(pages >= 4, "must page forward, got {pages}");
        let mut covered = alloc::vec::Vec::new();
        for p in 0..pages {
            let (f, l) = page_span(count, mask, 12, p);
            assert!(l > 0, "page {p} is empty");
            covered.extend(f..f + l);
        }
        assert_eq!(covered, (0..count).collect::<alloc::vec::Vec<_>>());
    }

    /// The real views: a label and its value are glued, and the mask reaches the
    /// platform. Checked on the ETH send shape (to: + address, and the calldata
    /// detail lines the Sepolia run showed split across pages).
    #[test]
    fn the_send_view_glues_labels_to_their_values() {
        use crate::chain::eth::calldata::DecodedCalldata;
        use crate::encoding::cbor;

        // ETH send with an approve calldata: `to:` + address and `spender` + value are
        // the two pairs that were split on the real device.
        let mut data = alloc::vec![0x09, 0x5e, 0xa7, 0xb3];
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&[0x9bu8; 20]);
        data.extend_from_slice(&{
            let mut w = [0u8; 32];
            w[31] = 1;
            w
        });
        use crate::chain::eth::rlp;
        let fields = alloc::vec![
            rlp::encode_uint(1),
            rlp::encode_uint(0),
            rlp::encode_uint(1_000_000_000),
            rlp::encode_uint(2_000_000_000),
            rlp::encode_uint(60_000),
            rlp::encode_bytes(&[0x11u8; 20]),
            rlp::encode_uint(0),
            rlp::encode_bytes(&data),
            rlp::encode_list(&[]),
        ];
        let mut raw = alloc::vec![0x02u8];
        raw.extend_from_slice(&rlp::encode_list(&fields));
        let payload = cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(37, &cbor::encode_bytes(&[0x9bu8; 16])),
            ),
            (cbor::encode_uint(2), cbor::encode_bytes(&raw)),
            (cbor::encode_uint(3), cbor::encode_uint(4)),
            (cbor::encode_uint(4), cbor::encode_uint(1)),
        ]);
        let view = build_eth_ws(&payload).expect("review");
        let mask = view.break_mask();
        let texts: alloc::vec::Vec<&str> = view.lines().iter().map(|l| l.as_str()).collect();

        // every "label then value" pair: the value line must carry the glue bit
        for (i, t) in texts.iter().enumerate() {
            if *t == "to:" || *t == "spender" || *t == "amount or token id" {
                assert!(
                    i + 1 < texts.len(),
                    "{t} is the last line — nothing to glue"
                );
                assert!(
                    (mask >> (i + 1)) & 1 == 1,
                    "line {} ({:?}) must not open a page",
                    i + 1,
                    texts[i + 1]
                );
            }
        }
        // …and a wrapped address keeps only its first chunk glued
        let _ = DecodedCalldata::Empty; // keep the import used if the shape changes
    }
}

#[cfg(test)]
#[cfg(feature = "chain-eth")]
mod erc20_transfer_layout_pins {
    //! The page layout the operator actually saw on the mainnet acceptance run
    //! (2026-11-25, tx 0xb29c50b4…2ff0, firmware `e303033`): page 1 ends at the
    //! calldata label because the next line is a label whose value is glued to it, so
    //! the whole `recipient` pair travels to page 2. Pinned as a layout, not as an
    //! implementation detail: if a line is added or the glue rules change, this test
    //! makes someone look at the screen again.
    use super::*;
    use crate::encoding::cbor;

    const RECIPIENT: [u8; 20] = [
        0xd0, 0x03, 0x87, 0xde, 0x9f, 0x68, 0xc9, 0x64, 0x2e, 0x25, 0xd4, 0xc1, 0x94, 0xd6, 0xe1,
        0xce, 0x23, 0x36, 0x33, 0xc0,
    ];
    const USDC: [u8; 20] = [
        0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0,
        0xce, 0x36, 0x06, 0xeb, 0x48,
    ];

    fn transfer_request() -> alloc::vec::Vec<u8> {
        use crate::chain::eth::rlp;
        let mut data = alloc::vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&RECIPIENT);
        data.extend_from_slice(&[0u8; 29]);
        data.extend_from_slice(&[0x0f, 0x42, 0x40]); // 1_000_000
        let fields = alloc::vec![
            rlp::encode_uint(1),
            rlp::encode_uint(2),
            rlp::encode_uint(100_000),
            rlp::encode_uint(204_205_660),
            rlp::encode_uint(94_548),
            rlp::encode_bytes(&USDC),
            rlp::encode_uint(0),
            rlp::encode_bytes(&data),
            rlp::encode_list(&[]),
        ];
        let mut raw = alloc::vec![0x02u8];
        raw.extend_from_slice(&rlp::encode_list(&fields));
        cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(37, &cbor::encode_bytes(&[0x9bu8; 16])),
            ),
            (cbor::encode_uint(2), cbor::encode_bytes(&raw)),
            (cbor::encode_uint(3), cbor::encode_uint(4)),
            (cbor::encode_uint(4), cbor::encode_uint(1)),
        ])
    }

    #[test]
    fn the_verified_mainnet_layout_pages_as_the_device_showed_it() {
        let payload = transfer_request();
        let view = build_eth_ws(&payload).expect("review");
        let texts: alloc::vec::Vec<&str> = view.lines().iter().map(|l| l.as_str()).collect();
        assert_eq!(texts.len(), 15, "the send view is 15 lines: {texts:?}");

        let mask = view.break_mask();
        assert_eq!(page_count(15, mask, 12), 2, "two pages");
        assert_eq!(page_span(15, mask, 12, 0), (0, 11), "page 1: {texts:?}");
        assert_eq!(page_span(15, mask, 12, 1), (11, 4), "page 2: {texts:?}");

        // page 1 ends on the calldata label; its value pair opens page 2
        assert_eq!(texts[10], "erc20 transfer");
        assert_eq!(texts[11], "recipient");
        assert_eq!(texts[12], "0xd00387de9f68C9642e25d4c194d6e1cE233633C0");
        assert_eq!(texts[13], "amount");
        assert_eq!(texts[14], "1000000");
        // …and the destination pair sits together on page 1
        assert_eq!(texts[2], "to:");
        assert_eq!(texts[3], "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    }
}

#[cfg(test)]
#[cfg(feature = "chain-eth")]
mod sepolia_acceptance_pins {
    //! Calldata taken from the six device-signed Sepolia transactions of 2026-11-25
    //! (MetaMask official test-dApp; txids in the acceptance record). These are what a
    //! real dApp put on the wire — not hand-written fixtures — so a rendering change
    //! that would mislabel one of them turns this module red.
    use super::*;
    use crate::chain::eth::calldata::DecodedCalldata;

    fn word(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }

    fn addr(hex: &str) -> [u8; 20] {
        let mut a = [0u8; 20];
        for i in 0..20 {
            a[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        a
    }

    fn render(decoded: &DecodedCalldata) -> alloc::string::String {
        let mut view = ReviewView::new();
        push_decoded_calldata(&mut view, decoded).expect("render");
        let mut s = alloc::string::String::new();
        for l in view.lines() {
            s.push_str(l.as_str());
            s.push('\n');
        }
        s
    }

    /// `0x095ea7b3` is ERC-20 `approve(address,uint256)` **and** ERC-721
    /// `approve(address,uint256)`. The same four bytes carry an allowance in the first
    /// case and a token id in the second, so both must render with the same neutral
    /// labels — the device cannot tell them apart and must not pretend to.
    #[test]
    fn the_shared_approve_selector_never_names_a_token_standard() {
        let spender = addr("9bc5baf874d2da8d216ae9f137804184ee5afef4");
        // ERC-20 approve: 70000 units (Sepolia tx 0xbfa80281…)
        let erc20 = render(&DecodedCalldata::Approve {
            spender,
            amount: word(70_000),
        });
        // ERC-721 approve: token id 1 (Sepolia tx 0x47a148a0…)
        let erc721 = render(&DecodedCalldata::Approve {
            spender,
            amount: word(1),
        });
        for t in [&erc20, &erc721] {
            assert!(!t.contains("erc20"), "no token-standard claim: {t}");
            assert!(t.contains("approve"), "{t}");
            assert!(t.contains("amount or token id"), "{t}");
            assert!(
                t.contains("0x9bc5baF874d2DA8D216aE9f137804184EE5AfEF4"),
                "spender must be the EIP-55 form: {t}"
            );
        }
        assert!(erc20.contains("\n70000\n"), "{erc20}");
        assert!(erc721.contains("\n1\n"), "{erc721}");
    }

    /// `setApprovalForAll` (Sepolia tx 0xabfd5b23…): operator + the boolean verdict must
    /// both be on the screen — "approved: no" is a revoke and reads differently.
    #[test]
    fn set_approval_for_all_shows_the_verdict() {
        let operator = addr("9bc5baf874d2da8d216ae9f137804184ee5afef4");
        let yes = render(&DecodedCalldata::SetApprovalForAll {
            operator,
            approved: true,
        });
        assert!(yes.contains("set approval for all"), "{yes}");
        assert!(yes.contains("operator"), "{yes}");
        assert!(yes.contains("approved: yes"), "{yes}");
        let no = render(&DecodedCalldata::SetApprovalForAll {
            operator,
            approved: false,
        });
        assert!(no.contains("approved: no"), "{no}");
    }

    /// `increaseAllowance` (Sepolia tx 0x6da06d0d…) is ERC-20 only, so it keeps the
    /// family label — the contrast with the shared `approve` is deliberate.
    #[test]
    fn increase_allowance_is_erc20_and_labelled_as_such() {
        let t = render(&DecodedCalldata::IncreaseAllowance {
            spender: addr("9bc5baf874d2da8d216ae9f137804184ee5afef4"),
            added: word(10_000),
        });
        assert!(t.contains("erc20 increase allowance"), "{t}");
        assert!(t.contains("\n10000\n"), "{t}");
    }
}

#[cfg(test)]
#[cfg(feature = "chain-eth")]
mod eth_unknown_call_pins {
    use super::*;
    use crate::encoding::cbor;

    /// A 1559 request whose calldata is `data`, optionally with no destination
    /// (contract creation).
    fn request_with(calldata: &[u8], destination: Option<[u8; 20]>) -> alloc::vec::Vec<u8> {
        use crate::chain::eth::rlp;
        let fields = alloc::vec![
            rlp::encode_uint(1),
            rlp::encode_uint(0),
            rlp::encode_uint(1_000_000_000),
            rlp::encode_uint(2_000_000_000),
            rlp::encode_uint(100_000),
            match destination {
                Some(d) => rlp::encode_bytes(&d),
                None => rlp::encode_bytes(&[]),
            },
            rlp::encode_uint(0),
            rlp::encode_bytes(calldata),
            rlp::encode_list(&[]),
        ];
        let mut raw = alloc::vec![0x02u8];
        raw.extend_from_slice(&rlp::encode_list(&fields));
        cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(37, &cbor::encode_bytes(&[0x9bu8; 16])),
            ),
            (cbor::encode_uint(2), cbor::encode_bytes(&raw)),
            (cbor::encode_uint(3), cbor::encode_uint(4)),
            (cbor::encode_uint(4), cbor::encode_uint(1)),
        ])
    }

    fn text(payload: &[u8]) -> alloc::string::String {
        let view = build_eth_ws(payload).expect("review renders");
        let mut s = alloc::string::String::new();
        for l in view.lines() {
            s.push_str(l.as_str());
            s.push('\n');
        }
        s
    }

    /// Sepolia 2026-11-25: a deploy was labelled `call: unknown contract`, which reads
    /// like a failed lookup against a contract that exists. There is no callee at all.
    #[test]
    fn contract_creation_says_deploy_not_unknown_contract() {
        let t = text(&request_with(&[0x61, 0x01, 0x40, 0x60, 0x80], None));
        assert!(t.contains("to: contract creation"), "{t}");
        assert!(t.contains("call: contract deploy"), "{t}");
        assert!(!t.contains("unknown contract"), "{t}");
    }

    /// Same run: a non-standard selector (the dApp's `mint`) printed only
    /// `unknown contract`, leaving the operator nothing to compare against. The four
    /// bytes are now on the screen.
    #[test]
    fn unknown_selector_is_printed() {
        let mut cd = alloc::vec![0x3b, 0xb1, 0x38, 0x1bu8]; // mint-ish, not in our table
        cd.extend_from_slice(&[0u8; 32]);
        let t = text(&request_with(&cd, Some([0x86u8; 20])));
        assert!(t.contains("call: unknown contract"), "{t}");
        assert!(t.contains("selector 0x3bb1381b"), "{t}");
    }

    /// A known selector with the wrong argument count keeps its "shape does not match"
    /// verdict and now also shows the selector, so a photo of the screen identifies the
    /// call without a debug channel.
    #[test]
    fn shape_mismatch_shows_the_selector() {
        // approve selector with a single word instead of two
        let mut cd = alloc::vec![0x09, 0x5e, 0xa7, 0xb3];
        cd.extend_from_slice(&[0u8; 32]);
        let t = text(&request_with(&cd, Some([0x11u8; 20])));
        assert!(t.contains("shape does not match"), "{t}");
        assert!(t.contains("selector 0x095ea7b3"), "{t}");
    }
}

#[cfg(test)]
#[cfg(feature = "chain-eth")]
mod eth_data_type_dispatch_pins {
    use super::*;

    /// eth-sign-request CBOR map, ur-registry shape:
    /// {1: request_id (tag 37 UUID), 2: sign_data, 3: data_type, 4: chain_id}
    fn request_map(sign_data: &[u8], data_type: u64, chain_id: u64) -> alloc::vec::Vec<u8> {
        use crate::encoding::cbor;
        cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(37, &cbor::encode_bytes(&[0x9bu8; 16])),
            ),
            (cbor::encode_uint(2), cbor::encode_bytes(sign_data)),
            (cbor::encode_uint(3), cbor::encode_uint(data_type)),
            (cbor::encode_uint(4), cbor::encode_uint(chain_id)),
        ])
    }

    /// A bare RLP list with the 1559 field body but no type byte — a shape that is
    /// neither a legacy request nor a typed transaction.
    fn bare_rlp_body() -> alloc::vec::Vec<u8> {
        use crate::chain::eth::rlp;
        rlp::encode_list(&[
            rlp::encode_uint(1),
            rlp::encode_uint(0),
            rlp::encode_uint(1_000_000_000),
            rlp::encode_uint(2_000_000_000),
            rlp::encode_uint(21_000),
            rlp::encode_bytes(&[0x11u8; 20]),
            rlp::encode_uint(12345),
            rlp::encode_bytes(b""),
            rlp::encode_list(&[]),
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
        ])
    }

    /// The legacy (EIP-155) preimage `rlp([nonce, gas_price, gas_limit, to, value,
    /// data, chain_id, [], []])` — the shape a `data_type` 1 request carries.
    fn legacy_preimage(chain_id: u64) -> alloc::vec::Vec<u8> {
        use crate::chain::eth::eip155::{self, Eip155Transaction};
        eip155::signing_preimage(&Eip155Transaction {
            chain_id,
            nonce: 7,
            gas_price: 30_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 1_000_000_000_000_000,
            data: alloc::vec::Vec::new().into(),
        })
    }

    fn joined(view: &ReviewView) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        for l in view.lines() {
            s.push_str(l.as_str());
            s.push('\n');
        }
        s
    }

    /// E-1 (2026-11-25): `data_type` 1 = legacy EIP-155 is reviewable now, and the
    /// page names the ONE fee this scheme pays.
    ///
    /// A legacy transaction has a `gas price`, not a base fee and not a priority tip:
    /// printing "max fee" here would describe a 1559 send the operator is not
    /// approving. The worst case (gas_limit × gas price + value) is still shown,
    /// because that is the ceiling they are authorizing either way.
    #[test]
    fn eth_review_renders_a_legacy_send_with_gas_price() {
        let payload = request_map(&legacy_preimage(1), 1, 1);
        let view = build_eth_ws(&payload).expect("legacy sends render");
        let text = joined(&view);
        assert!(text.contains("eth send request"), "{text}");
        assert!(text.contains("chain 1 ethereum mainnet"), "{text}");
        assert!(text.contains("to:"), "{text}");
        assert!(text.contains("value 1000000000000000 wei"), "{text}");
        assert!(text.contains("gas limit 21000"), "{text}");
        assert!(
            text.contains("gas price 30000000000 wei"),
            "legacy pays gas price, in wei: {text}"
        );
        // 21000 * 30 gwei + 0.001 ETH
        assert!(
            text.contains("max cost 1630000000000000 wei"),
            "worst case = gas_limit × gas price + value: {text}"
        );
        assert!(text.contains("data: none"), "{text}");
        // the two 1559-only fee words must not appear on a legacy page
        assert!(
            !text.contains("max fee") && !text.contains("priority fee"),
            "legacy has no max fee / priority fee: {text}"
        );
    }

    /// An unprotected legacy request has no chain id at all: it is a shape we refuse
    /// on purpose, and the operator must see it refused — not rendered as a send with
    /// a guessed network.
    #[test]
    fn eth_review_refuses_unprotected_legacy() {
        use crate::chain::eth::rlp;
        let six = rlp::encode_list(&[
            rlp::encode_uint(7),
            rlp::encode_uint(30_000_000_000),
            rlp::encode_uint(21_000),
            rlp::encode_bytes(&[0x11u8; 20]),
            rlp::encode_uint(0),
            rlp::encode_bytes(b""),
        ]);
        let result = build_eth_ws(&request_map(&six, 1, 1));
        assert!(result.is_err(), "6-item legacy must not render");
        if let Err(e) = result {
            assert_eq!(e.kind, ShlosiloErrorKind::FeatureNotImplemented, "{e:?}");
        }
    }

    /// A typed transaction body with its `0x02` type byte stripped is not a legacy
    /// request (12 items, item 6 is a fee, its signature slots are full of access-list
    /// shape): it must be refused as malformed rather than rendered as a send.
    #[test]
    fn eth_review_refuses_a_typed_body_without_its_type_byte() {
        let payload = request_map(&bare_rlp_body(), 1, 1);
        // ReviewView has no Debug, so assert on the error rather than unwrap_err().
        let result = build_eth_ws(&payload);
        assert!(
            result.is_err(),
            "a 12-item body under data_type 1 must be refused, not rendered as a send"
        );
        if let Err(e) = result {
            assert_eq!(
                e.kind,
                ShlosiloErrorKind::EncodingInvalidFormat,
                "12 items is not a legacy request shape"
            );
        }
    }

    /// The legacy page refuses a request whose own `chain_id` disagrees with the
    /// transaction, exactly like the 1559 page: the operator must never confirm a
    /// network this device will not sign for.
    #[test]
    fn eth_review_legacy_refuses_a_chain_id_mismatch() {
        // request says chain 5, the preimage says chain 1
        let result = build_eth_ws(&request_map(&legacy_preimage(1), 1, 5));
        assert!(result.is_err(), "a chain mismatch must not render");
        if let Err(e) = result {
            assert_eq!(e.kind, ShlosiloErrorKind::NetworkUnrecognized);
        }
        // control: the matching pairing renders
        let view =
            build_eth_ws(&request_map(&legacy_preimage(1), 1, 1)).expect("matching chain renders");
        assert!(joined(&view).contains("chain 1 ethereum mainnet"));
    }

    /// `data_type` 4 dispatches on the first payload byte, mirroring the sign path: the
    /// real-but-unsupported types read as unimplemented, anything else as a format error.
    /// Only 0x02 may reach the renderer.
    #[test]
    fn eth_review_refuses_unsupported_typed_transactions() {
        let cases: [(alloc::vec::Vec<u8>, ShlosiloErrorKind, &str); 5] = [
            (
                alloc::vec![0x01u8],
                ShlosiloErrorKind::FeatureNotImplemented,
                "0x01 (EIP-2930) is a real transaction type we do not sign",
            ),
            (
                alloc::vec![0x03u8],
                ShlosiloErrorKind::FeatureNotImplemented,
                "0x03 (EIP-4844) is a real transaction type we do not sign",
            ),
            (
                alloc::vec![0x04u8],
                ShlosiloErrorKind::FeatureNotImplemented,
                "0x04 (EIP-7702) is a real transaction type we do not sign",
            ),
            (
                alloc::vec![0x99u8],
                ShlosiloErrorKind::EncodingInvalidFormat,
                "0x99 is not a transaction type",
            ),
            (
                alloc::vec::Vec::new(),
                ShlosiloErrorKind::EncodingInvalidFormat,
                "an empty payload has no type byte",
            ),
        ];
        for (sign_data, expected, why) in cases {
            let payload = request_map(&sign_data, 4, 1);
            let result = build_eth_ws(&payload);
            assert!(result.is_err(), "{why}");
            if let Err(e) = result {
                assert_eq!(e.kind, expected, "{why}");
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "chain-eth")]
mod eth_personal_message_review_pins {
    use super::*;
    use crate::encoding::cbor;

    /// `eth-sign-request` map for a personal message: `{1: tag(37) uuid, 2: message,
    /// 3: data_type = 3}`.
    fn personal_request(message: &[u8]) -> alloc::vec::Vec<u8> {
        cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(37, &cbor::encode_bytes(&[0x9bu8; 16])),
            ),
            (cbor::encode_uint(2), cbor::encode_bytes(message)),
            (cbor::encode_uint(3), cbor::encode_uint(3)), // PersonalMessage
        ])
    }

    fn lines(view: &ReviewView) -> alloc::vec::Vec<alloc::string::String> {
        view.lines()
            .iter()
            .map(|l| alloc::string::String::from(l.as_str()))
            .collect()
    }

    /// The device signs this scheme (EIP-191), so the message it is signing has to be
    /// on the screen. `cannot display on this screen` was the pre-wiring placeholder;
    /// keeping it after wiring would make every personal_sign a blind signature.
    #[test]
    fn personal_message_review_shows_the_text() {
        let msg = b"Example `personal_sign` message";
        let view = build_eth_ws(&personal_request(msg)).expect("review");
        let joined = lines(&view).join("\n");
        assert!(joined.contains("eth message sign"), "{joined}");
        assert!(
            joined.contains(&alloc::format!("message {} bytes", msg.len())),
            "{joined}"
        );
        assert!(
            joined.contains("Example `personal_sign` message"),
            "the message text must be on the screen: {joined}"
        );
        assert!(
            !joined.contains("cannot display"),
            "personal_sign is signed now; the screen must show what is signed: {joined}"
        );
    }

    /// Non-printable bytes are escaped, so a message cannot render as something other
    /// than the bytes that get signed (a raw newline would move text between lines; an
    /// escape sequence could repaint a terminal).
    #[test]
    fn personal_message_review_escapes_non_printable_bytes() {
        let msg = b"line1\nline2\x1b[31m";
        let view = build_eth_ws(&personal_request(msg)).expect("review");
        let joined = lines(&view).join("\n");
        assert!(
            !joined.contains("line1\nline2"),
            "the embedded newline must not split the message: {joined}"
        );
        assert!(
            joined.contains("line1.line2.[31m") || joined.contains("line1.line2."),
            "control bytes render as dots: {joined}"
        );
        assert!(!joined.contains('\u{1b}'), "no raw ESC on the screen");
    }

    /// A long message is shown truncated but marked, and the true length is printed, so
    /// the operator can tell the screen is showing a prefix.
    #[test]
    fn personal_message_review_marks_truncation() {
        let msg = alloc::vec![b'A'; 400];
        let view = build_eth_ws(&personal_request(&msg)).expect("review");
        let joined = lines(&view).join("\n");
        assert!(joined.contains("message 400 bytes"), "{joined}");
        assert!(joined.contains("..truncated"), "{joined}");
        assert!(
            view.lines().len() <= REVIEW_LINES_MAX,
            "the view stays bounded"
        );
    }
}

#[cfg(test)]
#[cfg(feature = "chain-eth")]
mod eth_amount_rendering_pins {
    use super::*;
    use crate::chain::eth::calldata::DecodedCalldata;

    fn view_for(decoded: &DecodedCalldata) -> alloc::string::String {
        let mut view = ReviewView::new();
        push_decoded_calldata(&mut view, decoded).expect("render");
        let mut s = alloc::string::String::new();
        for l in view.lines() {
            s.push_str(l.as_str());
            s.push('\n');
        }
        s
    }

    fn word(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }

    /// The acceptance case: a 1.0 USDC transfer (raw 1_000_000, 6 decimals) rendered
    /// as `0x0f4240` on the real device run. Decimal raw units is the readable form —
    /// and the token's decimals are still not guessed, so no decimal point appears.
    #[test]
    fn erc20_amounts_render_in_decimal_raw_units() {
        let text = view_for(&DecodedCalldata::Transfer {
            to: [0x11u8; 20],
            amount: word(1_000_000),
        });
        assert!(text.contains("erc20 transfer"), "{text}");
        assert!(
            text.contains("\n1000000\n"),
            "amount must be decimal: {text}"
        );
        assert!(!text.contains("0x0f4240"), "hex is unreadable here: {text}");
    }

    /// Zero and the "unlimited" sentinel keep their dedicated renderings.
    #[test]
    fn erc20_amount_edge_values() {
        assert!(view_for(&DecodedCalldata::Transfer {
            to: [0x11u8; 20],
            amount: word(0),
        })
        .contains("\n0\n"));
        assert!(view_for(&DecodedCalldata::Approve {
            spender: [0x22u8; 20],
            amount: [0xffu8; 32],
        })
        .contains("unlimited"));
    }

    /// A u256 amount at the top of the range would not fit a 48-column line; the
    /// review refuses rather than printing a partial number.
    #[test]
    fn erc20_amount_too_wide_is_refused() {
        let mut view = ReviewView::new();
        let mut big = [0xffu8; 32];
        big[0] = 0x7f; // not the unlimited sentinel, but a 77-digit number
        let result = push_decoded_calldata(
            &mut view,
            &DecodedCalldata::Transfer {
                to: [0x11u8; 20],
                amount: big,
            },
        );
        assert!(result.is_err(), "a 77-digit amount must not be truncated");
    }

    /// Guard the reproduction: the fixture used above must be the shape the device
    /// actually saw (selector + two words), so the pin keeps matching a real request.
    #[test]
    fn the_acceptance_calldata_shape_is_transfer_selector_plus_two_words() {
        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&[
            0xd0u8, 0x03, 0x87, 0xde, 0x9f, 0x68, 0xc9, 0x64, 0x2e, 0x25, 0xd4, 0xc1, 0x94, 0xd6,
            0xe1, 0xce, 0x23, 0x36, 0x33, 0xc0,
        ]);
        data.extend_from_slice(&word(1_000_000));
        assert_eq!(data.len(), 68, "a real erc20 transfer request is 68 bytes");
        let decoded = crate::chain::eth::calldata::decode_calldata(&data).expect("decodes");
        match decoded {
            DecodedCalldata::Transfer { to, amount } => {
                assert_eq!(amount, word(1_000_000));
                let rendered = crate::address::eth::encode_bytes(&to).expect("eip55");
                assert_eq!(
                    rendered.as_ref(),
                    "0xd00387de9f68C9642e25d4c194d6e1cE233633C0",
                    "the screen showed this casing"
                );
            }
            _ => panic!("must decode as erc20 transfer"),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "chain-eth")]
mod eth_typed_data_review_pins {
    use super::*;
    use crate::encoding::cbor;

    fn typed_data_request(blob: &[u8]) -> alloc::vec::Vec<u8> {
        cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(37, &cbor::encode_bytes(&[0x9bu8; 16])),
            ),
            (cbor::encode_uint(2), cbor::encode_bytes(blob)),
            (cbor::encode_uint(3), cbor::encode_uint(2)), // TypedData
        ])
    }

    /// E-3 P3: typed data now has a container and a page, so a payload that is not
    /// typed-data JSON is refused as a format error instead of being described by its
    /// byte count. The old page said how many bytes it could not show; the new one either
    /// shows the document or says it is not one.
    #[test]
    fn typed_data_review_refuses_a_payload_that_is_not_json() {
        let blob = alloc::vec![b'x'; 512];
        let err = match build_eth_ws(&typed_data_request(&blob)) {
            Ok(_) => panic!("512 x's is not typed-data JSON"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind,
            ShlosiloErrorKind::EncodingInvalidFormat,
            "a non-JSON typed-data payload is a format error"
        );
    }

    /// A real ERC-2612 permit renders the values the operator has to check: the primary
    /// type, the domain it is bound to (name, chain, verifying contract) and every
    /// top-level field.
    #[test]
    fn typed_data_review_renders_a_permit() {
        let permit = br#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]},"primaryType":"Permit","domain":{"name":"USD Coin","version":"2","chainId":1,"verifyingContract":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"},"message":{"owner":"0x1111111111111111111111111111111111111111","spender":"0x2222222222222222222222222222222222222222","value":"1000000","nonce":0,"deadline":1700000000}}"#;
        let view = build_eth_ws(&typed_data_request(permit)).expect("permit renders");
        let mut text = alloc::string::String::new();
        for l in view.lines() {
            text.push_str(l.as_str());
            text.push('\n');
        }
        for needle in [
            "eth typed data",
            "sign Permit",
            "domain",
            "name USD Coin",
            "chain 1 ethereum mainnet",
            "verifying contract",
            // the address is re-encoded as EIP-55, not echoed as the wire's lowercase form
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "owner",
            "0x1111111111111111111111111111111111111111",
            "spender",
            "value 1000000",
            "nonce 0",
            "deadline 1700000000",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
    }

    /// A workspace one byte short of what the page needs is `BufferTooSmall` with the size
    /// that would have worked — never a page drawn from leftover bytes.
    #[test]
    fn typed_data_workspace_capacity_is_explicit() {
        let permit = br#"{"types":{"EIP712Domain":[],"Permit":[]},"primaryType":"Permit","domain":{},"message":{}}"#;
        let req = typed_data_request(permit);
        let mut short = alloc::vec![0u8; TYPED_DATA_WS_BYTES - 1];
        let err = match build_eth(&req, &mut short) {
            Ok(_) => panic!("a short workspace must be refused"),
            Err(e) => e,
        };
        assert_eq!(err.kind, ShlosiloErrorKind::BufferTooSmall);
        assert_eq!(
            err.context,
            crate::error::ErrorContext::RequiredLength(TYPED_DATA_WS_BYTES),
            "the refusal must name the size that fits"
        );
    }
}

#[cfg(test)]
#[cfg(feature = "chain-eth")]
mod eth_send_fee_review_pins {
    use super::*;
    use crate::chain::eth::rlp;
    use crate::encoding::cbor;

    /// Unsigned EIP-1559 payload: `0x02 || rlp([...12 fields...])`.
    fn unsigned_1559() -> alloc::vec::Vec<u8> {
        let mut raw = alloc::vec![0x02u8];
        raw.extend_from_slice(&rlp::encode_list(&[
            rlp::encode_uint(1),              // chain_id
            rlp::encode_uint(0),              // nonce
            rlp::encode_uint(1_000_000_000),  // max_priority_fee_per_gas
            rlp::encode_uint(2_000_000_000),  // max_fee_per_gas
            rlp::encode_uint(21_000),         // gas_limit
            rlp::encode_bytes(&[0x11u8; 20]), // destination
            rlp::encode_uint(12345),          // amount
            rlp::encode_bytes(b""),           // data
            rlp::encode_list(&[]),            // access_list
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
        ]));
        raw
    }

    /// `{1: tag(37) uuid, 2: sign_data, 3: data_type = 4, 4: chain_id}`
    fn typed_request(sign_data: &[u8], chain_id: u64) -> alloc::vec::Vec<u8> {
        cbor::encode_map(&[
            (
                cbor::encode_uint(1),
                cbor::encode_tag(37, &cbor::encode_bytes(&[0x9bu8; 16])),
            ),
            (cbor::encode_uint(2), cbor::encode_bytes(sign_data)),
            (cbor::encode_uint(3), cbor::encode_uint(4)),
            (cbor::encode_uint(4), cbor::encode_uint(chain_id)),
        ])
    }

    fn joined(view: &ReviewView) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        for l in view.lines() {
            s.push_str(l.as_str());
            s.push('\n');
        }
        s
    }

    /// EIP-1559 pays two fees; the operator authorizes a maximum, so the maximum has to
    /// be on the screen in the units the wire uses (wei). A rounded gwei figure would be
    /// a guess where the exact number matters.
    #[test]
    fn eth_send_review_shows_both_fees() {
        let view = build_eth_ws(&typed_request(&unsigned_1559(), 1)).expect("review");
        let text = joined(&view);
        assert!(text.contains("max fee 2000000000 wei"), "{text}");
        assert!(text.contains("priority fee 1000000000 wei"), "{text}");
        // the fee lines sit next to the gas limit, not somewhere else on the page
        let idx_gas = text.find("gas limit 21000").expect("gas line");
        let idx_max = text.find("max fee").expect("max fee line");
        assert!(idx_gas < idx_max, "fee lines follow the gas limit: {text}");
    }

    /// The signer refuses a request whose chain_id disagrees with its transaction, so the
    /// review must refuse it too — otherwise an operator confirms a network this device
    /// will not sign for.
    #[test]
    fn eth_send_review_refuses_chain_id_mismatch() {
        let result = build_eth_ws(&typed_request(&unsigned_1559(), 5));
        assert!(
            result.is_err(),
            "a chain_id that disagrees with the transaction must not render"
        );
        if let Err(e) = result {
            assert_eq!(e.kind, ShlosiloErrorKind::NetworkUnrecognized);
        }
    }

    /// The operator authorizes a ceiling, so the review must name it: gas_limit ×
    /// max_fee + value, in wei, and every amount line carries its unit (a bare number
    /// next to a `wei` line is the kind of mixed-unit screen that gets misread).
    #[test]
    fn eth_send_review_shows_the_worst_case_cost() {
        let view = build_eth_ws(&typed_request(&unsigned_1559(), 1)).expect("review");
        let text = joined(&view);
        // 21_000 * 2_000_000_000 + 12_345
        let want = 21_000u128 * 2_000_000_000u128 + 12_345u128;
        assert!(
            text.contains(&alloc::format!("max cost {} wei", want)),
            "worst-case cost missing: {text}"
        );
        assert!(
            text.contains("value 12345 wei"),
            "value needs its unit: {text}"
        );
        // every amount line states its unit
        for line in text.lines() {
            let has_number = line.chars().any(|c| c.is_ascii_digit());
            if has_number
                && (line.starts_with("value")
                    || line.starts_with("max fee")
                    || line.starts_with("priority fee")
                    || line.starts_with("max cost")
                    || line.starts_with("gas limit"))
            {
                assert!(
                    line.ends_with(" wei") || line.starts_with("gas limit"),
                    "amount line without its unit: {line}"
                );
            }
        }
    }

    /// Control: the matching chain_id still renders, so the pin above is not passing for
    /// an unrelated reason.
    #[test]
    fn eth_send_review_accepts_matching_chain_id() {
        let view = build_eth_ws(&typed_request(&unsigned_1559(), 1)).expect("review");
        assert!(joined(&view).contains("chain 1"));
    }
}
