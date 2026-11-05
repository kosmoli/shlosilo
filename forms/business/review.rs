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
    /// Non-zero locktime (height or time).
    pub const LOCKTIME: u16 = 1 << 4;
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
        UrTypeTag::CryptoPsbt => build_btc(payload, network, master_fingerprint, arena, recs),
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
        // A sighash other than ALL (0x01) needs the operator's eyes: NONE and
        // SINGLE let the coordinator rewrite outputs after our signature.
        let sighash = map
            .iter()
            .find(|kv| kv.key.first() == Some(&psbt::input_type::SIGHASH_TYPE))
            .and_then(|kv| kv.value.first().copied());
        if sighash.is_some_and(|v| v != 0x01) {
            view.flags |= flag::SIGHASH_UNSAFE;
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
        let is_change = match (master_fingerprint, psbt.output_map_checked(i)) {
            (Some(ours), Some(map)) => map_carries_our_fingerprint(map, ours),
            _ => false,
        };
        // One labelled row per output: the amount carries its unit and the
        // role (send / change) so a page never shows a bare number, and the
        // address follows on its own line (wrapped, never truncated).
        view.push_fmt(format_args!(
            "{} {} sats",
            if is_change { "change" } else { "send" },
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
    let mut head: heapless::Vec<Line, 3> = heapless::Vec::new();
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
    if rbf {
        view.flags |= flag::RBF;
    }
    if psbt.unsigned_tx.lock_time != 0 {
        view.flags |= flag::LOCKTIME;
    }

    // head lines first, then the body
    let mut merged: heapless::Vec<Line, REVIEW_LINES_MAX> = heapless::Vec::new();
    for line in head.iter() {
        merged
            .push(line.clone())
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

/// Network implied by the inputs' BIP-44 coin type (1 → testnet/signet).
///
/// Reviewed as "the PSBT tells us where it lives": wallets put the coin type in
/// the derivation path they hand the signer, and a mismatched address prefix is
/// exactly the kind of error the operator would mis-read.
fn infer_network(psbt: &Psbt<'_>) -> Option<Network> {
    for i in 0..psbt.unsigned_tx.inputs.len() {
        let map = psbt.input_map_checked(i)?;
        let mut coin: Option<u32> = None;
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

/// An output belongs to us when its output-map BIP32_DERIVATION carries our
/// master fingerprint. Absent fingerprint or absent record → treated as foreign
/// (a payment), which is the conservative reading for a review screen.
fn map_carries_our_fingerprint(map: psbt::KvMap<'_>, ours: &[u8; 4]) -> bool {
    for kv in map.iter() {
        // OUTPUT map: BIP-174 assigns the output-side derivation a different
        // key byte (0x02) than the input side (0x06). Using the input constant
        // here silently matched nothing, so change outputs were reported as
        // payments forever (caught by change_output_is_labelled_…, 2026-11-05).
        if kv.key.first() == Some(&psbt::output_type::BIP32_DERIVATION)
            && kv.value.len() >= 4
            && kv.value[..4] == ours[..]
        {
            return true;
        }
    }
    false
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
    view.push_fmt(format_args!("chain {}", tx.chain_id))?;
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
