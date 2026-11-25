//! UR type classification — the device's whole "what is this type?" policy.
//!
//! Five questions the product flow asks about an inbound UR type — *is it a sign
//! request*, *does it go through the operator review gate*, *is it a type we know
//! and deliberately do not support*, *which fixed phrase do we show*, and *which
//! name do we answer under* — used to live as ad-hoc `strcmp` chains in C
//! (`flux/forgebox/src/tasks/product_task.c`), reachable only by grepping that
//! file. They are pure string classification, so they live here: one table, one
//! match, host-testable, and adding a type alias (B-6 did exactly that) is a
//! one-line edit instead of four.
//!
//! **Screen vocabulary**: `display` values are the fixed phrases, never an echo of
//! the input — an unknown type says `unknown code`, not the bytes the sender chose
//! (2026-10-10 red line).
//!
//! **Faithfulness to the C it replaces**, including two asymmetries that are
//! deliberate here because tests pin them:
//! - the classify questions match **prefixes** (`crypto-psbt-extend` classifies as
//!   a BTC sign request), while the reply-name question matches the **whole**
//!   string (that same type answers as `bytes`);
//! - `xmr-*` exchange legs are *not* sign requests: they are pairing legs the
//!   product flow routes elsewhere, and a stray one must leave the session alive.
//!
//! **Case folding**: `UrMultipartDecoder` lowercases the type before the product
//! flow sees it (`ur_multipart.rs`, "Normalize to lowercase"), so matching
//! case-insensitively here cannot change any reachable behaviour. It does remove a
//! latent trap: C matched `review_type_gated` case-SENSITIVELY while
//! `ur_type_is_sign` folded case, so an upper-cased `CRYPTO-PSBT` would have
//! passed the whitelist and skipped the review gate.
//!
//! Pure, zero-alloc: no allocation, no I/O, no panics (checked by the no-panic
//! gate) — the whole module is table lookups over byte slices.

/// What the product flow needs to know about one UR type.
///
/// Three states, and they are not interchangeable on screen (E-6):
/// - [`TypeInfo::is_sign`] — a sign request: it reaches the sign dispatcher.
/// - neither `is_sign` nor [`TypeInfo::unsupported`] — **pass-through**: a leg the
///   product flow routes elsewhere (the Cake pairing legs `xmr-keyimage` /
///   `xmr-output`, a peer's `xmr-txsigned`). The device prompts and keeps
///   scanning, and the session must survive it.
/// - [`TypeInfo::unsupported`] — **known, and deliberately not supported here**.
///   The device must say so in a fixed phrase and keep scanning; it must not fall
///   through to `unknown code` (which reads as a broken QR) and it must not use the
///   pass-through wording (`collected: …` / `not a sign request`), because the
///   reason is our policy, not the sender's framing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TypeInfo {
    /// Fixed on-screen phrase (screen vocabulary; never echoes the input).
    pub display: &'static str,
    /// Reaches the sign dispatcher. Everything else is prompt + keep scanning:
    /// the typed sign entry refuses foreign types, and a sign FAIL leg closes the
    /// plate session underneath, so a stray exchange-leg QR must not be sign-gated.
    pub is_sign: bool,
    /// Goes through the operator review gate before signing (fail-closed: if the
    /// summary cannot be built, the request is not signed).
    pub review_gated: bool,
    /// Known, and **deliberately not supported by this device**.
    ///
    /// Distinct from an unknown type: the operator sees "not supported" (a retry
    /// will not help, the request itself is understood) instead of `unknown code`
    /// (which reads like a damaged QR).
    ///
    /// Invariant: `unsupported == true` implies `is_sign == false`. A type this
    /// device refuses never reaches the sign dispatcher, so a row claiming both
    /// would be a contradiction the product flow could not act on (pinned in
    /// `tests/ur_type_table.rs`).
    pub unsupported: bool,
}

/// The fall-through classification: unknown types are shown as a fixed phrase,
/// never signed, never review-gated (there is nothing to summarize), and not
/// mistaken for a type we know and refuse.
pub const UNKNOWN: TypeInfo = TypeInfo {
    display: "unknown code",
    is_sign: false,
    review_gated: false,
    unsupported: false,
};

/// One table row. `exact` selects whole-string matching (the registry's short
/// Cake-family name `psbt`) over the prefix matching the aliases use.
struct Rule {
    name: &'static str,
    exact: bool,
    info: TypeInfo,
}

/// The table. Order matters only for genuinely overlapping prefixes; the rows
/// mirror the C chain's order so a future reader can diff them.
const RULES: [Rule; 9] = [
    Rule {
        name: "xmr-txunsigned",
        exact: false,
        info: TypeInfo {
            display: "sign request: xmr",
            is_sign: true,
            review_gated: false, // XMR keeps its shipped session-bound flow
            unsupported: false,
        },
    },
    Rule {
        name: "crypto-monero-tx",
        exact: false,
        info: TypeInfo {
            display: "sign request: xmr",
            is_sign: true,
            review_gated: false,
            unsupported: false,
        },
    },
    Rule {
        name: "crypto-psbt",
        exact: false,
        info: TypeInfo {
            display: "sign request: btc",
            is_sign: true,
            review_gated: true,
            unsupported: false,
        },
    },
    Rule {
        name: "psbt",
        exact: true,
        info: TypeInfo {
            display: "sign request: btc",
            is_sign: true,
            review_gated: true,
            unsupported: false,
        },
    },
    Rule {
        name: "eth-sign-request",
        exact: false,
        info: TypeInfo {
            display: "sign request: eth",
            is_sign: true,
            review_gated: true,
            unsupported: false,
        },
    },
    // E-6: batch signing is a keystone private extension (`eth-batch-sign-request`,
    // UR type 40404, payload `{1: [tagged eth-sign-request, …]}`) that this device
    // decided **not** to implement — not now, and not by accident. Listing it makes
    // the refusal a decision instead of a gap: before this row the type fell through
    // to `unknown code`, which tells the operator the QR is damaged rather than that
    // the request is understood and declined.
    //
    // Placed after `eth-sign-request` because that row is a prefix: `eth-sign` is not
    // a prefix of `eth-batch`, so the order is safe either way, but keeping the two
    // ETH rows adjacent makes the split visible. Prefix (`not exact`) so it also
    // covers the reply leg `eth-batch-signature` (40405).
    Rule {
        name: "eth-batch", // prefix: covers eth-batch-sign-request(40404) and eth-batch-signature(40405)
        exact: false,
        info: TypeInfo {
            display: "no batch signing",
            is_sign: false,
            review_gated: false,
            unsupported: true,
        },
    },
    Rule {
        name: "xmr-txsigned",
        exact: false,
        info: TypeInfo {
            display: "signed: xmr",
            is_sign: false,
            review_gated: false,
            unsupported: false,
        },
    },
    Rule {
        name: "xmr-output",
        exact: false,
        info: TypeInfo {
            display: "pairing: outputs",
            is_sign: false,
            review_gated: false,
            unsupported: false,
        },
    },
    Rule {
        name: "xmr-keyimage",
        exact: false,
        info: TypeInfo {
            display: "pairing: key images",
            is_sign: false,
            review_gated: false,
            unsupported: false,
        },
    },
];

/// ASCII case-insensitive prefix test over bytes (no allocation, no slicing that
/// can panic: the loop is bounded by `needle.len() <= hay.len()`).
fn starts_with_folded(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    let mut i = 0usize;
    while i < needle.len() {
        if !hay[i].eq_ignore_ascii_case(&needle[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Whole-string ASCII case-insensitive equality.
fn eq_folded(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && starts_with_folded(a, b)
}

/// Classify an inbound UR type.
pub fn info(type_name: &str) -> TypeInfo {
    let hay = type_name.as_bytes();
    let mut i = 0usize;
    while i < RULES.len() {
        let rule = &RULES[i];
        let hit = if rule.exact {
            eq_folded(hay, rule.name.as_bytes())
        } else {
            starts_with_folded(hay, rule.name.as_bytes())
        };
        if hit {
            return rule.info;
        }
        i += 1;
    }
    UNKNOWN
}

/// The fixed on-screen phrase for `type_name` (`None` = no type recorded yet).
pub fn display(type_name: Option<&str>) -> &'static str {
    match type_name {
        Some(t) => info(t).display,
        None => UNKNOWN.display,
    }
}

/// Does this type reach the sign dispatcher?
pub fn is_sign(type_name: &str) -> bool {
    info(type_name).is_sign
}

/// Does this type go through the operator review gate?
pub fn review_gated(type_name: &str) -> bool {
    info(type_name).review_gated
}

/// Is this a type we recognize and deliberately do not support?
///
/// The product flow still prompts and keeps scanning (the operator can scan the
/// next QR), but the wording says *not supported* rather than `unknown code`:
/// the request is understood, so no amount of re-scanning helps (E-6).
pub fn unsupported(type_name: &str) -> bool {
    info(type_name).unsupported
}

/// The UR type the device answers under, given the inbound type.
///
/// Whole-string matching, unlike the classify questions: the reply must carry the
/// name the request used (`psbt` in → `psbt` out for the Cake family, `crypto-psbt`
/// in → `crypto-psbt` out for the registry name), and anything else — including a
/// prefix the classify questions accept — answers as opaque `bytes`.
///
/// `eth-sign-request` is the one row that changes name: the reply is a different
/// container (`ur:eth-signature`, E-1), not a transformation of the request.
pub fn reply_type(inbound: &str) -> &'static str {
    let hay = inbound.as_bytes();
    if eq_folded(hay, b"xmr-output") {
        return "xmr-keyimage";
    }
    if eq_folded(hay, b"xmr-txunsigned") || eq_folded(hay, b"crypto-monero-tx") {
        return "xmr-txsigned";
    }
    if eq_folded(hay, b"eth-sign-request") {
        return "eth-signature";
    }
    if eq_folded(hay, b"psbt") {
        return "psbt";
    }
    if eq_folded(hay, b"crypto-psbt") {
        return "crypto-psbt";
    }
    "bytes"
}

/// Whether a **reply** type's payload goes straight to the QR carousel after a
/// successful sign, instead of parking on the result page.
///
/// This used to be a three-way `strcmp` chain in the C product task
/// (`product_task.c`: `xmr-txsigned` / `crypto-psbt` / `psbt`), which is exactly the
/// drift that made the ETH exit unreachable: the reply name became
/// `eth-signature` and the hardcoded list never learned about it, so a successful
/// ETH sign stopped at the result page and the artifact never reached a wallet. The
/// rule now lives next to [`reply_type`], and a new reply type is one row here.
///
/// `bytes` is deliberately **not** in the set: an opaque payload is not something a
/// wallet can consume, so it stays on the result page where the diagnostics are.
pub fn reply_goes_to_qr(reply: &str) -> bool {
    let hay = reply.as_bytes();
    eq_folded(hay, b"xmr-txsigned")
        || eq_folded(hay, b"crypto-psbt")
        || eq_folded(hay, b"psbt")
        || eq_folded(hay, b"eth-signature")
        // `xmr-keyimage` is a wallet-scannable reply too; today it is produced by the
        // pairing leg, which has its own QR path, so listing it changes nothing — it
        // just keeps the set complete rather than leaving a future caller to discover
        // the omission the way the ETH exit did.
        || eq_folded(hay, b"xmr-keyimage")
}

/// Any `'static` string this module can hand to C, as a NUL-terminated C string.
///
/// A `&str` pointer is not a C string (Rust literals carry no terminator), so the
/// FFI hands out this form. The mapping covers **both** closed sets the module
/// produces — display phrases *and* reply names — and one test asserts every member
/// of each round-trips, so a missing row cannot slip through as a wrong phrase.
pub fn static_cstr(s: &'static str) -> &'static core::ffi::CStr {
    match s {
        // display phrases
        "unknown code" => c"unknown code",
        "sign request: xmr" => c"sign request: xmr",
        "sign request: btc" => c"sign request: btc",
        "sign request: eth" => c"sign request: eth",
        "signed: xmr" => c"signed: xmr",
        "pairing: outputs" => c"pairing: outputs",
        "pairing: key images" => c"pairing: key images",
        "no batch signing" => c"no batch signing",
        // reply names
        "xmr-keyimage" => c"xmr-keyimage",
        "xmr-txsigned" => c"xmr-txsigned",
        "eth-signature" => c"eth-signature",
        "psbt" => c"psbt",
        "crypto-psbt" => c"crypto-psbt",
        "bytes" => c"bytes",
        // Unreachable: the two sets above are closed and the test enforces it.
        // Falling back to the class phrase keeps this total without a panic.
        _ => c"unknown code",
    }
}

/// Every phrase this module can produce (the closed set `phrase_cstr` maps).
pub const ALL_PHRASES: [&str; 8] = [
    "unknown code",
    "sign request: xmr",
    "sign request: btc",
    "sign request: eth",
    "signed: xmr",
    "pairing: outputs",
    "pairing: key images",
    "no batch signing",
];

/// Every reply name this module can produce.
pub const ALL_REPLY_TYPES: [&str; 6] = [
    "xmr-keyimage",
    "xmr-txsigned",
    "eth-signature",
    "psbt",
    "crypto-psbt",
    "bytes",
];

/// The table's rows, for tests and for the header/host parity checks.
pub fn known_types() -> [&'static str; 9] {
    let mut out = [""; 9];
    let mut i = 0usize;
    while i < RULES.len() {
        out[i] = RULES[i].name;
        i += 1;
    }
    out
}
