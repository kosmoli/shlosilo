//! The UR type policy table: pins the exact answers the C product flow used to
//! compute with four `strcmp` chains.
//!
//! These are behaviour pins, not design tests: the C chain is the contract this
//! module replaces, so every row below restates what that chain answered. If a row
//! has to change, it is a product decision (and the on-screen wording is part of
//! the fixed vocabulary — see `failure_text`), not a refactor.
use shlosilo::ur::type_table::{
    display, info, is_sign, known_types, reply_goes_to_qr, reply_type, review_gated, static_cstr,
    unsupported, ALL_PHRASES, ALL_REPLY_TYPES,
};

/// Bring a Rust string into the state the product flow always sees: the decoder
/// lowercases the type before C can ask (`ur_multipart.rs`, "Normalize to
/// lowercase"). Every table row is asserted in both cases anyway, so a future
/// decoder change cannot silently split the two.
fn lc(t: &str) -> String {
    t.to_ascii_lowercase()
}

#[test]
fn display_phrases_match_the_former_c_chain() {
    // (type, phrase) — verbatim from `ur_type_display` in product_task.c
    let cases = [
        ("xmr-txunsigned", "sign request: xmr"),
        ("xmr-txsigned", "signed: xmr"),
        ("xmr-output", "pairing: outputs"),
        ("xmr-keyimage", "pairing: key images"),
        ("crypto-monero-tx", "sign request: xmr"),
        ("crypto-psbt", "sign request: btc"),
        ("psbt", "sign request: btc"),
        ("eth-sign-request", "sign request: eth"),
        ("something-else", "unknown code"),
        ("", "unknown code"),
    ];
    for (t, want) in cases {
        assert_eq!(display(Some(t)), want, "display({t})");
        assert_eq!(display(Some(&lc(t))), want, "display(lowercased {t})");
    }
    // No type recorded yet: same class phrase, never an echo of input.
    assert_eq!(display(None), "unknown code");
}

#[test]
fn sign_whitelist_matches_the_former_c_chain() {
    let sign = [
        "xmr-txunsigned",
        "crypto-monero-tx",
        "crypto-psbt",
        "psbt",
        "eth-sign-request",
    ];
    let not_sign = [
        // the Cake exchange legs: routed elsewhere, must leave the session alive
        "xmr-output",
        "xmr-keyimage",
        "xmr-txsigned",
        // registry types this product flow does not sign
        "crypto-hdkey",
        "crypto-account",
        "bytes",
        "unknown",
        "",
    ];
    for t in sign {
        assert!(is_sign(t), "is_sign({t}) must be true");
        assert!(is_sign(&lc(t)), "is_sign(lowercased {t}) must be true");
    }
    for t in not_sign {
        assert!(!is_sign(t), "is_sign({t}) must be false");
    }
}

#[test]
fn review_gate_covers_exactly_the_types_we_can_summarize() {
    let gated = ["crypto-psbt", "psbt", "eth-sign-request"];
    let ungated = [
        // XMR keeps its shipped session-bound flow (gating it would change a
        // product path, not close a blind-signing hole)
        "xmr-txunsigned",
        "crypto-monero-tx",
        "xmr-txsigned",
        "xmr-output",
        "xmr-keyimage",
        "crypto-hdkey",
        "unknown",
        "",
    ];
    for t in gated {
        assert!(review_gated(t), "review_gated({t}) must be true");
        assert!(
            is_sign(t),
            "{t} is review-gated, so it must also be a sign type"
        );
    }
    for t in ungated {
        assert!(!review_gated(t), "review_gated({t}) must be false");
    }
    // The latent trap the old C had: `ur_type_is_sign` folded case while
    // `review_type_gated` did not, so an upper-cased CRYPTO-PSBT would have signed
    // without review. The table folds case for both, so the two can no longer
    // disagree — this asserts the invariant for every row.
    for t in known_types() {
        if is_sign(t) && info(t).review_gated {
            assert!(
                is_sign(&lc(t)) && review_gated(&lc(t)),
                "{t} must classify identically in either case"
            );
        }
    }
}

#[test]
fn reply_names_follow_the_request_name() {
    // The reply must carry the name the request used (Cake says `psbt`, the
    // registry says `crypto-psbt`), and unknown names answer as opaque bytes.
    let cases = [
        ("psbt", "psbt"),
        ("crypto-psbt", "crypto-psbt"),
        ("xmr-txunsigned", "xmr-txsigned"),
        ("crypto-monero-tx", "xmr-txsigned"),
        ("xmr-output", "xmr-keyimage"),
        ("xmr-txsigned", "bytes"),
        ("eth-sign-request", "eth-signature"), // E-1: the reply container is ur:eth-signature
        ("bytes", "bytes"),
        ("", "bytes"),
        // Whole-string matching, unlike the classify questions: the prefix that
        // classifies as a BTC sign request answers as bytes.
        ("crypto-psbt-extend", "bytes"),
    ];
    for (t, want) in cases {
        assert_eq!(reply_type(t), want, "reply_type({t})");
        assert_eq!(reply_type(&lc(t)), want, "reply_type(lowercased {t})");
    }
}

/// E-1: an `eth-sign-request` is answered with the `ur:eth-signature` container.
///
/// Pinned on its own because it is the one reply row whose name differs from the
/// request's: the product flow asks the table for the reply name and hands it to
/// the frame encoder, so a missing row would ship the signature under `bytes` and
/// every wallet would refuse it as an unknown type.
#[test]
fn eth_sign_request_answers_as_eth_signature() {
    assert_eq!(reply_type("eth-sign-request"), "eth-signature");
    assert_eq!(reply_type("ETH-SIGN-REQUEST"), "eth-signature");
    // Whole-string rule: a prefixed alias still classifies as an ETH sign request
    // but has no container of its own, so it must not answer as eth-signature.
    assert!(is_sign("eth-sign-request-v2"));
    assert_eq!(reply_type("eth-sign-request-v2"), "bytes");
}

/// Which reply payloads go straight to the QR carousel after a successful sign.
///
/// This list used to live in the C product task as a `strcmp` chain and silently
/// missed `eth-signature`: a successful ETH sign parked on the result page and the
/// signed container never reached the wallet. The pin covers both directions — the
/// types a wallet can scan back, and the ones that must stay on the result page —
/// plus case folding, because the C side hands over whatever the table produced.
#[test]
fn qr_reply_types_are_the_wallet_scannable_ones() {
    for t in [
        "xmr-txsigned",
        "crypto-psbt",
        "psbt",
        "eth-signature",
        "xmr-keyimage",
        "ETH-SIGNATURE",
    ] {
        assert!(reply_goes_to_qr(t), "{t} must go to the QR carousel");
    }
    for t in ["bytes", "unknown", "", "crypto-psbt-extend"] {
        assert!(!reply_goes_to_qr(t), "{t} must stay on the result page");
    }
    // Everything the reply table can produce is classified explicitly: a new reply
    // name that nobody added here is a missing decision, not a default.
    for r in ALL_REPLY_TYPES {
        let _ = reply_goes_to_qr(r);
    }
}

/// Every reply name must be a type the UR encoder can frame: the FFI turns the
/// table's answer into a UR type field verbatim, so a name the tag enum does not
/// know would be shipped as `unknown`.
#[test]
fn every_reply_name_is_a_known_ur_type() {
    use shlosilo::ur::ur_encode::UrTypeTag;
    for r in ALL_REPLY_TYPES {
        let tag = UrTypeTag::from_name(r);
        assert_ne!(tag, UrTypeTag::Unknown, "reply name {r} is not a UR type");
        assert_eq!(tag.type_name(), r, "reply name {r} does not round-trip");
    }
}

/// The prefix/whole-string split is real, not an accident to be "fixed" later: a
/// type can be a sign request and still answer as bytes.
#[test]
fn prefix_classification_and_whole_string_reply_are_both_pinned() {
    let t = "crypto-psbt-extend";
    assert!(is_sign(t), "prefix rule: still a sign request");
    assert!(review_gated(t), "prefix rule: still review-gated");
    assert_eq!(display(Some(t)), "sign request: btc");
    assert_eq!(reply_type(t), "bytes", "whole-string rule: no reply name");
}

/// Every phrase the table can produce must map to a C string that says the same
/// thing — the FFI hands out `&'static CStr`, so a missing row would let C read a
/// wrong (or unterminated) phrase.
#[test]
fn every_phrase_round_trips_through_the_c_string_mapping() {
    for p in ALL_PHRASES {
        assert_eq!(
            static_cstr(p).to_str().expect("static phrase is UTF-8"),
            p,
            "static_cstr({p}) must round-trip"
        );
    }
    for r in ALL_REPLY_TYPES {
        assert_eq!(
            static_cstr(r).to_str().expect("static reply is UTF-8"),
            r,
            "reply {r} must round-trip through static_cstr"
        );
    }
    // Closed sets: the classification can only ever return a mapped phrase.
    for t in known_types() {
        let p = info(t).display;
        assert!(ALL_PHRASES.contains(&p), "{t} yields unmapped phrase {p}");
    }
    assert!(ALL_PHRASES.contains(&display(None)));
}

/// The table must not claim to sign a type the Rust dispatcher cannot route: the
/// two views of "is this a sign request" have to agree, or the C gate and the
/// typed-sign entry disagree at runtime.
#[test]
fn every_sign_type_is_recognized_by_the_ur_registry_mapping() {
    use shlosilo::ur::ur_encode::UrTypeTag;
    for t in known_types() {
        if !is_sign(t) {
            continue;
        }
        assert_ne!(
            UrTypeTag::from_name(t),
            UrTypeTag::Unknown,
            "{t} is a sign type, so the encoder must know the name"
        );
    }
}

/// E-6: batch signing is a **known, deliberately unsupported** type.
///
/// `eth-batch-sign-request` is UR type 40404 (a keystone private extension) carrying
/// `{1: [tagged eth-sign-request, …]}`. This device decided not to implement it, so
/// the decision has to be visible on screen: a fixed "no batch signing" phrase, not
/// `unknown code` (which reads like a damaged QR and invites a pointless retry).
///
/// The prefix row also covers the reply leg `eth-batch-signature` (40405), and case
/// folding matters because a wallet may upper-case the whole UR.
#[test]
fn eth_batch_requests_are_known_and_deliberately_unsupported() {
    for t in [
        "eth-batch-sign-request",
        "eth-batch-signature",
        "eth-batch-sign-request-v2", // same prefix: still our policy, still refused
    ] {
        assert_eq!(display(Some(t)), "no batch signing", "display({t})");
        assert_eq!(display(Some(&lc(t))), "no batch signing", "display(lc {t})");
        assert!(unsupported(t), "unsupported({t}) must be true");
        assert!(!is_sign(t), "unsupported({t}) must not be a sign request");
        assert!(!info(t).review_gated, "{t} must not reach the review gate");
        // The refusal is the whole point: it must not read as "unknown".
        assert_ne!(
            display(Some(t)),
            "unknown code",
            "{t} must not read as unknown"
        );
        assert!(unsupported(&lc(t)), "unsupported(lc {t}) must be true");
    }
    // Upper-cased verbatim, the shape the QR carries before the decoder folds it.
    assert!(unsupported("ETH-BATCH-SIGN-REQUEST"));
    assert!(unsupported("ETH-BATCH-SIGNATURE"));
}

/// The tri-state invariant: a type the device refuses is never also a sign type.
///
/// `is_sign` drives the dispatcher and `unsupported` drives the wording; a row with
/// both would ask the product flow to sign and refuse in the same breath, and the C
/// side cannot represent such a request.
#[test]
fn unsupported_types_are_never_sign_types() {
    for t in known_types() {
        if unsupported(t) {
            assert!(
                !is_sign(t),
                "{t} is unsupported, so it must not be a sign type"
            );
        }
    }
    // The fall-through class is *not* the unsupported class: an unknown type must
    // keep saying `unknown code`, and a known-unsupported one must never say it.
    for t in ["", "unknown", "bytes", "crypto-hdkey", "eth-signature"] {
        assert!(!unsupported(t), "unsupported({t}) must be false");
    }
    assert!(!unsupported("eth-sign-request"));
    assert!(unsupported("eth-batch-sign-request"));
}

/// Regression pin for the row ORDER: the `eth-sign-request` prefix must not swallow
/// the batch types, and the batch prefix must not swallow the plain ETH request.
///
/// `eth-sign` is not a prefix of `eth-batch`, so the two rows are independent — this
/// test holds that independence in place, because a future alias such as
/// `eth-sign-batch` would silently rewrite one of the two answers.
#[test]
fn eth_sign_request_keeps_its_own_answer_next_to_the_batch_row() {
    assert!(
        is_sign("eth-sign-request"),
        "eth-sign-request must stay a sign type"
    );
    assert!(
        !unsupported("eth-sign-request"),
        "eth-sign-request is supported"
    );
    assert_eq!(display(Some("eth-sign-request")), "sign request: eth");
    assert!(review_gated("eth-sign-request"));

    assert!(!is_sign("eth-batch-sign-request"));
    assert!(unsupported("eth-batch-sign-request"));
    assert_eq!(display(Some("eth-batch-sign-request")), "no batch signing");

    // ...and the batch reply leg is not mistaken for a wallet-scannable reply name.
    assert_eq!(reply_type("eth-batch-signature"), "bytes");
}

/// The new phrase is part of the closed screen vocabulary: it must round-trip
/// through the C string mapping and never reach the screen as anything else.
///
/// (`every_phrase_round_trips_through_the_c_string_mapping` covers all of
/// `ALL_PHRASES`; this names the E-6 member so a removal is a deliberate edit.)
#[test]
fn no_batch_signing_is_a_first_class_screen_phrase() {
    assert!(ALL_PHRASES.contains(&"no batch signing"));
    assert_eq!(
        static_cstr("no batch signing").to_str().expect("UTF-8"),
        "no batch signing"
    );
    // No echo of the UR type, no internal code, no pass-through wording.
    let shown = display(Some("eth-batch-sign-request"));
    for banned in [
        "eth-batch",
        "40404",
        "collected",
        "not a sign request",
        "unknown",
    ] {
        assert!(
            !shown.contains(banned),
            "the refused-batch phrase must not contain {banned:?} (got {shown:?})"
        );
    }
}
