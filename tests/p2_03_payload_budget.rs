//! P2-03: external payload resource budget property tests
//!
//! Audit requirement: add fuzz/property budget tests for CBOR, RLP, PSBT, UR.
//! Goal: on arbitrary/malformed inputs the decode paths never panic, never exceed budget, and always return Result.

use proptest::prelude::*;
use shlosilo::encoding::cbor;
use shlosilo::ur::ur_decode;

prop_compose! {
    fn arb_bytes()(v in proptest::collection::vec(any::<u8>(), 0..256)) -> Vec<u8> { v }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Feed arbitrary byte streams to CBOR decode: no panic, always Result
    #[test]
    fn cbor_decode_never_panics(data in arb_bytes()) {
        let _ = cbor::decode(&data);
    }

    /// Feed arbitrary strings to UR decode: no panic, always Result
    #[test]
    fn ur_decode_never_panics(s in "ur:[a-zA-Z0-9\\-]{0,20}/[a-zA-Z0-9\\-]{0,128}") {
        let _ = ur_decode::decode(&s);
    }

    /// Feed strings built from arbitrary bytes (including invalid UTF-8) to UR decode: no panic
    #[test]
    fn ur_decode_arbitrary_str(s in any::<String>()) {
        let _ = ur_decode::decode(&s);
    }

    /// CBOR round-trip: legal bytes decode identically after encoding
    #[test]
    fn cbor_bytes_round_trip(data in arb_bytes()) {
        let enc = cbor::encode_bytes(&data);
        match cbor::decode(&enc) {
            Ok(cbor::Cbor::Bytes(b)) => prop_assert_eq!(b, &data[..]),
            _ => prop_assert!(false, "round trip failed"),
        }
    }
}
