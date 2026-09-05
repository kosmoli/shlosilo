#![no_main]
// Audit #5 open-04: CBOR codec fuzz — arbitrary bytes must not panic (the keypath parsing
// in eth-sign-request, deeply nested bytes/arrays, etc.)
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // CBOR decode
    if let Ok(cbor) = shlosilo::encoding::cbor::decode(data) {
        // Decoded OK → also run the eth-sign-request shape parsing once (recursive tag/map paths)
        let _ = shlosilo::ur::codec::eth_sign_request::parse_eth_sign_request(data);
        let _ = format!("{:?}", cbor); // Debug chain
    }
});
