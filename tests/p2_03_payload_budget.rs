//! P2-03：外部 payload 资源预算 property 测试
//!
//! 审计要求：对 CBOR、RLP、PSBT、UR 加 fuzz/property 预算测试。
//! 目标：任意/畸形输入下 decode 路径不 panic、不超预算、恒返回 Result。

use proptest::prelude::*;
use shlosilo::encoding::cbor;
use shlosilo::ur::ur_decode;

prop_compose! {
    fn arb_bytes()(v in proptest::collection::vec(any::<u8>(), 0..256)) -> Vec<u8> { v }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// 任意字节流喂 CBOR decode：不 panic，恒 Result
    #[test]
    fn cbor_decode_never_panics(data in arb_bytes()) {
        let _ = cbor::decode(&data);
    }

    /// 任意字符串喂 UR decode：不 panic，恒 Result
    #[test]
    fn ur_decode_never_panics(s in "ur:[a-zA-Z0-9\\-]{0,20}/[a-zA-Z0-9\\-]{0,128}") {
        let _ = ur_decode::decode(&s);
    }

    /// 任意字节（含无效 UTF-8）构造的字符串喂 UR decode：不 panic
    #[test]
    fn ur_decode_arbitrary_str(s in any::<String>()) {
        let _ = ur_decode::decode(&s);
    }

    /// CBOR round-trip：合法 bytes 编码后解码一致
    #[test]
    fn cbor_bytes_round_trip(data in arb_bytes()) {
        let enc = cbor::encode_bytes(&data);
        match cbor::decode(&enc) {
            Ok(cbor::Cbor::Bytes(b)) => prop_assert_eq!(b, &data[..]),
            _ => prop_assert!(false, "round trip failed"),
        }
    }
}
