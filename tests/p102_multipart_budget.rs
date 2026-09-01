//! P1-02 整改落地测试（2026-09-01 审计 #4）——multipart decoder 资源预算
//!
//! 审计指控：
//! - wire message_length 直接 as usize，decoder 侧无 MULTIPART_PAYLOAD_MAX_LEN 检查
//! - u64 → usize/u32 静默窄化（32-bit Thumb 危险）
//! - fragment/count/message 缺一致性验证
//!
//! 覆盖：decoder 侧预算常量锁定 + 合法路径冒烟 + FFI 出口预算。
//! part_from_cbor 的逐项校验（wire_len fallible / message_length 预算 /
//! fragment-count-message 一致性）在 ur_multipart::tests 单元层覆盖。

use shlosilo::ur::ur_multipart::{UrMultipartDecoder, MULTIPART_PAYLOAD_MAX_LEN};

/// 合法多分片 roundtrip 冒烟（预算收紧不破坏合法路径）
#[test]
fn p102_valid_multipart_roundtrip() {
    let payload: std::vec::Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let mut enc =
        shlosilo::ur::ur_multipart::UrMultipartEncoder::new("bytes", &payload, 200).unwrap();
    let mut dec = UrMultipartDecoder::new();
    let n = enc.fragment_count();
    for _ in 0..n {
        let frame = enc.next_frame().unwrap();
        assert!(dec.receive_frame(frame.as_str()).unwrap());
    }
    assert!(dec.complete());
    let out = dec.payload().unwrap().unwrap();
    assert_eq!(out, payload);
}

/// budget 常量声明不变（锁定审计对齐：16 KiB payload / 40 KiB frame）
#[test]
fn p102_budget_constants() {
    assert_eq!(MULTIPART_PAYLOAD_MAX_LEN, 16384);
    assert_eq!(shlosilo::ur::ur_multipart::MULTIPART_FRAME_MAX_LEN, 40960);
}

/// encoder 拒绝超预算 payload（既有行为的回归锁定）
#[test]
fn p102_encoder_over_budget_rejected() {
    let big = std::vec![0u8; MULTIPART_PAYLOAD_MAX_LEN + 1];
    let r = shlosilo::ur::ur_multipart::UrMultipartEncoder::new("bytes", &big, 200);
    assert!(r.is_err(), "encoder payload > 16 KiB must be rejected");
}

/// FFI typed sign payload 预算（decoder 侧同一预算的 FFI 出口）
#[test]
fn p102_typed_sign_over_budget_rejected() {
    use shlosilo::ffi::c_abi::r3::shlosilo_sign_typed_ffi;
    let big = std::vec![0u8; MULTIPART_PAYLOAD_MAX_LEN + 1];
    let idx: [u16; 12] = [0; 12];
    let mut out = [0u8; 64];
    let mut actual: u32 = 0;
    let tname = c"crypto-psbt";
    let rc = shlosilo_sign_typed_ffi(
        tname.as_ptr(),
        big.as_ptr(),
        big.len() as u32,
        idx.as_ptr(),
        12,
        core::ptr::null(),
        0,
        0,
        core::ptr::null(),
        0,
        out.as_mut_ptr(),
        out.len() as u32,
        &mut actual,
    );
    assert_ne!(rc, 0, "typed sign payload > budget must be rejected");
}
