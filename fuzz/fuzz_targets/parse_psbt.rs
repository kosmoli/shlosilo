#![no_main]
// 审计 #5 开-04:PSBT parser fuzz——任意字节序列不得 panic/OOM
// (exact-consumption/重复键/预算在 unsafe 前校验的最终验证)
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 不关心结果,只关心不 panic/不 abort/不超预算分配
    let _ = shlosilo::chain::btc::psbt::parse_psbt(data);
});
