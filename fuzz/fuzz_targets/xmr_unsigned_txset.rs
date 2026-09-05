#![no_main]
// 审计 #12 P2-03:XMR unsigned-txset parser fuzz——任意字节序列不得
// panic/OOM。入口总预算 + read_count 物理可行性 + checked 读取的
// 最终验证(与 PSBT fuzz 同一验收口径)。
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 不关心结果,只关心不 panic/不 abort/不超预算分配
    let _ = shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx(data);
});
