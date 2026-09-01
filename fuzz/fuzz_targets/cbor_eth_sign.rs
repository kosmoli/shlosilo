#![no_main]
// 审计 #5 开-04:CBOR codec fuzz——任意字节不得 panic(eth-sign-request 里的
// keypath 解析、bytes/array 深度嵌套等)
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // CBOR 解码
    if let Ok(cbor) = shlosilo::encoding::cbor::decode(data) {
        // 解码成功 → 也压一遍 eth-sign-request 形状解析(递归 tag/map 路径)
        let _ = shlosilo::ur::codec::eth_sign_request::parse_eth_sign_request(data);
        let _ = format!("{:?}", cbor); // Debug 链
    }
});
