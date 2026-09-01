#![no_main]
// 审计 #5 开-04:multipart decoder fuzz——任意帧序列不得 panic/挂起/超预算
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut dec = shlosilo::ur::ur_multipart::UrMultipartDecoder::new();
    // 按 \n 分割成伪帧序列,逐帧喂
    for chunk in data.split(|&b| b == b'\n') {
        if chunk.is_empty() {
            continue;
        }
        // 尽力转成合法 frame 字符串形态——非法输入也要稳定拒绝
        let s = String::from_utf8_lossy(chunk);
        let _ = dec.receive_frame(&s);
        if dec.complete() {
            let _ = dec.payload();
            break;
        }
    }
});
