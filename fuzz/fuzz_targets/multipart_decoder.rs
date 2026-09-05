#![no_main]
// Audit #5 open-04: multipart decoder fuzz — any frame sequence must not panic/hang/exceed budget
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut dec = shlosilo::ur::ur_multipart::UrMultipartDecoder::new();
    // Split on \n into a pseudo frame sequence, feed frame by frame
    for chunk in data.split(|&b| b == b'\n') {
        if chunk.is_empty() {
            continue;
        }
        // Best-effort conversion into a valid frame string shape — invalid input must still be stably rejected
        let s = String::from_utf8_lossy(chunk);
        let _ = dec.receive_frame(&s);
        if dec.complete() {
            let _ = dec.payload();
            break;
        }
    }
});
