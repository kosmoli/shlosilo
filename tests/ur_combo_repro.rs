//! DIAGNOSTIC/REGRESSION: feed a recorded UR frame set through the real
//! decode FFI and report per-frame accept/progress, pinning which part shape
//! (systematic vs fountain combo) yields "no new information".
//!
//! Ignored by default: needs an external frames file. Run with:
//!   UR_FRAMES_TXT=/path/to/frames.txt cargo test --test ur_combo_repro -- --ignored --nocapture

use shlosilo::ffi::c_abi::r3::*;
use shlosilo::ffi::c_abi::shlosilo_ur_decode_ws_len;

#[test]
#[ignore = "needs UR_FRAMES_TXT (external recorded frame set)"]
fn combo_part_acceptance_repro() {
    let path = std::env::var("UR_FRAMES_TXT")
        .unwrap_or_else(|_| "/home/komo/works/xmr-stagenet-lab/artifacts/frames.txt".into());
    let text = std::fs::read_to_string(&path).expect("frames.txt");
    let frames: Vec<String> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect();
    assert!(frames.len() >= 12, "need combo parts in the mix");

    let ws_len = shlosilo_ur_decode_ws_len() as usize;
    let mut ws = vec![0u8; ws_len];
    let mut payload = vec![0u8; 8192];
    let mut accepted: u32 = 0;

    let dec = shlosilo_ur_decode_new(ws.as_mut_ptr(), ws_len as u32);
    assert!(!dec.is_null());

    for (i, f) in frames.iter().enumerate() {
        let c = std::ffi::CString::new(f.as_str()).unwrap();
        let rc = unsafe { shlosilo_ur_decode_feed(dec, c.as_ptr(), &mut accepted) };
        let prog = shlosilo_ur_decode_progress(dec);
        let complete = shlosilo_ur_decode_complete(dec);
        println!(
            "frame {i:2}: rc={rc} accepted={} progress={prog} complete={complete} head={}",
            accepted,
            &f[..f.len().min(34)]
        );
        if complete != 0 {
            let mut plen = 0u32;
            let prc = unsafe {
                shlosilo_ur_decode_payload(
                    dec,
                    payload.as_mut_ptr(),
                    payload.len() as u32,
                    &mut plen,
                )
            };
            println!("COMPLETE after frame {i}: payload rc={prc} len={plen}");
            break;
        }
    }
    println!(
        "final: progress={} complete={}",
        shlosilo_ur_decode_progress(dec),
        shlosilo_ur_decode_complete(dec)
    );
    unsafe { shlosilo_ur_decode_free(dec) };
}
