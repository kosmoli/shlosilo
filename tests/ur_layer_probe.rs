//! UR-layer decisive probe (2026-10-11): put the UR layer back into the
//! xmr-output pairing chain and locate where -21 drops in.
//!
//! Diagnostic harness (NOT a regression test). Run:
//!   `cargo test --offline --test ur_layer_probe -- --nocapture`
//! Input (env `WATCHONLY_PROBE_DIR`, default
//! `/home/komo/works/xmr-stagenet-lab/watchonly_probe`):
//!   full_outputs_all.bin — real wallet2 `export_outputs` container (241 B)
//!   keys.hex             — "<spend_sk hex> <view_sk hex>" (same wallet)
//!
//! Layer walk:
//!   raw container
//!   -> (a) single-frame ur:xmr-output/<bytewords>  via shlosilo_ur_decode_uri_ffi
//!   -> (b) multipart 2-fragment animation frames   via shlosilo_ur_decode_feed/payload
//!   -> byte-compare every payload against the raw container
//!   -> pairing (business::xmr_pairing::process_output_export + the product
//!      FFI face shlosilo_xmr_pairing_ffi) on each payload
//!   -> failure-mode bisect probes (multipart-into-single-frame exit,
//!      CBOR byte-string wrapping, oversize single-frame) to see which layer
//!      produces the device's exact -21.

use rand_chacha::rand_core::SeedableRng as _;
use shlosilo::business::xmr_pairing::{carve_pairing_ws, pairing_ws_len, process_output_export};
use shlosilo::chain::xmr::key_image_export::{
    decrypt_export_payload, KEY_IMAGE_EXPORT_MAGIC, OUTPUT_EXPORT_MAGIC,
};
use shlosilo::encoding::bytewords;
use shlosilo::ffi::c_abi::r3::{
    shlosilo_ur_decode_complete, shlosilo_ur_decode_feed, shlosilo_ur_decode_free,
    shlosilo_ur_decode_new, shlosilo_ur_decode_payload, shlosilo_ur_decode_type,
    shlosilo_ur_decode_uri_ffi,
};
use shlosilo::ffi::error_code::to_ffi_code;
use shlosilo::ur::ur_multipart::UrMultipartEncoder;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn head32(label: &str, bytes: &[u8]) {
    let n = 32.min(bytes.len());
    println!(
        "    {label}: len={} head32={}",
        bytes.len(),
        hex(&bytes[..n])
    );
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    for i in 0..32 {
        a[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    a
}

/// First differing byte index (None = identical).
fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    let n = a.len().min(b.len());
    for i in 0..n {
        if a[i] != b[i] {
            return Some(i);
        }
    }
    if a.len() != b.len() {
        Some(n)
    } else {
        None
    }
}

/// (a) single-frame URI through the product FFI exit
/// `shlosilo_ur_decode_uri_ffi` — returns (rc, type_name, payload).
fn ffi_decode_single(uri: &str) -> (i32, String, Vec<u8>) {
    let c: Vec<u8> = uri.bytes().chain(core::iter::once(0)).collect();
    let mut type_buf = [0u8; 32];
    let mut payload = vec![0u8; 16384];
    let mut actual: core::ffi::c_uint = 0;
    let rc = shlosilo_ur_decode_uri_ffi(
        c.as_ptr() as *const core::ffi::c_char,
        type_buf.as_mut_ptr(),
        type_buf.len() as core::ffi::c_uint,
        payload.as_mut_ptr(),
        payload.len() as core::ffi::c_uint,
        &mut actual,
    );
    let t = String::from_utf8_lossy(&type_buf)
        .trim_end_matches('\0')
        .to_string();
    payload.truncate(actual as usize);
    (rc, t, payload)
}

/// (b) multipart frames through the product FFI exits used by the C scan flow
/// (`shlosilo_ur_decode_new/feed/complete/type/payload`) — returns
/// (rc_payload, type_name, payload).
fn ffi_decode_multipart(frames: &[String]) -> (i32, String, Vec<u8>) {
    use shlosilo::ur::ur_multipart::ur_decode_ws_len;
    let ws_len = ur_decode_ws_len();
    let mut ws = vec![0u8; ws_len];
    let dec = shlosilo_ur_decode_new(ws.as_mut_ptr(), ws_len as core::ffi::c_uint);
    assert!(!dec.is_null(), "decoder placement");
    for f in frames {
        let c: Vec<u8> = f.bytes().chain(core::iter::once(0)).collect();
        let mut accepted: core::ffi::c_uint = 0;
        let rc =
            shlosilo_ur_decode_feed(dec, c.as_ptr() as *const core::ffi::c_char, &mut accepted);
        assert_eq!(rc, 0, "frame rejected: {f}");
        let _ = accepted;
    }
    assert_eq!(shlosilo_ur_decode_complete(dec), 1, "frames incomplete");
    let mut type_buf = [0u8; 32];
    let mut tlen: core::ffi::c_uint = 0;
    let rct = shlosilo_ur_decode_type(dec, type_buf.as_mut_ptr(), 32, &mut tlen);
    let t = String::from_utf8_lossy(&type_buf)
        .trim_end_matches('\0')
        .to_string();
    let mut payload = vec![0u8; 16384];
    let mut actual: core::ffi::c_uint = 0;
    let rc = shlosilo_ur_decode_payload(
        dec,
        payload.as_mut_ptr(),
        payload.len() as core::ffi::c_uint,
        &mut actual,
    );
    payload.truncate(actual as usize);
    shlosilo_ur_decode_free(dec);
    let _ = rct;
    (rc, t, payload)
}

/// Pairing on a payload with the real wallet keys: returns (label, ok, detail).
fn pairing_with_real_keys(
    label: &str,
    payload: &[u8],
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
) -> bool {
    let mut ws_raw = vec![0u8; pairing_ws_len()];
    let mut ws = carve_pairing_ws(&mut ws_raw).unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
    let mut out = vec![0u8; 8192];
    match process_output_export(view_sk, spend_sk, payload, &mut ws, &mut out, &mut rng) {
        Ok(o) => {
            let wire = &out[..o.written];
            // readback: the response container must decrypt under view_sk
            match decrypt_export_payload(wire, KEY_IMAGE_EXPORT_MAGIC, view_sk) {
                Ok((_, _, plain)) => {
                    println!(
                        "    pairing[{label}]: rc=0 written={} outputs={} readback OK",
                        o.written, o.output_count
                    );
                    head32("keyimage wire", wire);
                    head32("keyimage plain", &plain);
                    true
                }
                Err(e) => {
                    println!(
                        "    pairing[{label}]: wrote {} but readback ERR {:?}",
                        o.written, e
                    );
                    false
                }
            }
        }
        Err(e) => {
            println!(
                "    pairing[{label}]: ERR {:?} -> ffi {} <-- the device would show rc {}",
                e,
                to_ffi_code(&e),
                to_ffi_code(&e)
            );
            false
        }
    }
}

/// Ground truth on the framing convention: decode the REAL captured Cake
/// `xmr-txunsigned` animation frames (the leg known to work end-to-end on
/// device) and inspect the reassembled message head. Raw blob (magic at
/// offset 0) vs CBOR byte-string head decides whether Cake wraps UR
/// messages in CBOR — and therefore whether the xmr-output leg's payload
/// arrives wrapped (P2 failure mode) or bare.
#[test]
fn real_cake_frames_message_framing() {
    let path = std::env::var("CAKE_FRAMES")
        .unwrap_or_else(|_| "/home/komo/works/xmr-stagenet-lab/artifacts/frames.txt".into());
    let Ok(text) = std::fs::read_to_string(&path) else {
        println!("(no captured Cake frames at {path} — skipped)");
        return;
    };
    let frames: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ur:"))
        .map(String::from)
        .collect();
    println!("==== REAL CAKE FRAMES: {} captured", frames.len());
    println!(
        "    frame[0] head: {}",
        &frames[0][..40.min(frames[0].len())]
    );
    let mut ws = vec![0u8; shlosilo::ur::ur_multipart::ur_decode_ws_len()];
    let dec = shlosilo_ur_decode_new(ws.as_mut_ptr(), ws.len() as core::ffi::c_uint);
    let mut rejected = 0usize;
    for f in &frames {
        let c: Vec<u8> = f.bytes().chain(core::iter::once(0)).collect();
        let mut accepted: core::ffi::c_uint = 0;
        if shlosilo_ur_decode_feed(dec, c.as_ptr() as *const core::ffi::c_char, &mut accepted) != 0
        {
            rejected += 1;
        }
    }
    println!(
        "    feed: rejected={rejected} complete={}",
        shlosilo_ur_decode_complete(dec)
    );
    if shlosilo_ur_decode_complete(dec) != 1 {
        println!("    (frames insufficient — skip)");
        shlosilo_ur_decode_free(dec);
        return;
    }
    let mut type_buf = [0u8; 32];
    let mut tlen: core::ffi::c_uint = 0;
    let _ = shlosilo_ur_decode_type(dec, type_buf.as_mut_ptr(), 32, &mut tlen);
    let mut payload = vec![0u8; 16384];
    let mut actual: core::ffi::c_uint = 0;
    let rc = shlosilo_ur_decode_payload(
        dec,
        payload.as_mut_ptr(),
        payload.len() as core::ffi::c_uint,
        &mut actual,
    );
    payload.truncate(actual as usize);
    shlosilo_ur_decode_free(dec);
    let t = String::from_utf8_lossy(&type_buf)
        .trim_end_matches('\0')
        .to_string();
    println!("    payload rc={rc} type={t} len={}", payload.len());
    head32("real Cake message", &payload);
    println!(
        "    head == 'Monero unsigned tx set\\x05' (raw blob): {}",
        payload.starts_with(b"Monero unsigned tx set\x05")
    );
    println!(
        "    head is CBOR byte-string (0x58/0x59/0x5a): {}",
        matches!(payload.first(), Some(0x58) | Some(0x59) | Some(0x5a))
    );
    // 2026-10-12 payload semantics: the exits deliver ur_message_content —
    // shell content when the message is a complete byte-string, bare otherwise.
    let content = shlosilo::ur::ur_message_content(&payload);
    println!(
        "    ur_message_content: bare passthrough={} stripped_len={}",
        core::ptr::eq(content.as_ptr(), payload.as_ptr()),
        content.len()
    );
}

#[test]
fn ur_layer_xmr_output_full_chain() {
    let dir = std::env::var("WATCHONLY_PROBE_DIR")
        .unwrap_or_else(|_| "/home/komo/works/xmr-stagenet-lab/watchonly_probe".into());
    let container = std::fs::read(format!("{dir}/full_outputs_all.bin")).expect("container");
    let keys = std::fs::read_to_string(format!("{dir}/keys.hex")).expect("keys.hex");
    let mut it = keys.split_whitespace();
    let spend_sk = hex_to_32(it.next().unwrap());
    let view_sk = hex_to_32(it.next().unwrap());

    println!("==== LAYER 0: raw container");
    head32("container", &container);
    println!("    magic ok = {}", &container[..21] == OUTPUT_EXPORT_MAGIC);

    // ── (a) single-frame URI form ──────────────────────────────────────────
    println!("==== FORM A: single-frame ur:xmr-output/<bytewords>");
    let uri =
        shlosilo::ur::ur_encode::encode(shlosilo::ur::ur_encode::UrTypeTag::XmrOutput, &container)
            .expect("single-frame encode");
    println!(
        "    uri len={} head: {}",
        uri.as_str().len(),
        &uri.as_str()[..40.min(uri.as_str().len())]
    );
    let (rc_a, type_a, payload_a) = ffi_decode_single(uri.as_str());
    println!("    shlosilo_ur_decode_uri_ffi: rc={rc_a} type={type_a}");
    head32("payload_a", &payload_a);
    let a_eq = payload_a == container[..];
    println!(
        "    payload_a == raw container: {} (first_diff={:?})",
        a_eq,
        first_diff(&payload_a, &container)
    );
    assert_eq!(rc_a, 0, "single-frame exit must accept our own encoder");

    // ── (b) multipart 2-fragment form ─────────────────────────────────────
    println!("==== FORM B: multipart 2-fragment animation");
    let mut enc = UrMultipartEncoder::new("xmr-output", &container, 128).expect("multipart encode");
    let nfrag = enc.fragment_count();
    println!("    fragment_count={nfrag} (max_fragment_len=128)");
    let mut frames = Vec::new();
    for _ in 0..nfrag {
        frames.push(enc.next_frame().expect("frame"));
    }
    for f in &frames {
        println!("    frame head: {}", &f[..40.min(f.len())]);
    }
    let (rc_b, type_b, payload_b) = ffi_decode_multipart(&frames);
    println!("    shlosilo_ur_decode_payload: rc={rc_b} type={type_b}");
    head32("payload_b", &payload_b);
    let b_eq = payload_b == container[..];
    println!(
        "    payload_b == raw container: {} (first_diff={:?})",
        b_eq,
        first_diff(&payload_b, &container)
    );

    // library-path payload_into cross-check (task step 3 semantics question)
    let mut dec = shlosilo::ur::ur_multipart::UrMultipartDecoder::new();
    for f in &frames {
        dec.receive_frame(f).unwrap();
    }
    let mut p = vec![0u8; 16384];
    let n = dec.payload_into(&mut p).unwrap().expect("complete");
    p.truncate(n);
    println!(
        "    payload_into == payload_b: {} == raw container: {}",
        p == payload_b,
        p[..] == container[..]
    );
    head32("payload_into", &p);

    // ── task step 3: single-frame exit vs multipart exit semantics ─────────
    println!("==== STEP 3: payload semantics across the two exits");
    println!(
        "    payload_a == payload_b: {} (both = raw message bytes, no CBOR strip/add)",
        payload_a == payload_b
    );

    // ── pairing on each form with the REAL wallet keys ────────────────────
    println!("==== PAIRING (business::xmr_pairing, keys from keys.hex)");
    let ok_raw = pairing_with_real_keys("raw container", &container, &view_sk, &spend_sk);
    let ok_a = pairing_with_real_keys("form A payload", &payload_a, &view_sk, &spend_sk);
    let ok_b = pairing_with_real_keys("form B payload", &payload_b, &view_sk, &spend_sk);
    println!("    summary: raw={ok_raw} formA={ok_a} formB={ok_b}");

    // ── product FFI face end-to-end with a UR-derived payload ─────────────
    println!("==== PRODUCT FFI (shlosilo_xmr_pairing_ffi) with UR-derived payload");
    {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;
        use rand_chacha::rand_core::SeedableRng as _;
        use shlosilo::chain::xmr::key_image_export::encrypt_export_payload_into;
        use shlosilo::chain::xmr::subaddress::calc_output_key_offset;
        use shlosilo::ffi::c_abi::r3::shlosilo_xmr_pairing_ffi;
        use shlosilo::types::key_session::KeySession;

        let session = KeySession::from_entropy(&[0x11u8; 16], b"").unwrap();
        let ks = session.monero();
        let v = *ks.view_sk.expose();
        let s = *ks.spend_sk.expose();
        let point = |sk: &[u8; 32]| {
            (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
                .compress()
                .to_bytes()
        };
        let spend_pub = point(&s);
        let view_pub = point(&v);
        let tx_pub = point(&[0x42u8; 32]);
        let offset = calc_output_key_offset(&v, &tx_pub, 0, 0, 0).unwrap();
        let input_sk = Scalar::from_bytes_mod_order(s) + Scalar::from_bytes_mod_order(offset);
        let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();
        let mut plain = Vec::new();
        plain.extend_from_slice(&[0x01, 0x00, 0x01, 0x00]);
        plain.extend_from_slice(&[0x01]);
        plain.extend_from_slice(&out_pub);
        plain.extend_from_slice(&[0x00, 0x64]);
        plain.extend_from_slice(&tx_pub);
        plain.push(0b0001_0100);
        plain.extend_from_slice(&[0x80, 0x96, 0x98, 0x91, 0x04]);
        plain.extend_from_slice(&[0x00, 0x00, 0x00]);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        let mut req_buf = vec![0u8; 2048];
        let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
        let req_n = encrypt_export_payload_into(
            OUTPUT_EXPORT_MAGIC,
            &v,
            &spend_pub,
            &view_pub,
            &plain,
            &mut rng,
            &mut req_buf,
            &mut cn,
        )
        .unwrap();
        let req = &req_buf[..req_n];

        for (label, payload) in [
            ("uri single", {
                let u = shlosilo::ur::ur_encode::encode(
                    shlosilo::ur::ur_encode::UrTypeTag::XmrOutput,
                    req,
                )
                .unwrap();
                let (rc, _, p) = ffi_decode_single(u.as_str());
                assert_eq!(rc, 0);
                p
            }),
            ("multipart", {
                let mut e = UrMultipartEncoder::new("xmr-output", req, 128).unwrap();
                let mut fs = Vec::new();
                for _ in 0..e.fragment_count() {
                    fs.push(e.next_frame().unwrap());
                }
                let (rc, _, p) = ffi_decode_multipart(&fs);
                assert_eq!(rc, 0);
                p
            }),
        ] {
            let entropy = [7u8; 32];
            let mut out = vec![0u8; 8192];
            let mut ws = vec![0u8; pairing_ws_len()];
            let mut actual: core::ffi::c_uint = 0;
            let rc = shlosilo_xmr_pairing_ffi(
                &session,
                payload.as_ptr(),
                payload.len() as core::ffi::c_uint,
                entropy.as_ptr(),
                entropy.len() as core::ffi::c_uint,
                out.as_mut_ptr(),
                out.len() as core::ffi::c_uint,
                &mut actual,
                ws.as_mut_ptr(),
                ws.len() as core::ffi::c_uint,
            );
            println!("    xmr_pairing_ffi[{label}]: rc={rc} out_len={}", actual);
        }
    }

    // ── failure-mode bisect probes ─────────────────────────────────────────
    println!("==== PROBE P1: multipart frame text into the SINGLE-FRAME exit");
    let (rc_p1, _, _) = ffi_decode_single(&frames[0]);
    println!(
        "    shlosilo_ur_decode_uri_ffi(ur:xmr-output/1-N/...) -> rc={rc_p1} ({})",
        shlosilo::ffi::error_code::describe(rc_p1)
    );

    println!("==== PROBE P2: CBOR byte-string wrapped container (keystone-ur Bytes semantics)");
    {
        // 241 B -> CBOR bytes item = 0x58 0xf1 || container (1-byte length head)
        let mut wrapped = Vec::new();
        wrapped.push(0x58u8);
        wrapped.push(container.len() as u8);
        wrapped.extend_from_slice(&container);
        head32("wrapped", &wrapped);
        let u = shlosilo::ur::ur_encode::encode(
            shlosilo::ur::ur_encode::UrTypeTag::XmrOutput,
            &wrapped,
        )
        .unwrap();
        let (rc, _, p) = ffi_decode_single(u.as_str());
        // 2026-10-12 semantics: the decode exit strips exactly ONE complete
        // CBOR byte-string shell. The probe's pre-wrapped message enters
        // encode -> double-wrapped on the wire -> the transport shell is
        // stripped, delivering the (keystone-style) wrapped form.
        println!(
            "    single-frame round trip rc={rc} (transport shell stripped, payload == wrapped form: {})",
            p == wrapped[..]
        );
        println!(
            "    wrapped form still carries the container at +2: {}",
            p.len() == wrapped.len() && p[2..] == container[..]
        );
        assert_eq!(
            p,
            wrapped[..],
            "exactly one shell stripped (P2 new semantics)"
        );
        pairing_with_real_keys("CBOR-wrapped", &p, &view_sk, &spend_sk);

        // 2026-10-12: the multipart encoder owns the shell -- feed the raw
        // container and the wire message IS the keystone CBOR bytes item.
        let mut e = UrMultipartEncoder::new("xmr-output", &container, 128).unwrap();
        let mut fs = Vec::new();
        for _ in 0..e.fragment_count() {
            fs.push(e.next_frame().unwrap());
        }
        let (rc, _, p) = ffi_decode_multipart(&fs);
        // one strip lands on the keystone shell -> raw container.
        println!(
            "    multipart round trip rc={rc} (payload stripped == raw container: {})",
            p == container[..]
        );
        assert_eq!(
            p,
            container[..],
            "multipart exit strips the keystone shell (P2 new semantics)"
        );
        pairing_with_real_keys("CBOR-wrapped mp", &p, &view_sk, &spend_sk);
    }

    println!("==== PROBE P3: oversize single-frame (> UR_PAYLOAD_MAX_LEN 2048)");
    {
        let big = vec![0xAAu8; 2500];
        let mut body_buf = vec![0u8; 8192];
        let mut body_n = 0usize;
        bytewords::encode_minimal_into(&big, &mut body_buf, &mut body_n).expect("bytewords");
        let body = std::str::from_utf8(&body_buf[..body_n]).unwrap();
        let uri = format!("ur:xmr-output/{body}");
        let (rc, _, _) = ffi_decode_single(&uri);
        println!(
            "    2500B payload single-frame -> rc={rc} ({})  [multipart budget is 16 KiB]",
            shlosilo::ffi::error_code::describe(rc)
        );
        // same big payload over multipart: decode fine, pairing sees it (budget = 16 KiB)
        let mut e = UrMultipartEncoder::new("xmr-output", &big, 200).unwrap();
        let mut fs = Vec::new();
        for _ in 0..e.fragment_count() {
            fs.push(e.next_frame().unwrap());
        }
        let (rc, _, p) = ffi_decode_multipart(&fs);
        println!("    2500B payload multipart -> rc={rc} recovered={}B (pairing would then -21 on magic)", p.len());
    }

    assert!(
        ok_raw && ok_a && ok_b,
        "UR layer must be byte-faithful for this container"
    );
}
