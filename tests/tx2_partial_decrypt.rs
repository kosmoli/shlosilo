//! Host tool: partial reassembly + decrypt of the REAL tx2 device frames.
//!
//! The fountain parts are pure slices of the message, so 17/19 parts leave a
//! single hole (container bytes ~1947..2337). ChaCha20 is a stream cipher:
//! covered ciphertext decrypts correctly regardless of the hole. We
//! zero-patch the hole and dump the plaintext field structure so the
//! structured tail fields can be compared with the host signer's output.
//!
//! Run:
//!   TX2_FRAMES=/tmp/tx2real_frames.txt \
//!   SHLOSILO_TEST_XMR_VIEW_SK=... \
//!   cargo test --release --test tx2_partial_decrypt -- --ignored --nocapture
use shlosilo::chain::xmr::signed_txset::decrypt_signed_txset;

fn env_hex(name: &str) -> Option<[u8; 32]> {
    let s = std::env::var(name).ok()?;
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    Some(v.try_into().unwrap())
}

/// Minimal bytewords decode (2 chars per byte: first+last letter of table word).
fn bw_decode_min(s: &str) -> Vec<u8> {
    let words_src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("forms/encoding/bytewords.rs"),
    )
    .expect("bytewords.rs");
    let start = words_src.find("const WORDS").unwrap();
    let block = &words_src[start..];
    let words: Vec<&str> = block
        .split('"')
        .filter(|w| w.len() == 4 && w.chars().all(|c| c.is_ascii_lowercase()))
        .collect();
    let mut idx = [0usize; 256];
    for (i, w) in words.iter().enumerate().take(256) {
        let b = ((w.as_bytes()[0] - b'a') << 4) | (w.as_bytes()[3] - b'a');
        idx[b as usize] = i;
    }
    // build lookup by 2-char code
    let mut by_code = std::collections::HashMap::new();
    for (i, w) in words.iter().enumerate().take(256) {
        let code = format!("{}{}", &w[..1], &w[3..4]);
        by_code.insert(code, i as u8);
    }
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        let code = format!("{}{}", b[i] as char, b[i + 1] as char);
        out.push(*by_code.get(&code).expect("bad code"));
        i += 2;
    }
    let _ = idx;
    out
}

fn cbor_uint(b: &[u8], i: &mut usize) -> u64 {
    let v = b[*i] & 0x1f;
    *i += 1;
    match v {
        x if x < 24 => u64::from(x),
        24 => {
            let r = u64::from(b[*i]);
            *i += 1;
            r
        }
        25 => {
            let r = u64::from(u16::from_be_bytes([b[*i], b[*i + 1]]));
            *i += 2;
            r
        }
        _ => {
            let r = u64::from(u32::from_be_bytes([b[*i], b[*i + 1], b[*i + 2], b[*i + 3]]));
            *i += 4;
            r
        }
    }
}

#[test]
#[ignore = "host tool: partial decrypt of real tx2 device frames"]
fn partial_reassemble_decrypt() {
    let path = std::env::var("TX2_FRAMES").unwrap_or_else(|_| "/tmp/tx2real_frames.txt".into());
    let text = std::fs::read_to_string(&path).expect("frames");
    let mut parts: Vec<(u64, u64, u64, Vec<u8>)> = Vec::new(); // seq, count, mlen, data
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("ur:") {
            continue;
        }
        let seg: Vec<&str> = line.split('/').collect();
        let body = seg[2];
        let raw = bw_decode_min(body);
        let mut i = 0usize;
        assert_eq!(raw[i] >> 5, 4, "part must be array");
        i += 1;
        let seq = cbor_uint(&raw, &mut i);
        let cnt = cbor_uint(&raw, &mut i);
        let mlen = cbor_uint(&raw, &mut i);
        let _csum = cbor_uint(&raw, &mut i);
        assert_eq!(raw[i] >> 5, 2, "data must be bstr");
        let mut ln = (raw[i] & 0x1f) as usize;
        i += 1;
        if ln == 24 {
            ln = raw[i] as usize;
            i += 1;
        } else if ln == 25 {
            ln = usize::from(u16::from_be_bytes([raw[i], raw[i + 1]]));
            i += 2;
        }
        parts.push((seq, cnt, mlen, raw[i..i + ln].to_vec()));
    }
    let count = parts[0].1;
    let mlen = parts[0].2 as usize;
    let frag_len = parts[0].3.len();
    println!(
        "parts={} count={count} message_length={mlen} frag_len={frag_len}",
        parts.len()
    );

    let mut msg = vec![0u8; mlen];
    let mut covered = vec![false; mlen];
    for (seq, _, _, data) in &parts {
        let off = (*seq as usize - 1) * frag_len;
        for (j, b) in data.iter().enumerate() {
            if off + j < mlen {
                msg[off + j] = *b;
                covered[off + j] = true;
            }
        }
    }
    let missing: Vec<(usize, usize)> = {
        let mut v = Vec::new();
        let mut start = None;
        for (i, c) in covered.iter().enumerate() {
            if !c && start.is_none() {
                start = Some(i);
            }
            if *c && start.is_some() {
                v.push((start.unwrap(), i));
                start = None;
            }
        }
        if let Some(s) = start {
            v.push((s, mlen));
        }
        v
    };
    println!("missing ranges (message offsets): {missing:?}");

    // shell strip: 59 xx xx bstr header
    assert_eq!(msg[0], 0x59, "expected 2-byte-len bstr shell");
    let clen = (usize::from(msg[1]) << 8) | usize::from(msg[2]);
    println!("shell declares container len {clen}");
    let container = &msg[3..3 + clen];
    let cmissing: Vec<(usize, usize)> = missing
        .iter()
        .map(|(a, b)| (a.saturating_sub(3), b.saturating_sub(3)))
        .collect();
    println!("missing ranges (container offsets): {cmissing:?}");

    let view_sk = env_hex("SHLOSILO_TEST_XMR_VIEW_SK").expect("view sk");
    let plain = decrypt_signed_txset(container, &view_sk).expect("decrypt (hole zero-patched)");
    println!("plaintext {} bytes", plain.len());
    std::fs::write("/tmp/tx2real_plain.bin", &plain).unwrap();

    // structural dump: print plaintext head + tail with ascii annotation
    let hexdump = |label: &str, slice: &[u8]| {
        println!("--- {label} ({} B)", slice.len());
        for (n, chunk) in slice.chunks(32).enumerate() {
            let hx: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
            let asc: String = chunk
                .iter()
                .map(|b| {
                    if b.is_ascii_graphic() || *b == b' ' {
                        *b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            println!("{:06x}  {hx}  {asc}", n * 32,)
        }
        let _ = label;
    };
    let _ = hexdump;
    for (n, chunk) in plain.chunks(32).enumerate() {
        let hx: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let asc: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("{:06x}  {hx}  {asc}", n * 32);
    }
}
