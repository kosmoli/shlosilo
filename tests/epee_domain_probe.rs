//! epee parse-domain matrix probe (diagnostic, not a regression test).
//!
//! Question: can a real-wallet `export_outputs` plaintext shape (multi output /
//! additional_tx_keys / partial export with offset≠0) push the pairing chain
//! into the -21 "output format not recognized" funnel?
//!
//! Runs only host-side; touches no product code.
//!
//! Repro: PATH=~/.rustup/toolchains/1.88-x86_64-unknown-linux-gnu/bin:$PATH \
//!        cargo test --offline --test epee_domain_probe -- --nocapture

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng as _;
use shlosilo::business::xmr_pairing::{
    carve_pairing_ws, pairing_ws_len, process_output_export_session,
};
use shlosilo::chain::xmr::key_image_export::{encrypt_export_payload_into, OUTPUT_EXPORT_MAGIC};
use shlosilo::chain::xmr::output_export::{ExportedTransferDetail, ExportedTransferDetails};
use shlosilo::chain::xmr::subaddress::calc_output_key_offset;
use shlosilo::ffi::c_abi::r3::shlosilo_xmr_pairing_ffi;
use shlosilo::types::key_session::KeySession;

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// Independent LEB128 reference reader (for parse traces).
fn ref_varint(d: &[u8], off: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *d.get(*off)?;
        *off += 1;
        v |= u64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some(v);
        }
        if shift >= 64 {
            return None;
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Spec {
    internal: u64,
    global: u64,
    amount: u64,
    add_keys: usize,
    major: u32,
    minor: u32,
    flags: u8,
    /// false = garbage pubkey (parse-only specimen, key-image stage will fail)
    derive: bool,
}

/// Build a plaintext: head (v1,v2,v3,v4) varints + `outs.len()` records.
fn build_plain(
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
    outs: &[Spec],
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
) -> Vec<u8> {
    let mut plain = Vec::new();
    encode_varint(v1, &mut plain);
    encode_varint(v2, &mut plain);
    encode_varint(v3, &mut plain);
    encode_varint(v4, &mut plain);
    for (i, s) in outs.iter().enumerate() {
        let tx_sk = [0x42u8.wrapping_add(i as u8 * 3); 32];
        let tx_pub = point(&tx_sk);
        let mut add_pks = Vec::new();
        for j in 0..s.add_keys {
            let ak = point(&[0x60u8.wrapping_add(j as u8); 32]);
            add_pks.push(ak);
        }
        // same key-selection rule as compute_key_image_with_signature
        let key_to_use: [u8; 32] = if s.major != 0 || s.minor != 0 {
            match add_pks.len() {
                1 => add_pks[0],
                n if n > 1 => {
                    add_pks.get(s.internal as usize).copied().unwrap_or(tx_pub)
                }
                _ => tx_pub,
            }
        } else {
            tx_pub
        };
        let out_pub = if s.derive {
            let off = calc_output_key_offset(view_sk, &key_to_use, s.internal, s.major, s.minor)
                .unwrap();
            let input_sk =
                Scalar::from_bytes_mod_order(*spend_sk) + Scalar::from_bytes_mod_order(off);
            (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes()
        } else {
            [0xEEu8; 32]
        };

        encode_varint(1, &mut plain); // VERSION_FIELD(1)
        plain.extend_from_slice(&out_pub);
        encode_varint(s.internal, &mut plain);
        encode_varint(s.global, &mut plain);
        plain.extend_from_slice(&tx_pub);
        plain.push(s.flags);
        encode_varint(s.amount, &mut plain);
        encode_varint(s.add_keys as u64, &mut plain);
        for ak in &add_pks {
            plain.extend_from_slice(ak);
        }
        encode_varint(u64::from(s.major), &mut plain);
        encode_varint(u64::from(s.minor), &mut plain);
    }
    plain
}

/// keystone-grammar reference parse (loops on the 4th varint = vector count).
fn ref_parse(d: &[u8], loop_on_v3: bool) -> String {
    let mut off = 0usize;
    let v1 = ref_varint(d, &mut off);
    let v2 = ref_varint(d, &mut off);
    let v3 = ref_varint(d, &mut off);
    let v4 = ref_varint(d, &mut off);
    let n = if loop_on_v3 { v3 } else { v4 }.unwrap_or(0);
    let mut rec = 0u64;
    let mut err: Option<String> = None;
    for _ in 0..n {
        if ref_varint(d, &mut off).is_none() {
            err = Some(format!("varint overflow/oob @{}", off));
            break;
        }
        if off + 32 > d.len() {
            err = Some(format!("pubkey oob @{}", off));
            break;
        }
        off += 32;
        if ref_varint(d, &mut off).is_none() || ref_varint(d, &mut off).is_none() {
            err = Some(format!("idx varint oob @{}", off));
            break;
        }
        if off + 32 + 1 > d.len() {
            err = Some(format!("tx_pubkey/flags oob @{}", off));
            break;
        }
        off += 33;
        if ref_varint(d, &mut off).is_none() {
            err = Some(format!("amount oob @{}", off));
            break;
        }
        let kn = match ref_varint(d, &mut off) {
            Some(k) => k,
            None => {
                err = Some(format!("add-keys count oob @{}", off));
                break;
            }
        };
        if off + 32 * kn as usize > d.len() {
            err = Some(format!("add-keys oob @{}", off));
            break;
        }
        off += 32 * kn as usize;
        if ref_varint(d, &mut off).is_none() || ref_varint(d, &mut off).is_none() {
            err = Some(format!("major/minor oob @{}", off));
            break;
        }
        rec += 1;
    }
    match err {
        Some(e) => format!("head=({:?},{:?},{:?},{:?}) recs={} FAIL {}", v1, v2, v3, v4, rec, e),
        None => format!(
            "head=({:?},{:?},{:?},{:?}) recs={} consumed={}/{} exact={}",
            v1,
            v2,
            v3,
            v4,
            rec,
            off,
            d.len(),
            off == d.len()
        ),
    }
}

/// Direct device-grammar parse (shlosilo `ExportedTransferDetails::from_bytes`).
fn dev_parse(d: &[u8]) -> String {
    let mut pool: [ExportedTransferDetail; 16] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    match ExportedTransferDetails::from_bytes(d, &mut pool) {
        Ok(p) => format!("OK n={} offset={} size={}", p.details.len(), p.offset, p.size),
        Err(e) => format!("ERR {:?}", e),
    }
}

struct Row {
    label: &'static str,
    expect: &'static str,
}

fn run_variant(
    label: &'static str,
    expect: &'static str,
    plain: &[u8],
    session: &KeySession,
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
    spend_pub: &[u8; 32],
    view_pub: &[u8; 32],
    use_business_face: bool,
) {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    let mut req_buf = vec![0u8; 16384];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let req_n = encrypt_export_payload_into(
        OUTPUT_EXPORT_MAGIC,
        view_sk,
        spend_pub,
        view_pub,
        plain,
        &mut rng,
        &mut req_buf,
        &mut cn,
    )
    .unwrap();
    let req = &req_buf[..req_n];

    let mut out = vec![0u8; 16384];
    let mut ws = vec![0u8; pairing_ws_len()];
    let mut actual: core::ffi::c_uint = 0;
    let rc = if use_business_face {
        let mut w = carve_pairing_ws(&mut ws).unwrap();
        match process_output_export_session(session, req, &mut w, &mut out, &mut rng) {
            Ok(o) => {
                actual = o.written as core::ffi::c_uint;
                0
            }
            Err(e) => shlosilo::error::ShlosiloErrorCode::from_shlosilo_error(e),
        }
    } else {
        shlosilo_xmr_pairing_ffi(
            session,
            req.as_ptr(),
            req.len() as core::ffi::c_uint,
            [7u8; 32].as_ptr(),
            32,
            out.as_mut_ptr(),
            out.len() as core::ffi::c_uint,
            &mut actual,
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
        )
    };

    // attribution: re-parse the SAME plaintext with the device grammar directly
    let dev = dev_parse(plain);
    let ref4 = ref_parse(plain, false); // keystone grammar: loop v4
    let ref3 = ref_parse(plain, true); // shlosilo grammar: loop v3

    let verdict = if rc == 0 {
        "PASS"
    } else if dev.starts_with("ERR") {
        "F3 plaintext-epee-parse (-21 container-form funnel)"
    } else if rc == -21 {
        "F4 keyimage stage -21 (add-key index / pubkey verify), parse was OK"
    } else if rc == -20 {
        "F- pool/scratch cap (-20 data error)"
    } else {
        "other"
    };

    println!(
        "┌ {label}\n│ expect: {expect}\n│ plain_len={} container_len={} rc={rc} ({}) out_len={actual}\n\
         │ dev_parse[from_bytes] : {dev}\n│ ref_parse[loop v4/key]  : {ref4}\n\
         │ ref_parse[loop v3/shl]: {ref3}\n│ plain[..96]: {}\n└ verdict: {verdict}\n",
        plain.len(),
        req.len(),
        shlosilo::ffi::error_code::describe(rc),
        hex(&plain[..plain.len().min(96)]),
    );
}

#[test]
fn epee_domain_matrix() {
    let session = KeySession::from_entropy(&[0x11u8; 16], b"").unwrap();
    let keys = session.monero();
    let view_sk = *keys.view_sk.expose();
    let spend_sk = *keys.spend_sk.expose();
    let spend_pub = point(&spend_sk);
    let view_pub = point(&view_sk);

    let mk = |n: usize, add: usize, major_minor: &[(u32, u32)], flags: u8| -> Vec<Spec> {
        (0..n)
            .map(|i| Spec {
                internal: if add > 1 {
                    (i % (add.min(3))) as u64 // indexable within add_keys
                } else {
                    (i % 2) as u64
                },
                global: 100_000_000 + i as u64 * 7, // multi-byte varint, real-shaped
                amount: 100_000_000_000 + i as u64, // multi-byte varint
                add_keys: add,
                major: major_minor[i % major_minor.len()].0,
                minor: major_minor[i % major_minor.len()].1,
                flags,
                derive: true,
            })
            .collect()
    };

    // ── A: multi-output (all full export: v3 == v4 == n) ───────────────────
    for n in [2usize, 3, 5, 8, 9] {
        let outs = mk(n, 0, &[(0, 0)], 0x14);
        let plain = build_plain(3, 0, n as u64, n as u64, &outs, &view_sk, &spend_sk);
        let expect = if n <= 8 { "rc=0" } else { "-20 pool cap 8" };
        run_variant(
            Box::leak(format!("A: {n} outputs, 0 add-keys, v3=v4={n}").into_boxed_str()),
            expect,
            &plain,
            &session,
            &view_sk,
            &spend_sk,
            &spend_pub,
            &view_pub,
            false,
        );
    }

    // ── B: additional_tx_keys ─────────────────────────────────────────────
    let b1 = mk(2, 1, &[(0, 1), (1, 0)], 0x14);
    let plain = build_plain(3, 0, 2, 2, &b1, &view_sk, &spend_sk);
    run_variant(
        "B1: 2 outputs, 1 add-key each, subaddr major/minor≠0",
        "rc=0",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    let b2 = mk(3, 2, &[(0, 2), (1, 1)], 0x14);
    let plain = build_plain(3, 0, 3, 3, &b2, &view_sk, &spend_sk);
    run_variant(
        "B2: 3 outputs, 2 add-keys each, internal idx within range",
        "rc=0",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    // add-key index OOB: internal=2 with only 2 add keys (parse OK, keyimage -21)
    let mut b3 = mk(2, 2, &[(0, 2), (1, 1)], 0x14);
    b3[0].internal = 2;
    let plain = build_plain(3, 0, 2, 2, &b3, &view_sk, &spend_sk);
    run_variant(
        "B3: 2 outputs, 2 add-keys, internal idx=2 (add-key index OOB)",
        "parse OK, keyimage-stage -21 (wrong-layer funnel)",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    // ── C: partial / chunked export (offset, v3≠v4 divergence) ────────────
    let c0 = mk(2, 0, &[(0, 0)], 0x14);
    let plain = build_plain(3, 5, 2, 2, &c0, &view_sk, &spend_sk);
    run_variant(
        "C0: partial marker offset=5, v3=v4=2 (offset alone)",
        "rc=0 (offset field harmless)",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    // the conviction candidate: total(v3)=5 > count(v4)=2, 2 records present
    let c1 = mk(2, 0, &[(0, 0)], 0x14);
    let plain = build_plain(3, 3, 5, 2, &c1, &view_sk, &spend_sk);
    run_variant(
        "C1: PARTIAL offset=3, v3(total)=5, v4(count)=2, 2 records",
        "-21 at plaintext epee parse (shlosilo loops v3=total)",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        true, // business face for the conviction variant
    );

    let c2 = mk(3, 0, &[(0, 0)], 0x14);
    let plain = build_plain(3, 0, 6, 3, &c2, &view_sk, &spend_sk);
    run_variant(
        "C2: CHUNKED offset=0, v3(total)=6, v4(count)=3, 3 records",
        "-21 at plaintext epee parse",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    // v3 < v4: shlosilo under-reads (silent truncation, trailing record ignored)
    let c3 = mk(5, 0, &[(0, 0)], 0x14);
    let plain = build_plain(3, 0, 2, 5, &c3, &view_sk, &spend_sk);
    run_variant(
        "C3: v3=2 < v4=5, 5 records (under-read direction)",
        "rc=0 but only 2 of 5 records answered (silent)",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    // ── D: combination (partial + add-keys + subaddr + multi-output) ──────
    let d1 = mk(3, 1, &[(0, 1), (1, 0), (0, 2)], 0x34); // key_image_partial bit set
    let plain = build_plain(3, 2, 5, 3, &d1, &view_sk, &spend_sk);
    run_variant(
        "D1: COMBO offset=2, v3=5/v4=3, 3 outputs, 1 add-key, subaddr, partial flag",
        "-21 at plaintext epee parse",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    let d2 = mk(4, 1, &[(0, 1), (1, 0), (0, 2), (2, 1)], 0x34);
    let plain = build_plain(3, 0, 4, 4, &d2, &view_sk, &spend_sk);
    run_variant(
        "D2: COMBO full export v3=v4=4, 4 outputs, 1 add-key, subaddr, partial flags",
        "rc=0",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    // ── E: REAL specimens (parse attribution only / key-image stage expected) ──
    // real stagenet wallet2 1-output plaintext (watchonly_probe probe_output.txt)
    let e2 = hex_to_bytes(
        "0300010101bd1389863f53d580233c3c2b01ad01d62930125efb5946e585c2bc1832344a1a00f3a4e80486bd02355da4e06d2245e32b7b05feb7f0cff2e4e2de32e7232c5c678fd6f2a10c80d0dbc3f402000000",
    );
    run_variant(
        "E2: REAL wallet2 stagenet 1-output plaintext (foreign keys)",
        "parse OK; -21 at keyimage verify (foreign output keys)",
        &e2,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    // real 7-output plaintext (keystone3-firmware outputs.rs test vector)
    let e1 = hex_to_bytes(
        "03000707013e8c52245d21b22cbcb90f95270a7937d4974d726209f0a41fdefc7f9df01fde01c8b486383e45d72b841a8b76094dbaa26f9800aac4eaced3bc06122a3380bcf6c666d2281480a0b787e905000000012d58a6378c07f230148c11979cc6e3bec2719f0ec92de21f7fae02029ab025e000f385873857dc102abc6d35c878db7be629646658ae1a418afb27a943f8a2591be4f450e9148094ebdc03000001014ef323a52d2e048594ad73acbe5fb7e588b1859ec9aa02b2670f487660b2700901f485873857dc102abc6d35c878db7be629646658ae1a418afb27a943f8a2591be4f450e914c0b5809ce50500000001cb8ab3c1b4dd10404a4a3c9275a7e2e1e9bf2e4edf1c84f61952bb97965573a300d0c78a38bdd50fdc0367b3141fdc055dec3af5e3ac920dd55816823dfe02f70c3d1816431480c2d72f00000301dd8c2a791056760d903bf06e7930585201e0bd20bcba1e720b85ad0e4d628e4801d1c78a38bdd50fdc0367b3141fdc055dec3af5e3ac920dd55816823dfe02f70c3d18164314a0eec19e03000000019b65ada69049d73e4b049ebd50393410cdc05dad5314690d2b4a36628c4e257600a4909d385d43421399107bd34350b8938f9ff69da18e8f083e6522adf6aa270b3f370ed41480e8eda1ba01000100016311ba60a0a8c636806e232db3e1ad7f79e26df3d24258e264e4351e47f4374d01a5909d385d43421399107bd34350b8938f9ff69da18e8f083e6522adf6aa270b3f370ed414c0c2b383ae04000000",
    );
    run_variant(
        "E1: REAL wallet2 7-output plaintext (foreign keys, mixed subaddr)",
        "parse OK; -21 at keyimage verify (foreign output keys)",
        &e1,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    // E1b: same shape as the real 7-output specimen but re-derived with lab keys
    let e1b = mk(7, 0, &[(0, 0), (0, 1), (1, 0), (0, 3)], 0x14);
    let plain = build_plain(3, 0, 7, 7, &e1b, &view_sk, &spend_sk);
    run_variant(
        "E1b: real 7-output SHAPE re-derived with lab keys (mixed subaddr/internal)",
        "rc=0 (multi-output real shape exonerated)",
        &plain,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    // ── F: head edge forms ────────────────────────────────────────────────
    let f1 = build_plain(0, 0, 0, 0, &[], &view_sk, &spend_sk);
    run_variant(
        "F1: v1=0 short form (no transfers)",
        "rc=0, 0 outputs",
        &f1,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    let f2 = build_plain(1, 0, 1, 1, &mk(1, 0, &[(0, 0)], 0x14), &view_sk, &spend_sk);
    run_variant(
        "F2: legacy lab shape v1=1, 1 output",
        "rc=0",
        &f2,
        &session,
        &view_sk,
        &spend_sk,
        &spend_pub,
        &view_pub,
        false,
    );

    let _ = Row {
        label: "",
        expect: "",
    };
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
