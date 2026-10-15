//! Cake REAL container (240 B) through our pairing prologue — staged timing probe.
//!
//! Motivation (2026-10-15): the device scanned a real Cake `xmr-output` and
//! wedged inside the pairing FFI prologue (whole system freeze → WDT reset;
//! crash-phase 3, the marker before the key-image loop, never fired). Host had
//! only ever exercised synthetic lab containers (1 output / 0 add keys). The
//! real Cake container (240 B wallet2 container, real wallet with multiple
//! outputs / subaddresses / additional tx keys) had never entered our parser.
//!
//! This probe drives the real two-frame capture through every prologue segment
//! and times each one:
//!   (a) `decrypt_export_payload`  — signature verify + ChaCha decrypt
//!   (b) `ExportedTransferDetails::from_bytes` — epee parse (field dump below)
//!   (c) pk1/pk2 ownership check
//!   (d) per-output key image derivation
//! plus the product FFI face `shlosilo_xmr_pairing_ffi` end-to-end. Any segment
//! over [`HANG_LIMIT`] is treated as the hang reproducing on host; the run
//! reports which segment it stopped in.
//!
//! Disk keys: entropy = 0x22 × 32 → BIP-39 → SLIP-0010 MoneroPath (the device's
//! KeySession). `view_sk` is pinned to the known value below — if the derivation
//! chain ever walks differently, the probe fails before touching the container.

use std::time::{Duration, Instant};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use monero_ed25519::Point;
use shlosilo::chain::xmr::key_image_export::{
    decrypt_export_payload, encrypt_export_payload_into, generate_key_image_export_into,
    KEY_IMAGE_EXPORT_MAGIC, OUTPUT_EXPORT_MAGIC,
};
use shlosilo::chain::xmr::output_export::{
    deserialize_key_images_into, ExportedTransferDetail, ExportedTransferDetails,
    KEY_IMAGE_RECORD_LEN,
};
use shlosilo::chain::xmr::subaddress::{calc_output_key_offset, hash_to_scalar};
use shlosilo::types::key_session::KeySession;
use shlosilo::ur::ur_multipart::UrMultipartDecoder;

/// Device freeze threshold: any prologue segment at or beyond this on host is
/// the hang class that WDT-reset the device.
const HANG_LIMIT: Duration = Duration::from_secs(5);

/// The known view_sk of the disk wallet (the keys the real Cake export was
/// encrypted under). Pin: the entropy→mnemonic→seed→MoneroPath chain must land
/// here or the probe is testing the wrong wallet.
const KNOWN_VIEW_SK: &str = "db93ce632d8d31e31bd0b4ecbdbdb833cae813928af402c5b7ffeb85769cf000";

const DISK_ENTROPY: [u8; 32] = [0x22u8; 32];

// ─── helpers ────────────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hexdump_head_tail(bytes: &[u8]) -> String {
    let head = &bytes[..bytes.len().min(96)];
    let tail = &bytes[bytes.len().saturating_sub(64)..];
    format!(
        "len={}\n  head96: {}\n  tail64: {}",
        bytes.len(),
        hex(head),
        hex(tail)
    )
}

fn timed<T>(segment: &str, f: impl FnOnce() -> T) -> (T, Duration) {
    let t0 = Instant::now();
    let out = f();
    let dt = t0.elapsed();
    println!("[timing] {:<38} {:?}", segment, dt);
    assert!(
        dt < HANG_LIMIT,
        "HANG REPRODUCED: segment '{segment}' took {dt:?} (>= {HANG_LIMIT:?}) — the device wedge class is in THIS segment"
    );
    (out, dt)
}

/// Reassemble the two real-capture Cake `xmr-output` frames to the 240 B
/// wallet2 container (same pipeline as `ur_cbor_shell::real_cake_...`).
fn real_container() -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/cake_real_frames.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    let path = std::env::var("CAKE_FRAMES").unwrap_or(path);
    let text = std::fs::read_to_string(&path).expect("cake frames fixture");
    let frames: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ur:"))
        .collect();
    assert_eq!(frames.len(), 2, "real capture = exactly 2 frames");
    let mut dec = UrMultipartDecoder::new();
    for f in &frames {
        dec.receive_frame(f).expect("frame feeds");
    }
    assert!(dec.complete(), "2-frame capture must complete");
    let mut out = vec![0u8; 16384];
    let n = dec.payload_into(&mut out).unwrap().expect("complete");
    assert_eq!(
        n, 240,
        "real wire message = 242 B shelled → 240 B container"
    );
    assert_eq!(&out[..5], b"Moner", "container head = 'Moner'");
    out.truncate(n);
    out
}

fn disk_session() -> KeySession {
    KeySession::from_entropy(&DISK_ENTROPY, b"").expect("disk KeySession")
}

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

/// Independent byte-level epee walk (diagnostic oracle — NOT the product
/// parser). Returns per-field rows plus, on failure, the exact byte offset and
/// the field where the wallet2 v0.18.4 layout expectation broke.
struct WalkRow {
    field: &'static str,
    off: usize,
    raw: String,
    val: String,
}

fn read_varint(plain: &[u8], off: &mut usize) -> Result<(u64, usize), (usize, String)> {
    let start = *off;
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *plain
            .get(*off)
            .ok_or((start, format!("varint runs past end (len={})", plain.len())))?;
        *off += 1;
        value |= u64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((value, *off - start));
        }
        if shift >= 64 {
            return Err((start, "varint overflows u64".into()));
        }
    }
}

fn read_32(plain: &[u8], off: &mut usize) -> Result<[u8; 32], (usize, String)> {
    if plain.len() < *off + 32 {
        return Err((
            *off,
            format!("32B blob runs past end (len={})", plain.len()),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plain[*off..*off + 32]);
    *off += 32;
    Ok(out)
}

fn walk_epee(plain: &[u8]) -> (Vec<WalkRow>, Option<(usize, String)>) {
    let mut rows = Vec::new();
    let mut off = 0usize;
    macro_rules! var {
        ($name:expr) => {
            match read_varint(plain, &mut off) {
                Ok((v, n)) => {
                    rows.push(WalkRow {
                        field: $name,
                        off: off - n,
                        raw: hex(&plain[off - n..off]),
                        val: format!("{v}"),
                    });
                    v
                }
                Err((at, why)) => {
                    rows.push(WalkRow {
                        field: $name,
                        off: at,
                        raw: String::new(),
                        val: format!("FAIL: {why}"),
                    });
                    return (rows, Some((at, format!("{}: {}", $name, why))));
                }
            }
        };
    }
    macro_rules! blob {
        ($name:expr) => {
            match read_32(plain, &mut off) {
                Ok(v) => {
                    rows.push(WalkRow {
                        field: $name,
                        off: off - 32,
                        raw: hex(&v),
                        val: hex(&v),
                    });
                    v
                }
                Err((at, why)) => {
                    rows.push(WalkRow {
                        field: $name,
                        off: at,
                        raw: String::new(),
                        val: format!("FAIL: {why}"),
                    });
                    return (rows, Some((at, format!("{}: {}", $name, why))));
                }
            }
        };
    }

    let has_transfers = var!("has_transfers");
    if has_transfers == 0 {
        return (
            rows,
            if off == plain.len() {
                None
            } else {
                Some((off, "short-form with trailing bytes".into()))
            },
        );
    }
    var!("offset");
    let total = var!("total(transfers.size)");
    let count = var!("record_count(loop bound)");
    for i in 0..count {
        let tag = |f: &'static str| -> &'static str { f };
        let _ = tag;
        rows.push(WalkRow {
            field: "── record",
            off,
            raw: String::new(),
            val: format!("#{i}"),
        });
        var!("  version(ignored)");
        blob!("  output_pubkey");
        var!("  internal_output_index");
        var!("  global_output_index");
        blob!("  tx_pubkey");
        if plain.get(off).is_none() {
            return (rows, Some((off, "flags byte: past end".into())));
        }
        rows.push(WalkRow {
            field: "  flags",
            off,
            raw: hex(&[plain[off]]),
            val: format!("{:#010b}", plain[off]),
        });
        off += 1;
        var!("  amount");
        let keys_num = var!("  additional_tx_keys count");
        for k in 0..keys_num {
            blob!("    additional_tx_key");
            let _ = k;
        }
        var!("  major");
        var!("  minor");
    }
    let _ = total;
    if off != plain.len() {
        return (
            rows,
            Some((
                off,
                format!("stream exhaustion: walked {off} of {} bytes", plain.len()),
            )),
        );
    }
    (rows, None)
}

/// (key_to_use, input_sk, input_pub, image) tuple.
type DerivedKeyImage = ([u8; 32], Scalar, [u8; 32], [u8; 32]);

/// Single-output key image derivation — the product semantics replicated over
/// public primitives (mirrors `key_image_export::compute_key_image_with_signature`).
fn derive_key_image(
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
    d: &ExportedTransferDetail,
) -> Result<DerivedKeyImage, String> {
    // additional key semantics (keystone outputs.rs / wallet2
    // generate_key_image_helper): subaddress outputs derive from the per-output
    // additional tx key, main-address outputs from the tx pubkey.
    let key_to_use: [u8; 32] = if d.major != 0 || d.minor != 0 {
        match d.additional_tx_keys.len() {
            1 => *d.additional_tx_keys[0],
            n if n > 1 => **d
                .additional_tx_keys
                .get(d.internal_output_index as usize)
                .ok_or_else(|| {
                    format!(
                        "additional_tx_keys[{}] out of range (len={n})",
                        d.internal_output_index
                    )
                })?,
            _ => d.tx_pubkey,
        }
    } else {
        d.tx_pubkey
    };
    let offset = calc_output_key_offset(
        view_sk,
        &key_to_use,
        d.internal_output_index,
        d.major,
        d.minor,
    )
    .map_err(|e| format!("calc_output_key_offset: {e:?}"))?;
    let input_sk = Scalar::from_bytes_mod_order(*spend_sk) + Scalar::from_bytes_mod_order(offset);
    let input_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();
    let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(d.pubkey).into();
    let image: [u8; 32] = (hp * input_sk).compress().to_bytes();
    Ok((key_to_use, input_sk, input_pub, image))
}

/// Independent verification of the key-image accompanying signature (single
/// ring, formula from `key_image_export` tests): Hs(image ‖ r·B+c·P ‖
/// (r+c·x)·Hp(P)) == c.
fn verify_ki_sig(image: &[u8; 32], pubkey: &[u8; 32], input_sk: &Scalar, sig: &[u8; 64]) -> bool {
    let i_point: curve25519_dalek::EdwardsPoint = Point::biased_hash(*pubkey).into();
    let Some(c) = Scalar::from_canonical_bytes(sig[..32].try_into().unwrap()).into_option() else {
        return false;
    };
    let Some(r) = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).into_option() else {
        return false;
    };
    let p_point = ED25519_BASEPOINT_TABLE * input_sk;
    let s1 = (ED25519_BASEPOINT_TABLE * &r) + (c * p_point);
    let s2 = (r + c * input_sk) * i_point;
    let mut vbuf = Vec::new();
    vbuf.extend_from_slice(image);
    vbuf.extend_from_slice(&s1.compress().to_bytes());
    vbuf.extend_from_slice(&s2.compress().to_bytes());
    match hash_to_scalar(&vbuf) {
        Ok(h) => h == c.to_bytes(),
        Err(_) => false,
    }
}

// ─── test 1: disk key derivation pin ────────────────────────────────────────

#[test]
fn cake_real_disk_keys_derive_and_pin() {
    let session = disk_session();
    let keys = session.monero();
    let spend_sk = *keys.spend_sk.expose();
    let view_sk = *keys.view_sk.expose();
    let spend_pub = point(&spend_sk);
    let view_pub = point(&view_sk);
    println!("disk keys (entropy 0x22×32):");
    println!("  spend_sk = {}", hex(&spend_sk));
    println!("  spend_pub= {}", hex(&spend_pub));
    println!("  view_sk  = {}", hex(&view_sk));
    println!("  view_pub = {}", hex(&view_pub));
    assert_eq!(
        hex(&view_sk),
        KNOWN_VIEW_SK,
        "derived view_sk must equal the known disk-wallet view_sk (derivation-chain guard)"
    );
}

// ─── test 2: the staged, timed prologue over the real 240 B container ───────

#[test]
fn cake_real_container_prologue_staged_timed() {
    let session = disk_session();
    let keys = session.monero();
    let spend_sk = *keys.spend_sk.expose();
    let view_sk = *keys.view_sk.expose();
    let spend_pub = point(&spend_sk);
    let view_pub = point(&view_sk);
    assert_eq!(hex(&view_sk), KNOWN_VIEW_SK, "derivation-chain guard");

    let (container, _t_reasm) = timed("segment 0: UR reassembly (2 frames)", real_container);
    println!("real container: {}", hexdump_head_tail(&container));

    // ── (a) decrypt_export_payload (sig verify + ChaCha) ────────────────────
    let (dec, _t_dec) = timed("(a) decrypt_export_payload", || {
        decrypt_export_payload(&container, OUTPUT_EXPORT_MAGIC, &view_sk)
    });
    let (pk1, pk2, plain) = match dec {
        Ok(v) => v,
        Err(e) => {
            // Task §4: (a) failed — dump the real container against the lab
            // shape and report differing bytes.
            eprintln!("(a) decrypt FAILED: {e:?}");
            eprintln!(
                "real container hexdump:\n  {}",
                hexdump_head_tail(&container)
            );
            // lab container: same keys, synthetic 1-output plaintext (what host
            // tested with) — for structural byte comparison only.
            let mut lab_plain = vec![0x01u8, 0x00, 0x01, 0x01, 0x01];
            lab_plain.extend_from_slice(&[0xAAu8; 32]); // pubkey (not derived — decrypt doesn't check it)
            lab_plain.extend_from_slice(&[0x00, 0x64]);
            lab_plain.extend_from_slice(&[0x22u8; 32]);
            lab_plain.push(0b0001_0100);
            lab_plain.extend_from_slice(&[0x80, 0x89, 0x2f, 0x00, 0x00, 0x00]);
            use rand_chacha::rand_core::SeedableRng as _;
            let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x1AB);
            let mut lab = vec![0u8; 1024];
            let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
            let n = encrypt_export_payload_into(
                OUTPUT_EXPORT_MAGIC,
                &view_sk,
                &spend_pub,
                &view_pub,
                0u32,
                &lab_plain,
                &mut rng,
                &mut lab,
                &mut cn,
            )
            .unwrap();
            lab.truncate(n);
            eprintln!("lab container hexdump:\n  {}", hexdump_head_tail(&lab));
            let mut diffs = Vec::new();
            let min = lab.len().min(container.len());
            for i in 0..min {
                if lab[i] != container[i] {
                    diffs.push(i);
                }
            }
            eprintln!(
                "differing byte positions (min-len {}): {} … ({} differ)",
                min,
                diffs
                    .iter()
                    .take(24)
                    .map(|i| format!("{i}"))
                    .collect::<Vec<_>>()
                    .join(","),
                diffs.len()
            );
            panic!(
                "HANG/FAIL SEGMENT: (a) decrypt_export_payload rejected the REAL container: {e:?}"
            );
        }
    };
    println!("  pk1      = {}", hex(&pk1));
    println!("  pk2      = {}", hex(&pk2));
    println!("  plain len = {}", plain.len());
    println!("  plain hex = {}", hex(&plain));

    // ── (b) epee parse + field dump ─────────────────────────────────────────
    let mut pool: [ExportedTransferDetail; 8] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    let (parsed, _t_parse) = timed("(b) ExportedTransferDetails::from_bytes", || {
        ExportedTransferDetails::from_bytes(&plain, &mut pool)
    });
    // diagnostic walk is cheap and always printed — it is what pinpoints the
    // failing varint/field offset when (b) diverges.
    let (rows, walk_fail) = walk_epee(&plain);
    println!("--- independent epee walk (wallet2 v0.18.4 layout) ---");
    for r in &rows {
        println!(
            "  @{:<3} {:<32} raw={:<18} val={}",
            r.off, r.field, r.raw, r.val
        );
    }
    match (&walk_fail, &parsed) {
        (None, Ok(_)) => println!("  walk: clean ({} bytes fully consumed)", plain.len()),
        (Some((at, why)), Err(e)) => panic!(
            "HANG/FAIL SEGMENT: (b) epee parse failed at byte {at}: {why} (product error {e:?}) — compare against wallet2 layout: VERSION_FIELD(1)+pubkey(32)+varint(idx)+varint(gidx)+tx_pubkey(32)+flags(1)+varint(amount)+varint(add_keys)+N×32B+varint(major)+varint(minor)"
        ),
        (None, Err(e)) => panic!(
            "HANG/FAIL SEGMENT: (b) product parser rejected a stream the independent walk fully consumed (product error {e:?}) — layout divergence in OUR parser"
        ),
        (Some((at, why)), Ok(_)) => panic!(
            "independent walk failed at {at} ({why}) but product parser accepted — fix the probe walk first"
        ),
    }
    let parsed = parsed.unwrap();
    println!(
        "  offset={}  size(transfers.size)={}  records={}",
        parsed.offset,
        parsed.size,
        parsed.details.len()
    );
    for (i, d) in parsed.details.iter().enumerate() {
        println!("  [{}] pubkey             = {}", i, hex(&d.pubkey));
        println!("      internal_out_index = {}", d.internal_output_index);
        println!("      global_out_index   = {}", d.global_output_index);
        println!("      tx_pubkey          = {}", hex(&d.tx_pubkey));
        println!(
            "      flags              = {:#010b} (spent={} frozen={} rct={} ki_known={} ki_request={} ki_partial={})",
            d.flags,
            d.is_spent(),
            d.is_frozen(),
            d.is_rct(),
            d.is_key_image_known(),
            d.is_key_image_request(),
            d.is_key_image_partial()
        );
        println!("      amount             = {} piconero", d.amount);
        println!(
            "      additional_tx_keys = {} key(s)",
            d.additional_tx_keys.len()
        );
        for (k, ak) in d.additional_tx_keys.iter().enumerate() {
            println!("        [{}] {}", k, hex(ak.as_ref()));
        }
        println!(
            "      subaddr            = major={} minor={}",
            d.major, d.minor
        );
    }

    // ── (c) ownership (pk1/pk2 binding) ─────────────────────────────────────
    let (owned, _t_own) = timed("(c) pk1/pk2 ownership check", || {
        pk1 == spend_pub && pk2 == view_pub
    });
    assert!(
        owned,
        "HANG/FAIL SEGMENT: (c) ownership mismatch — pk1={} (want spend_pub={}), pk2={} (want view_pub={})",
        hex(&pk1),
        hex(&spend_pub),
        hex(&pk2),
        hex(&view_pub)
    );

    // ── (d) per-output key image ────────────────────────────────────────────
    let mut images: Vec<[u8; 32]> = Vec::new();
    for (i, d) in parsed.details.iter().enumerate() {
        let ((key_to_use, _input_sk, input_pub, image), _t_ki) = timed(
            &format!("(d) key image [{}] (sub {}/{})", i, d.major, d.minor),
            || {
                derive_key_image(&view_sk, &spend_sk, d).unwrap_or_else(|e| {
                    panic!("HANG/FAIL SEGMENT: (d) key image [{i}] derivation failed: {e}")
                })
            },
        );
        println!(
            "      key_to_use = {} ({})",
            hex(&key_to_use),
            if key_to_use == d.tx_pubkey {
                "tx_pubkey"
            } else {
                "additional_tx_key"
            }
        );
        assert_eq!(
            input_pub, d.pubkey,
            "HANG/FAIL SEGMENT: (d) output [{i}] ephemeral pubkey mismatch — offset derivation does not reproduce the output (wrong tx key selected?)"
        );
        println!("      key image  = {}", hex(&image));
        images.push(image);
    }
    println!(
        "PROLOGUE COMPLETE: {} output(s), no segment exceeded {HANG_LIMIT:?}",
        images.len()
    );
}

// ─── test 3: product FFI face end-to-end over the real container ────────────

#[test]
fn cake_real_container_product_entry_ffi() {
    use shlosilo::business::xmr_pairing::pairing_ws_len;
    use shlosilo::ffi::c_abi::r3::shlosilo_xmr_pairing_ffi;

    let session = disk_session();
    let keys = session.monero();
    let spend_sk = *keys.spend_sk.expose();
    let view_sk = *keys.view_sk.expose();
    assert_eq!(hex(&view_sk), KNOWN_VIEW_SK, "derivation-chain guard");

    let container = real_container();
    let entropy = [0x5Au8; 32]; // §B.5 signing-randomness stream
    let mut out = vec![0u8; 8192];
    let mut ws = vec![0u8; pairing_ws_len()];
    let mut actual: core::ffi::c_uint = 0;

    let (rc, dt) = timed("FFI shlosilo_xmr_pairing_ffi (whole chain)", || {
        shlosilo_xmr_pairing_ffi(
            &session,
            container.as_ptr(),
            container.len() as core::ffi::c_uint,
            entropy.as_ptr(),
            entropy.len() as core::ffi::c_uint,
            out.as_mut_ptr(),
            out.len() as core::ffi::c_uint,
            &mut actual,
            ws.as_mut_ptr(),
            ws.len() as core::ffi::c_uint,
        )
    });
    println!("  rc={rc}  response len={}  total={dt:?}", actual);
    assert_eq!(rc, 0, "product FFI must accept the REAL Cake container");

    // Response read-back + independent key image check against the staged
    // derivation (test 2's replicate).
    let (_, _, resp_plain) =
        decrypt_export_payload(&out[..actual as usize], KEY_IMAGE_EXPORT_MAGIC, &view_sk)
            .expect("response decrypt");
    let mut recs = [([0u8; 32], [0u8; 64]); 8];
    let n = deserialize_key_images_into(&resp_plain, &mut recs).expect("record parse");
    println!(
        "  response carries {n} key-image record(s) ({} B wire)",
        resp_plain.len()
    );
    assert_eq!(resp_plain.len(), n * KEY_IMAGE_RECORD_LEN);

    let mut pool: [ExportedTransferDetail; 8] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    let (_, _, plain) = decrypt_export_payload(&container, OUTPUT_EXPORT_MAGIC, &view_sk).unwrap();
    let parsed = ExportedTransferDetails::from_bytes(&plain, &mut pool).expect("parse");
    assert_eq!(n, parsed.details.len(), "one record per output");
    for (i, d) in parsed.details.iter().enumerate() {
        let (key_to_use, input_sk, input_pub, image) =
            derive_key_image(&view_sk, &spend_sk, d).expect("derive");
        let _ = key_to_use;
        assert_eq!(input_pub, d.pubkey, "output [{i}] reproduces its pubkey");
        assert_eq!(
            recs[i].0, image,
            "key image [{i}] matches independent derivation"
        );
        assert!(
            verify_ki_sig(&image, &d.pubkey, &input_sk, &recs[i].1),
            "accompanying signature [{i}] must verify"
        );
    }
    println!("FFI END-TO-END OK over the real 240 B Cake container");
}

// ─── test 4: prying surfaces — additional tx keys + amount=0/rct ────────────

/// Build one epee record (independent of the product serializer).
fn push_varint(out: &mut Vec<u8>, mut v: u64) {
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

struct SynthRec {
    pubkey: [u8; 32],
    idx: u64,
    gidx: u64,
    tx_pubkey: [u8; 32],
    flags: u8,
    amount: u64,
    add_keys: Vec<[u8; 32]>,
    major: u32,
    minor: u32,
}

fn synth_plain(recs: &[SynthRec]) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0x01); // has_transfers
    push_varint(&mut p, 0); // offset
    push_varint(&mut p, recs.len() as u64); // total
    push_varint(&mut p, recs.len() as u64); // record_count (loop bound)
    for r in recs {
        push_varint(&mut p, 1); // version (ignored)
        p.extend_from_slice(&r.pubkey);
        push_varint(&mut p, r.idx);
        push_varint(&mut p, r.gidx);
        p.extend_from_slice(&r.tx_pubkey);
        p.push(r.flags);
        push_varint(&mut p, r.amount);
        push_varint(&mut p, r.add_keys.len() as u64);
        for k in &r.add_keys {
            p.extend_from_slice(k);
        }
        push_varint(&mut p, r.major as u64);
        push_varint(&mut p, r.minor as u64);
    }
    p
}

fn encrypt_request(view_sk: &[u8; 32], plain: &[u8], seed: u64) -> Vec<u8> {
    use rand_chacha::rand_core::SeedableRng as _;
    let spend_pub = point(&{
        // spend_pub is only envelope metadata here; use the disk session's
        let s = disk_session();
        *s.monero().spend_sk.expose()
    });
    let view_pub = point(view_sk);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
    let mut buf = vec![0u8; 4096];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let n = encrypt_export_payload_into(
        OUTPUT_EXPORT_MAGIC,
        view_sk,
        &spend_pub,
        &view_pub,
        0u32,
        plain,
        &mut rng,
        &mut buf,
        &mut cn,
    )
    .unwrap();
    buf.truncate(n);
    buf
}

/// (key_image, ring_signature) records produced by the chain run.
type KeyImageRecords = Vec<([u8; 32], [u8; 64])>;

/// Run the product chain core on a request container; returns Ok(records) or
/// the error kind string.
fn run_chain(
    req: &[u8],
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
) -> Result<KeyImageRecords, String> {
    let mut scratch = vec![0u8; 2048];
    let mut details: [ExportedTransferDetail; 8] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    let mut recs = [([0u8; 32], [0u8; 64]); 8];
    let mut out = vec![0u8; 8192];
    let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let mut rng = {
        use rand_chacha::rand_core::SeedableRng as _;
        rand_chacha::ChaCha20Rng::seed_from_u64(0xC0FFEE)
    };
    let n = generate_key_image_export_into(
        view_sk,
        spend_sk,
        req,
        &mut scratch,
        &mut details,
        &mut recs,
        &mut out,
        &mut rng,
        &mut cn,
    )
    .map_err(|e| format!("{e:?}"))?;
    let count = (n - (KEY_IMAGE_EXPORT_MAGIC.len() + 8 + 4 + 64 + 64)) / KEY_IMAGE_RECORD_LEN;
    Ok(recs[..count].to_vec())
}

#[test]
fn prying_surface_additional_tx_keys_and_amount_zero() {
    let session = disk_session();
    let keys = session.monero();
    let spend_sk = *keys.spend_sk.expose();
    let view_sk = *keys.view_sk.expose();
    assert_eq!(hex(&view_sk), KNOWN_VIEW_SK, "derivation-chain guard");

    // ── case A: subaddress output with TWO additional tx keys ────────────────
    // wallet2 v0.18.4 semantics (`is_out_to_acc_precomp`): the main derivation
    // is tried first, then additional_derivations[real_output_index] — indexed
    // by the INTERNAL OUTPUT INDEX (lookup_acc_outs enforces
    // additional_tx_pub_keys.size() == tx.vout.size()). shlosilo/keystone select
    // additional_tx_keys[internal_output_index] directly: same key for any
    // well-formed export.
    // additional tx keys are real ed25519 points (R' = r·G) — arbitrary 32B
    // values fail the decompress inside calc_output_key_offset (a malformed add
    // key surfaces at key-image time, not at parse time — noted in the report).
    let k0 = point(&[0xA0u8; 32]);
    let k1 = point(&[0xA1u8; 32]);
    let tx_pub = point(&[0x42u8; 32]);
    let idx = 1u64;
    // The output is a subaddress (1,0) output derived FROM k1 (the additional
    // key at its internal index), not from tx_pub.
    let offset = calc_output_key_offset(&view_sk, &k1, idx, 1, 0).unwrap();
    let input_sk = Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(offset);
    let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();

    let rec_a = SynthRec {
        pubkey: out_pub,
        idx,
        gidx: 7,
        tx_pubkey: tx_pub,
        flags: 0b0001_0100, // rct + key_image_request
        amount: 0,
        add_keys: vec![k0, k1],
        major: 1,
        minor: 0,
    };

    // ── case B: amount=0 / rct flag, main address, no request bit ───────────
    let offset_b = calc_output_key_offset(&view_sk, &tx_pub, 0, 0, 0).unwrap();
    let input_sk_b =
        Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(offset_b);
    let out_pub_b = (ED25519_BASEPOINT_TABLE * &input_sk_b)
        .compress()
        .to_bytes();
    let rec_b = SynthRec {
        pubkey: out_pub_b,
        idx: 0,
        gidx: 8,
        tx_pubkey: tx_pub,
        flags: 0b0000_0100, // rct only — NO key_image_request
        amount: 0,          // rct real amount hidden
        add_keys: vec![],
        major: 0,
        minor: 0,
    };

    let plain = synth_plain(&[rec_a, rec_b]);
    let req = encrypt_request(&view_sk, &plain, 0x99);
    let recs = run_chain(&req, &view_sk, &spend_sk)
        .expect("chain must handle add-keys subaddress output + amount=0/rct variant");

    // case A image must come from the ADDITIONAL key at the internal index —
    // computing with tx_pubkey instead would not reproduce out_pub.
    let wrong_offset = calc_output_key_offset(&view_sk, &tx_pub, idx, 1, 0).unwrap();
    let wrong_sk =
        Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(wrong_offset);
    let wrong_pub = (ED25519_BASEPOINT_TABLE * &wrong_sk).compress().to_bytes();
    assert_ne!(
        wrong_pub, out_pub,
        "fixture check: tx_pubkey derivation must NOT reproduce the subaddress output"
    );
    let hp_a: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub).into();
    let expect_a: [u8; 32] = (hp_a * input_sk).compress().to_bytes();
    assert_eq!(
        recs[0].0, expect_a,
        "subaddress image derives from additional_tx_keys[internal_output_index]"
    );
    assert!(
        verify_ki_sig(&expect_a, &out_pub, &input_sk, &recs[0].1),
        "add-key output signature verifies"
    );

    // case B: amount=0/rct with NO key_image_request bit — the chain computes
    // key images for ALL parsed outputs (no flag filtering, golden compat).
    let hp_b: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub_b).into();
    let expect_b: [u8; 32] = (hp_b * input_sk_b).compress().to_bytes();
    assert_eq!(recs.len(), 2, "no flag filtering: both outputs answered");
    assert_eq!(recs[1].0, expect_b, "amount=0/rct image still derived");
    println!(
        "case A (subaddr, 2 add keys, idx=1 → additional[1]) image = {}",
        hex(&expect_a)
    );
    println!(
        "case B (amount=0, rct, no ki_request bit)        image = {}",
        hex(&expect_b)
    );

    // ── case C: exactly ONE additional key with internal index > 0 ──────────
    // shlosilo/keystone: `len()==1 → additional[0]` shortcut accepts this.
    // wallet2 v0.18.4 would reject (`output_index < additional_derivations.size()`
    // fails when idx>0 and only 1 derivation) — documented divergence: we are
    // strictly MORE permissive than wallet2 here, on data wallet2 cannot emit.
    let only = point(&[0xB0u8; 32]);
    let idx_c = 3u64;
    let off_c = calc_output_key_offset(&view_sk, &only, idx_c, 2, 5).unwrap();
    let sk_c = Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(off_c);
    let pub_c = (ED25519_BASEPOINT_TABLE * &sk_c).compress().to_bytes();
    let rec_c = SynthRec {
        pubkey: pub_c,
        idx: idx_c,
        gidx: 9,
        tx_pubkey: tx_pub,
        flags: 0b0001_0100,
        amount: 15_000_000_000,
        add_keys: vec![only],
        major: 2,
        minor: 5,
    };
    let plain_c = synth_plain(&[rec_c]);
    let req_c = encrypt_request(&view_sk, &plain_c, 0x11);
    let recs_c = run_chain(&req_c, &view_sk, &spend_sk).expect(
        "len==1 shortcut: additional[0] used regardless of internal index (keystone parity)",
    );
    let hp_c: curve25519_dalek::EdwardsPoint = Point::biased_hash(pub_c).into();
    assert_eq!(recs_c[0].0, (hp_c * sk_c).compress().to_bytes());

    // ── case D: two additional keys, internal index out of range ────────────
    // wallet2: `is_out_to_acc_precomp` → "wrong number of additional
    // derivations" → generate_key_image_helper returns false → export aborts.
    // keystone: panics. shlosilo: explicit error (no panic on a signer).
    let off_d = calc_output_key_offset(&view_sk, &k1, 5, 1, 0).unwrap();
    let sk_d = Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(off_d);
    let pub_d = (ED25519_BASEPOINT_TABLE * &sk_d).compress().to_bytes();
    let rec_d = SynthRec {
        pubkey: pub_d,
        idx: 5, // >= 2 additional keys
        gidx: 10,
        tx_pubkey: tx_pub,
        flags: 0b0001_0100,
        amount: 1,
        add_keys: vec![k0, k1],
        major: 1,
        minor: 0,
    };
    let plain_d = synth_plain(&[rec_d]);
    let req_d = encrypt_request(&view_sk, &plain_d, 0x22);
    let err = run_chain(&req_d, &view_sk, &spend_sk)
        .expect_err("out-of-range additional key index must error (wallet2 also aborts)");
    println!("case D (idx=5 over 2 add keys) rejected: {err}");
}

/// Mainnet regression pin (2026-10-16): the wild failing case -- a request
/// container with offset=1. The key-image response plaintext field 1 (u32 LE,
/// right after the nonce in the cipher) MUST echo the request offset: wallet2's
/// import_key_images maps records onto `m_transfers[offset + n]`; the old
/// hardcoded 0 pinned the record to transfer 0 and the signature was checked
/// against the wrong pubkey ("Signature check failed 0/1" on mainnet).
///
/// Decrypt-free differential pin: run the pairing twice over identical
/// records with request offset 1 vs 0 and the SAME response RNG seed -- the
/// responses must be identical EXCEPT the 4 offset bytes in the cipher
/// (magic + nonce identical because the seed is fixed). With the old
/// hardcoded 0 the two responses are fully equal (this test goes RED).
#[test]
fn failing_case_offset_echo() {
    use rand_chacha::rand_core::SeedableRng as _;
    let session = disk_session();
    let keys = session.monero();
    let spend_sk = *keys.spend_sk.expose();
    let view_sk = *keys.view_sk.expose();

    // Wild capture (v2): 2-transfer wallet, request offset=1.
    let path = format!(
        "{}/tests/fixtures/cake_real_frames_v2.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("v2 frames fixture");
    let frames: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ur:"))
        .collect();
    let mut dec = UrMultipartDecoder::new();
    for f in &frames {
        dec.receive_frame(f).expect("frame feeds");
    }
    assert!(dec.complete());
    let mut msg = vec![0u8; 16384];
    let n = dec.payload_into(&mut msg).unwrap().expect("complete");
    let container = msg[..n].to_vec();

    // Request A = the wild bytes; request B = same plaintext with offset 0.
    let (_a, _b, plain_a) =
        decrypt_export_payload(&container, OUTPUT_EXPORT_MAGIC, &view_sk).expect("decrypt request");
    let mut plain_b = plain_a.clone();
    assert_eq!(
        plain_b[1], 1,
        "wild request head: [has_transfers=1][offset=1]"
    );
    plain_b[1] = 0;
    let req_a = encrypt_request(&view_sk, &plain_a, 0xA1);
    let req_b = encrypt_request(&view_sk, &plain_b, 0xA2);

    let run = |req: &Vec<u8>| {
        let mut scratch = vec![0xEEu8; 4096];
        let mut details: [shlosilo::chain::xmr::output_export::ExportedTransferDetail; 8] =
            core::array::from_fn(|_| Default::default());
        let mut recs = [([0u8; 32], [0u8; 64]); 8];
        let mut out = vec![0u8; 4096];
        let mut cn = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xF1CE);
        let n = generate_key_image_export_into(
            &view_sk,
            &spend_sk,
            req,
            &mut scratch,
            &mut details,
            &mut recs,
            &mut out,
            &mut rng,
            &mut cn,
        )
        .expect("pairing run");
        out[..n].to_vec()
    };
    let resp_a = run(&req_a);
    let resp_b = run(&req_b);

    // Header = 24B magic + 8B nonce; the cipher starts at 32 and its first 4
    // bytes are the echoed offset.
    assert_eq!(resp_a.len(), resp_b.len(), "same shape");
    assert_eq!(
        resp_a[..32],
        resp_b[..32],
        "magic + nonce identical (fixed seed)"
    );
    assert_ne!(
        resp_a[32..36],
        resp_b[32..36],
        "THE PIN: the response offset field must follow the request offset"
    );
    // Body before the trailing 64 B envelope signature must be identical:
    // pk1||pk2||records cipher. (The envelope Schnorr sig legitimately
    // differs -- it signs the ciphertext, which contains the offset bytes.)
    let body = resp_a.len() - 64;
    assert_eq!(
        resp_a[36..body],
        resp_b[36..body],
        "pk1/pk2/records identical -- only the offset differs"
    );
}
