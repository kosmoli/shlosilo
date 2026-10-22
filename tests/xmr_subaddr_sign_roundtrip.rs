//! Signing-path subaddress input derivation × wallet2 gold (2026-10-16, tx2
//! regression: signed_txset rejected by wallet2 parse on Cake).
//!
//! The key-image path got wallet2-faithful candidate matching in 03fb977
//! (main tx key first, then indexed additional key, match by x*G against the
//! record pubkey). The SIGNING path (`derive_input_from_source`,
//! forms/chain/xmr/subaddress.rs) still uses the old rule: pick
//! additional_tx_keys[real_output_in_tx_index] when any additional key exists.
//! For a change-to-own-subaddress output (derived from the MAIN tx key even
//! when additional keys exist — device_default.cpp change_addr branch,
//! cryptonote_tx_utils.cpp) that rule derives the wrong input_sk and the
//! input_pub gate rejects the input outright.
//!
//! > STATUS 2026-10-21: both pins in this file FLIPPED GREEN (`cc777c5` derivation matching, `c3a5a00` BP+ scratch) — the red contract below is history.
//!
//! `pin_red_…` was INTENTIONALLY RED (the pinned divergence, not fixed here —
//! see ~/works/xmr-stagenet-lab/watchonly_probe/SIGNED_TX_PARSE_FAIL_REPORT.md).
//! The two `control_…` tests are green and prove the harness is sound.
#![cfg(feature = "alloc-fallback")]

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use monero_ed25519::Commitment as MonCommitment;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use shlosilo::chain::xmr::subaddress::calc_output_key_offset;
use shlosilo::chain::xmr::tx_signer::sign_tx_from_construction_with_rngs;
use shlosilo::chain::xmr::unsigned_txset::{
    MultisigKLRki, OutputEntry, RctConfig, TxConstructionData, TxDestinationEntry, TxSourceEntry,
};
use shlosilo::types::{SecretBytes, SliceVec};

fn point(sk: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*sk))
        .compress()
        .to_bytes()
}

fn dalek(x: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*x)
}

fn monero_pub(s: &Scalar) -> [u8; 32] {
    (ED25519_BASEPOINT_TABLE * s).compress().to_bytes()
}

/// x = spend + calc_output_key_offset(view, tx_pub, idx, major, minor)
fn one_time_x(
    spend_sk: &[u8; 32],
    view_sk: &[u8; 32],
    tx_pub: &[u8; 32],
    idx: u64,
    major: u32,
    minor: u32,
) -> Scalar {
    let off = calc_output_key_offset(view_sk, tx_pub, idx, major, minor).unwrap();
    dalek(spend_sk) + dalek(&off)
}

/// wallet2 expected key image for a real output P with one-time secret x
fn wallet2_image(out_pub: &[u8; 32], x: &Scalar) -> [u8; 32] {
    let hp: curve25519_dalek::EdwardsPoint = monero_ed25519::Point::biased_hash(*out_pub).into();
    (hp * x).compress().to_bytes()
}

/// Minimal tx-prefix walk: version, unlock_time, vin[] → first key image.
fn first_key_image(tx: &[u8]) -> [u8; 32] {
    eprintln!(
        "tx head: {}",
        tx[..24.min(tx.len())]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
    fn varint(b: &[u8], pos: &mut usize) -> u64 {
        let mut v = 0u64;
        let mut shift = 0;
        loop {
            let c = b[*pos];
            *pos += 1;
            v |= ((c & 0x7f) as u64) << shift;
            if c & 0x80 == 0 {
                return v;
            }
            shift += 7;
        }
    }
    let mut pos = 0;
    assert_eq!(varint(tx, &mut pos), 2, "tx version 2");
    let _unlock = varint(tx, &mut pos);
    let n_in = varint(tx, &mut pos);
    assert_eq!(n_in, 1, "single input");
    assert_eq!(tx[pos], 0x02, "txin_to_key tag");
    pos += 1;
    let _amount = varint(tx, &mut pos); // RCT inputs carry amount=0 before the offsets
    let n_off = varint(tx, &mut pos);
    for _ in 0..n_off {
        let _rel = varint(tx, &mut pos);
    }
    let mut ki = [0u8; 32];
    ki.copy_from_slice(&tx[pos..pos + 32]);
    ki
}

/// Build the full construction data around one synthetic source. Ring = 2
/// members (real at slot 0), amount 1000, one destination of 900 (fee 100).
fn sign_shape(
    spend_sk: &[u8; 32],
    view_sk: &[u8; 32],
    source: TxSourceEntry,
    subaddr_account: u32,
    subaddr_indices: &[u32],
) -> Result<Vec<u8>, shlosilo::error::ShlosiloError> {
    // destination: any decompressible point pair (external main address)
    let dest = TxDestinationEntry {
        original: heapless::Vec::new(),
        amount: 900,
        spend_public_key: point(&[0x77u8; 32]),
        view_public_key: point(&[0x78u8; 32]),
        is_subaddress: false,
        is_integrated: false,
    };
    let mut t_src = [None; 1];
    let mut t_src_f = SliceVec::new(&mut t_src);
    t_src_f.push(Some(source)).unwrap();
    let mut t_sd =
        core::array::from_fn::<TxDestinationEntry, 1, _>(|_| TxDestinationEntry::default());
    let mut t_sd_f = SliceVec::new(&mut t_sd);
    t_sd_f.push(dest.clone()).unwrap();
    let mut t_sel = [0usize; 1];
    let mut t_sel_f = SliceVec::new(&mut t_sel);
    t_sel_f.push(0usize).unwrap();
    let mut t_extra: [u8; 0] = [];
    let mut t_dests: [TxDestinationEntry; 0] = [];
    let mut t_sub_buf = [0u32; 8];
    let mut t_sub = SliceVec::new(&mut t_sub_buf);
    for &i in subaddr_indices {
        t_sub.push(i).unwrap();
    }
    let tx_data = TxConstructionData {
        sources: t_src_f,
        change_dts: dest.clone(),
        splitted_dsts: t_sd_f,
        selected_transfers: t_sel_f,
        extra: SliceVec::new(&mut t_extra),
        unlock_time: 0,
        use_rct: 1,
        rct_config: RctConfig::default(),
        dests: SliceVec::new(&mut t_dests),
        subaddr_account,
        subaddr_indices: t_sub,
    };
    let mut bp_rng = ChaCha20Rng::seed_from_u64(0x51);
    let mut clsag_rng = ChaCha20Rng::seed_from_u64(0x52);
    let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
    sign_tx_from_construction_with_rngs(
        &tx_data,
        spend_sk,
        view_sk,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
    )
}

/// Synthetic source: real output P at creating-tx index `real_idx`, ring of 2.
/// `derive_pub` is the curve point the SENDER actually derived P from.
fn build_source(out_pub: [u8; 32], real_idx: u64, add_keys: &[[u8; 32]]) -> TxSourceEntry {
    let real_mask = [0x66u8; 32];
    use shlosilo::chain::xmr::transaction::bytes_to_monerod_scalar;
    let c_real = MonCommitment::new(bytes_to_monerod_scalar(&real_mask), 1000)
        .commit()
        .compress()
        .to_bytes();
    let c_decoy = MonCommitment::new(bytes_to_monerod_scalar(&[0x67u8; 32]), 1000)
        .commit()
        .compress()
        .to_bytes();
    TxSourceEntry {
        outputs: heapless::Vec::from_slice(&[
            OutputEntry {
                index: 50,
                dest: out_pub,
                mask: c_real,
            },
            OutputEntry {
                index: 60,
                dest: point(&[0x33u8; 32]),
                mask: c_decoy,
            },
        ])
        .unwrap(),
        real_output: 0,
        real_out_tx_key: zeroize::Zeroizing::new(point(&[0x42u8; 32])),
        real_out_additional_tx_keys: {
            let mut v: heapless::Vec<zeroize::Zeroizing<[u8; 32]>, 8> = heapless::Vec::new();
            for k in add_keys {
                v.push(zeroize::Zeroizing::new(*k)).unwrap();
            }
            v
        },
        real_output_in_tx_index: real_idx,
        amount: 1000,
        rct: true,
        mask: SecretBytes::new(real_mask),
        multisig_kLRki: MultisigKLRki {
            k: [0; 32],
            l: [0; 32],
            r: [0; 32],
            ki: [0; 32],
        },
    }
}

// ─── the pinned divergence ───────────────────────────────────────────────────

/// Shape: one tx paying an external subaddress with change to the wallet's own
/// subaddress (1,0). The creating tx has additional keys [k0, k1] but the
/// CHANGE output is main-tx-key derived (wallet2 device_default.cpp change_addr
/// branch). Spending that output: wallet2 re-derives it via the MAIN tx key
/// (is_out_to_acc_precomp branch 1); our signing path picks
/// additional_tx_keys[real_output_in_tx_index] and the input_pub gate rejects.
///
/// This is the tx2 (subaddress-input) regression pinned red on the SIGN path.
#[test]
fn sign_path_change_to_own_subaddress_uses_main_txkey() {
    let spend_sk = [5u8; 32];
    let view_sk = [6u8; 32];
    let tx_pub = point(&[0x42u8; 32]); // MAIN tx key
    let k0 = point(&[0xA0u8; 32]);
    let k1 = point(&[0xA1u8; 32]);
    let real_idx = 1u64;
    // wallet2 sender semantics: change to own subaddress (1,0) derives from
    // the MAIN tx key + the subaddress base m(1,0):
    let x = one_time_x(&spend_sk, &view_sk, &tx_pub, real_idx, 1, 0);
    let out_pub = monero_pub(&x);
    let source = build_source(out_pub, real_idx, &[k0, k1]);

    let result = std::panic::catch_unwind(|| sign_shape(&spend_sk, &view_sk, source, 1, &[0]));
    let tx = match result {
        Ok(Ok(tx)) => tx,
        Ok(Err(_)) => panic!(
            "PINNED RED: sign path REJECTED the change-to-own-subaddress input — \
             derive_input_from_source still picks additional_tx_keys[real_output_in_tx_index] \
             (the pre-03fb977 rule) while wallet2 re-derives this shape via the MAIN tx key \
             (device_default.cpp change_addr branch, matched via is_out_to_acc_precomp branch 1). \
             Fix = the same wallet2-faithful candidate matching as the key-image path"
        ),
        Err(_) => panic!("PINNED RED: sign path panicked on change-to-own-subaddress input"),
    };
    // If we get here the sign path accepted the input: the key image must be
    // the wallet2 one (over the MAIN-tx-key one-time secret).
    assert_eq!(
        first_key_image(&tx),
        wallet2_image(&out_pub, &x),
        "key image must be x·Hp(P) with x from the MAIN tx key derivation"
    );
}

// ─── green controls (harness soundness) ─────────────────────────────────────

/// Same subaddress (1,0) output, but NO additional keys and main-tx-key
/// derivation (wallet2 branch 1, keyimage probe case (d)). Must sign.
#[test]
fn control_sign_path_main_txkey_subaddr_no_addkeys() {
    let spend_sk = [5u8; 32];
    let view_sk = [6u8; 32];
    let tx_pub = point(&[0x42u8; 32]);
    let real_idx = 1u64;
    let x = one_time_x(&spend_sk, &view_sk, &tx_pub, real_idx, 1, 0);
    let out_pub = monero_pub(&x);
    let source = build_source(out_pub, real_idx, &[]);
    let tx = sign_shape(&spend_sk, &view_sk, source, 1, &[0]).expect("sign (no add keys)");
    assert_eq!(first_key_image(&tx), wallet2_image(&out_pub, &x));
}

/// External subaddress output with additional tx keys (2 keys, idx 1 →
/// additional[1]; wallet2 branch 2). Must sign.
#[test]
fn control_sign_path_subaddr_via_additional_idx() {
    let spend_sk = [5u8; 32];
    let view_sk = [6u8; 32];
    let k0 = point(&[0xA0u8; 32]);
    let k1 = point(&[0xA1u8; 32]);
    let real_idx = 1u64;
    let x = one_time_x(&spend_sk, &view_sk, &k1, real_idx, 1, 0);
    let out_pub = monero_pub(&x);
    let source = build_source(out_pub, real_idx, &[k0, k1]);
    let tx = sign_shape(&spend_sk, &view_sk, source, 1, &[0]).expect("sign (additional[1])");
    assert_eq!(first_key_image(&tx), wallet2_image(&out_pub, &x));
}

// ─── pinned red: BP aggregation scratch OOB on non-pow2 output counts ───────

/// Three signed outputs (2 payees + change — the real shape of
/// `signed_rt/fd/unsigned_monero_tx`, 2026-10-16) overflow the vendored
/// monero-bulletproofs A-terms scratch: `a_terms_len = mn*2+1` is computed
/// from the UNPADDED commitment count (mn = V.len()*64) while `a_l/a_r`
/// iterate `padded_pow_of_2(mn)` scalars —
/// vendor/monero-bulletproofs/src/plus/aggregate_range_proof.rs:323-374.
/// 2- and 4-output txs sign fine (FC / FD2 fixtures round-tripped through
/// wallet2 parse); the 3-output real fixture panics
/// "index out of bounds: the len is 385 but the index is 385".
#[test]
fn sign_three_outputs_bp_scratch_in_bounds() {
    fn dest(amount: u64, tag: u8) -> TxDestinationEntry {
        TxDestinationEntry {
            original: heapless::Vec::new(),
            amount,
            spend_public_key: point(&[0x77u8.wrapping_add(tag); 32]),
            view_public_key: point(&[0x88u8.wrapping_add(tag); 32]),
            is_subaddress: false,
            is_integrated: false,
        }
    }
    fn sign_n(
        spend_sk: [u8; 32],
        view_sk: [u8; 32],
        source: TxSourceEntry,
        n: usize,
    ) -> Result<Vec<u8>, shlosilo::error::ShlosiloError> {
        let dests: Vec<TxDestinationEntry> = (0..n).map(|i| dest(300, i as u8)).collect();
        let mut t_src = [None; 1];
        let mut t_src_f = SliceVec::new(&mut t_src);
        t_src_f.push(Some(source)).unwrap();
        let mut t_sd: Vec<TxDestinationEntry> =
            (0..n).map(|_| TxDestinationEntry::default()).collect();
        let mut t_sd_f = SliceVec::new(&mut t_sd);
        for d in &dests {
            t_sd_f.push(d.clone()).unwrap();
        }
        let mut t_sel = [0usize; 1];
        let mut t_sel_f = SliceVec::new(&mut t_sel);
        t_sel_f.push(0usize).unwrap();
        let mut t_extra: [u8; 0] = [];
        let mut t_dests: [TxDestinationEntry; 0] = [];
        let mut t_sub_buf = [0u32; 8];
        let mut t_sub = SliceVec::new(&mut t_sub_buf);
        t_sub.push(0u32).unwrap();
        let tx_data = TxConstructionData {
            sources: t_src_f,
            change_dts: dests[0].clone(),
            splitted_dsts: t_sd_f,
            selected_transfers: t_sel_f,
            extra: SliceVec::new(&mut t_extra),
            unlock_time: 0,
            use_rct: 1,
            rct_config: RctConfig::default(),
            dests: SliceVec::new(&mut t_dests),
            subaddr_account: 0,
            subaddr_indices: t_sub,
        };
        let mut bp_rng = ChaCha20Rng::seed_from_u64(0x53);
        let mut clsag_rng = ChaCha20Rng::seed_from_u64(0x54);
        let r_bytes = zeroize::Zeroizing::new([0x77u8; 32]);
        sign_tx_from_construction_with_rngs(
            &tx_data,
            &spend_sk,
            &view_sk,
            &r_bytes,
            &mut bp_rng,
            &mut clsag_rng,
        )
    }
    let spend_sk = [5u8; 32];
    let view_sk = [6u8; 32];
    let tx_pub = point(&[0x42u8; 32]);
    let real_idx = 1u64;
    let x = one_time_x(&spend_sk, &view_sk, &tx_pub, real_idx, 0, 0);
    let out_pub = monero_pub(&x);
    // green differential: 4 outputs (pow2) must sign on the same harness
    let source4 = build_source(out_pub, real_idx, &[]);
    let four = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sign_n(spend_sk, view_sk, source4, 4)
    }));
    assert!(
        matches!(four, Ok(Ok(ref t)) if !t.is_empty()),
        "harness control: the 4-output (pow2) shape must sign (got {four:?})"
    );
    // red pin: 3 outputs (non-pow2) — real signed_rt/fd fixture shape
    let source3 = build_source(out_pub, real_idx, &[]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sign_n(spend_sk, view_sk, source3, 3)
    }));
    match result {
        Err(_) => panic!(
            "PINNED RED: 3-output signing PANICKED in the vendored bulletproofs aggregate \
             range proof (scratch index OOB) — a_terms_len is sized from the UNPADDED \
             commitment count while a_l/a_r iterate padded_pow_of_2(mn) scalars \
             (vendor/monero-bulletproofs/src/plus/aggregate_range_proof.rs:323-374)"
        ),
        Ok(Ok(tx)) => assert!(
            !tx.is_empty(),
            "3-output tx must sign once the scratch sizing is fixed"
        ),
        Ok(Err(e)) => panic!(
            "PINNED RED: 3-output sign failed while the 4-output control signs \
             (scratch sized from the unpadded commitment count — \
             aggregate_range_proof.rs:323-374): {e:?}"
        ),
    }
}

// ─── host tool: tx_key placeholder → real scalar control container ──────────

/// Patch the ptx `tx_key` slot (our forced `Scalar::ONE` placeholder) in an
/// OUR-signed container to caller-supplied 32B and re-encrypt the envelope —
/// the wallet2-parse control for "does the tx_key slot value matter to
/// sanity_check_pending_tx" (suspect #3, §10 of SIGNED_TX_PARSE_FAIL_REPORT).
///
/// Run:
///   DUMP_IN=ours_signed.bin DUMP_OUT=patched.bin PATCH_TXKEY_HEX=<32B hex> \
///   SHLOSILO_TEST_XMR_VIEW_SK=... \
///   cargo test --release --test xmr_subaddr_sign_roundtrip -- --ignored --nocapture \
///   patch_ptx_txkey_reencrypt
#[test]
#[ignore = "host tool: patch the ptx tx_key placeholder and re-encrypt"]
fn patch_ptx_txkey_reencrypt() {
    use shlosilo::chain::xmr::signed_txset::{decrypt_signed_txset, encrypt_signed_txset};
    fn env_hex(name: &str) -> Option<[u8; 32]> {
        let s = std::env::var(name).ok()?;
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Some(v.try_into().unwrap())
    }
    let inn = std::env::var("DUMP_IN").expect("set DUMP_IN");
    let out = std::env::var("DUMP_OUT").expect("set DUMP_OUT");
    let view_sk = env_hex("SHLOSILO_TEST_XMR_VIEW_SK").expect("set SHLOSILO_TEST_XMR_VIEW_SK");
    let patch = env_hex("PATCH_TXKEY_HEX").expect("set PATCH_TXKEY_HEX");
    let blob = std::fs::read(&inn).expect("read container");
    let plain = decrypt_signed_txset(&blob, &view_sk).expect("decrypt container");
    let one = Scalar::ONE.to_bytes();
    let mut found: Vec<usize> = Vec::new();
    for i in 0..=plain.len().saturating_sub(32) {
        if plain[i..i + 32] == one {
            found.push(i);
        }
    }
    println!("Scalar::ONE 32B slots in plaintext: {found:?}");
    assert_eq!(
        found.len(),
        1,
        "expected exactly one tx_key placeholder slot"
    );
    let pos = found[0];
    let mut p = plain.to_vec();
    p[pos..pos + 32].copy_from_slice(&patch);
    let mut rng = ChaCha20Rng::seed_from_u64(0x43);
    let sealed = encrypt_signed_txset(p, &view_sk, &mut rng).expect("re-encrypt");
    std::fs::write(&out, &sealed).expect("write patched container");
    println!(
        "{out}: patched container {} bytes (tx_key slot @ {pos})",
        sealed.len()
    );
}

// ─── host tool: container plaintext dump for the gold-vs-ours diff ──────────

/// Decrypt a signed container (ours OR wallet2's gold — same envelope family)
/// and dump the plaintext for structural comparison.
///
/// Run:
///   DUMP_IN=<container> DUMP_OUT=<plain> SHLOSILO_TEST_XMR_VIEW_SK=... \
///   cargo test --release --test xmr_subaddr_sign_roundtrip -- --ignored --nocapture \
///   dump_signed_container_plain
#[test]
#[ignore = "host tool: decrypt a signed container and dump its plaintext"]
fn dump_signed_container_plain() {
    use shlosilo::chain::xmr::signed_txset::decrypt_signed_txset;
    fn env_hex(name: &str) -> Option<[u8; 32]> {
        let s = std::env::var(name).ok()?;
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Some(v.try_into().unwrap())
    }
    let inn = std::env::var("DUMP_IN").expect("set DUMP_IN");
    let out = std::env::var("DUMP_OUT").expect("set DUMP_OUT");
    let view_sk = env_hex("SHLOSILO_TEST_XMR_VIEW_SK").expect("set SHLOSILO_TEST_XMR_VIEW_SK");
    let blob = std::fs::read(&inn).expect("read container");
    let plain = decrypt_signed_txset(&blob, &view_sk).expect("decrypt container");
    println!(
        "{inn}: container {} bytes -> plaintext {} bytes",
        blob.len(),
        plain.len()
    );
    std::fs::write(&out, &plain).expect("write plaintext");
}

// ─── host tool: real fixture round-trip for the wallet2 gold compare ────────

/// Sign a REAL wallet2 `unsigned_monero_tx` fixture on the host and dump both
/// the raw tx (for monerod send_raw_transaction) and the encrypted signed
/// container (for wallet-cli submit_transfer), byte-identical to the device
/// output path (business::sign::sign_with_entropy).
///
/// Run:
///   P64_FIXTURE_PATH=<unsigned_monero_tx> \
///   SHLOSILO_TEST_XMR_SPEND_SK=... SHLOSILO_TEST_XMR_VIEW_SK=... \
///   P64_RAWTX_OUT=/tmp/ours_raw_tx.bin P64_SIGNED_OUT=/tmp/ours_signed.bin \
///   cargo test --release --test xmr_subaddr_sign_roundtrip -- --ignored --nocapture \
///   sign_real_fixture_for_wallet2_compare
#[test]
#[ignore = "host tool: real fixture → raw tx + signed container for the wallet2 gold compare"]
fn sign_real_fixture_for_wallet2_compare() {
    use shlosilo::business::sign::{sign_with_entropy, SignInput};
    use shlosilo::chain::xmr::unsigned_txset::{decrypt_unsigned_txset, deserialize_unsigned_tx};
    use shlosilo::entropy::mnemonic::Mnemonic;
    use shlosilo::ur::ur_encode::UrTypeTag;

    fn env_hex(name: &str) -> Option<[u8; 32]> {
        let s = std::env::var(name).ok()?;
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Some(v.try_into().unwrap())
    }

    let fixture_path = std::env::var("P64_FIXTURE_PATH").expect("set P64_FIXTURE_PATH");
    let enc = std::fs::read(&fixture_path).expect("read fixture");
    let (Some(view_sk), Some(spend_sk)) = (
        env_hex("SHLOSILO_TEST_XMR_VIEW_SK"),
        env_hex("SHLOSILO_TEST_XMR_SPEND_SK"),
    ) else {
        panic!("set SHLOSILO_TEST_XMR_SPEND_SK / _VIEW_SK");
    };

    // Parse + sign the raw tx via the chain core (exact input_sk derivation
    // under test).
    let plain = decrypt_unsigned_txset(&enc, &view_sk).expect("decrypt unsigned");
    let mut p_txes = core::array::from_fn::<
        Option<shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'_>>,
        8,
        _,
    >(|_| None);
    let mut p_src = core::array::from_fn::<Option<TxSourceEntry>, 32, _>(|_| None);
    let mut p_sd =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_sel = [0usize; 256];
    let mut p_ex = [0u8; 8192];
    let mut p_de =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut p_su = [0u32; 256];
    let utx = deserialize_unsigned_tx(
        &plain,
        shlosilo::chain::xmr::unsigned_txset::UnsignedTxPools {
            txes: &mut p_txes,
            sources: &mut p_src,
            splitted_dsts: &mut p_sd,
            selected_transfers: &mut p_sel,
            extra: &mut p_ex,
            dests: &mut p_de,
            subaddr_indices: &mut p_su,
        },
    )
    .expect("deserialize unsigned");
    for (i, tx_data) in utx.txes.iter().flatten().enumerate() {
        println!(
            "tx[{i}]: sources={} dsts={} subaddr_account={} subaddr_indices={:?}",
            tx_data.sources.len(),
            tx_data.splitted_dsts.iter().count(),
            tx_data.subaddr_account,
            tx_data.subaddr_indices.iter().copied().collect::<Vec<_>>()
        );
        for (j, s) in tx_data.sources.iter().flatten().enumerate() {
            println!(
                "  src[{j}]: amount={} real_output={} real_idx={} ring={} add_keys={} tx_key={}",
                s.amount,
                s.real_output,
                s.real_output_in_tx_index,
                s.outputs.len(),
                s.real_out_additional_tx_keys.len(),
                s.real_out_tx_key
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
        }
        let mut rng = ChaCha20Rng::seed_from_u64(0x99);
        let t0 = std::time::Instant::now();
        let raw = sign_tx_from_construction_with_rngs(
            tx_data,
            &spend_sk,
            &view_sk,
            &zeroize::Zeroizing::new([0x77u8; 32]),
            &mut rng.clone(),
            &mut rng,
        )
        .expect("host sign");
        println!(
            "tx[{i}]: host sign {} ms, raw tx {} bytes",
            t0.elapsed().as_millis(),
            raw.len()
        );
        if let Ok(p) = std::env::var("P64_RAWTX_OUT") {
            std::fs::write(&p, &raw).expect("write raw tx");
            println!("raw tx -> {p}");
        }
    }

    // Full product path: business::sign → encrypted SignedTxSet container
    // (device-identical; the QR payload minus any CBOR/UR shell).
    let entropy = [0x22u8; 32]; // stage_disk / device disk keys
    let m = Mnemonic::from_entropy(&entropy).expect("mnemonic");
    // sanity: the mnemonic must derive the wallet keys we were given
    {
        let path = shlosilo::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
        let mut seed = [0u8; 64];
        shlosilo::business::restore_seed::restore_seed(&m, b"", &mut seed).expect("seed");
        let kp = shlosilo::derivation::monero_reduce_scalar::derive(&seed, &path).expect("derive");
        assert_eq!(
            shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv()),
            spend_sk,
            "mnemonic [0x22;32] must reproduce SHLOSILO_TEST_XMR_SPEND_SK"
        );
        assert_eq!(
            shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv()),
            view_sk,
            "mnemonic [0x22;32] must reproduce SHLOSILO_TEST_XMR_VIEW_SK"
        );
    }
    let mut out = vec![0u8; 65536];
    let n = sign_with_entropy(
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &enc,
        &[0x77u8; 32],
        &mut out,
    )
    .expect("business sign");
    println!("business signed container: {n} bytes");
    if let Ok(p) = std::env::var("P64_SIGNED_OUT") {
        std::fs::write(&p, &out[..n]).expect("write signed container");
        println!("signed container -> {p}");
    }
}
