//! CI regression pin (T-15 class): re-signing with a REUSED WipScratch must
//! be byte-identical under fixed entropy. The C-cut E stale-scratch bug
//! (`d[base+k] +=` over an unzeroed scratch region) produced INVALID proofs
//! from the second sign on, and slid past every gate: the byte pins sign once
//! with fresh scratch, and the zero-count receipt runs release-only (the
//! relation shadow in wip::prove is compiled out there).
//!
//! This test is deliberately NOT env-gated: the DEV test-wallet keys are
//! embedded fixture keys (same class as the p63 test vectors — not secrets).
//! In debug builds the wip::prove relation shadow additionally asserts the
//! P-relation on BOTH signs. The real-wallet zero-count receipt stays in
//! `xmr_sign_zero_alloc` (env-gated).

use rand_core::SeedableRng as _;

/// DEV test wallet spend secret key (fixture key, tests/fixtures/README).
const DEV_SPEND_SK: [u8; 32] = [
    0xd8, 0xcd, 0x34, 0xaf, 0xac, 0x38, 0xfe, 0x95, 0xa2, 0x04, 0x39, 0xc2, 0x73, 0x8c, 0xb5, 0xfa,
    0xc0, 0xad, 0x29, 0x97, 0xe8, 0x35, 0x16, 0x45, 0x4b, 0x70, 0x20, 0x33, 0xb3, 0xed, 0xa5, 0x03,
];
/// DEV test wallet view secret key (fixture key).
const DEV_VIEW_SK: [u8; 32] = [
    0xdd, 0x87, 0x2c, 0xe8, 0x67, 0x39, 0xd7, 0x8d, 0xf0, 0x71, 0xd7, 0xf9, 0xef, 0x72, 0x91, 0x3b,
    0xd5, 0xf3, 0xc2, 0xdb, 0x02, 0xcb, 0x55, 0x5c, 0x24, 0x4b, 0x07, 0x6e, 0xfa, 0x5a, 0x9a, 0x0f,
];

#[test]
fn xmr_sign_reuse_determinism() {
    use shlosilo::chain::xmr::tx_signer::sign_tx_from_construction_with_rngs_into;
    use shlosilo::chain::xmr::unsigned_txset::{
        deserialize_unsigned_tx, TxConstructionData, TxDestinationEntry, TxSourceEntry,
        UnsignedTxPools,
    };

    // fixture: the DEV-wallet 2-input encrypted txset — decrypted with the
    // view key, parsed into caller pools (deploy shape).
    const ENC: &[u8] = include_bytes!("fixtures/unsigned_txset_2in_dev.bin");
    let plain = shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset(ENC, &DEV_VIEW_SK)
        .expect("decrypt 2-input DEV fixture");
    let mut p_txes = core::array::from_fn::<Option<TxConstructionData<'_>>, 8, _>(|_| None);
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
        UnsignedTxPools {
            txes: &mut p_txes,
            sources: &mut p_src,
            splitted_dsts: &mut p_sd,
            selected_transfers: &mut p_sel,
            extra: &mut p_ex,
            dests: &mut p_de,
            subaddr_indices: &mut p_su,
        },
    )
    .expect("deserialize");
    let tx_data = utx.txes.iter().flatten().next().unwrap();

    let r_bytes = zeroize::Zeroizing::new([0x11u8; 32]);

    let mut out = vec![0u8; 65536];
    let mut bp_terms = vec![
        (
            curve25519_dalek::Scalar::ZERO,
            curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
        );
        shlosilo::types::caps::SIGN_WS_BP_TERMS
    ];
    let mut bp_straus_storage = vec![
        0u8;
        curve25519_dalek::scratch::StrausScratch::storage_bytes(
            shlosilo::types::caps::SIGN_WS_BP_TERMS
        )
    ];
    let mut bp_straus = curve25519_dalek::scratch::StrausScratch::new(
        &mut bp_straus_storage,
        shlosilo::types::caps::SIGN_WS_BP_TERMS,
    )
    .expect("sized storage");
    let mut wip_storage =
        vec![
            0u8;
            monero_bulletproofs::WipScratch::storage_bytes(shlosilo::types::caps::SIGN_WS_BP_TERMS)
        ];
    let mut wip_scratch = monero_bulletproofs::WipScratch::new(
        &mut wip_storage,
        shlosilo::types::caps::SIGN_WS_BP_TERMS,
    )
    .expect("wip storage");

    // sign #1
    let mut bp_rng = rand_chacha::ChaCha20Rng::from_seed([0xB1u8; 32]);
    let mut clsag_rng = rand_chacha::ChaCha20Rng::from_seed([0xC1u8; 32]);
    let n1 = sign_tx_from_construction_with_rngs_into(
        tx_data,
        &DEV_SPEND_SK,
        &DEV_VIEW_SK,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
        &mut out,
        &mut bp_terms,
        &mut bp_straus,
        &mut wip_scratch,
    )
    .expect("first sign");
    assert!(n1 > 0);
    let first = out[..n1].to_vec();

    // T-11 straus codegen A/B handle: the signed-blob digest printed under
    // `--nocapture` must be identical with and without the vendored
    // `straus-compact-codegen` codegen attributes (pure `inline(never)`).
    {
        let d = shlosilo::encoding::sha256::hash(&first).expect("sha256");
        let mut hx = String::with_capacity(64);
        for b in d.iter() {
            use core::fmt::Write as _;
            write!(&mut hx, "{b:02x}").expect("hex");
        }
        println!("t11_straus_ab digest: sha256={hx} len={}", first.len());
    }

    // sign #2: identical RNG seeds, SAME scratch stack (the reuse under test).
    let mut bp_rng = rand_chacha::ChaCha20Rng::from_seed([0xB1u8; 32]);
    let mut clsag_rng = rand_chacha::ChaCha20Rng::from_seed([0xC1u8; 32]);
    let n2 = sign_tx_from_construction_with_rngs_into(
        tx_data,
        &DEV_SPEND_SK,
        &DEV_VIEW_SK,
        &r_bytes,
        &mut bp_rng,
        &mut clsag_rng,
        &mut out,
        &mut bp_terms,
        &mut bp_straus,
        &mut wip_scratch,
    )
    .expect("second sign");
    assert_eq!(
        &out[..n2],
        &first[..],
        "Z6/T-15: reusing the WipScratch must be deterministic (byte-identical re-sign)"
    );
}
