//! Diagnostics: locate the failing step inside sign_tx_from_construction
use shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx;

const PLAIN: &[u8] = include_bytes!("fixtures/txset_plain.bin");

fn env_hex(name: &str) -> Option<[u8; 32]> {
    let Ok(s) = std::env::var(name) else {
        return None;
    };
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect::<Option<_>>()?;
    v.try_into().ok()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[test]
/// One-off troubleshooting diagnostics: requires SHLOSILO_TEST_XMR_* env vars (real spend/view keys); ignored by default.
#[ignore]
fn diag_step_by_step() {
    let view_sk = env_hex("SHLOSILO_TEST_XMR_VIEW_SK").expect("VIEW_SK");
    let spend_sk = env_hex("SHLOSILO_TEST_XMR_SPEND_SK").expect("SPEND_SK");

    let utx = deserialize_unsigned_tx(PLAIN).expect("deserialize");
    let tx_data = &utx.txes[0];

    // step A: derive_input_from_source(key image)
    let src = &tx_data.sources[0];
    let ki = shlosilo::chain::xmr::subaddress::derive_input_from_source(
        &view_sk,
        &spend_sk,
        src,
        tx_data.subaddr_account,
        &tx_data.subaddr_indices,
    );
    match ki {
        Ok((ki_bytes, ik)) => eprintln!("A KEYIMAGE OK {} {}", hex(&ki_bytes), hex(&ik)),
        Err(e) => {
            eprintln!("A KEYIMAGE FAIL {:?}", e);
            panic!("keyimage");
        }
    }
}

#[test]
/// Same as above; env-driven diagnostics.
#[ignore]
fn diag_clsag_with_fixture_ring() {
    use rand_core::OsRng;
    use shlosilo::chain::xmr::clsag;
    use shlosilo::chain::xmr::transaction::{bytes_to_monerod_scalar, monerod_scalar_to_bytes};
    use shlosilo::chain::xmr::unsigned_txset::deserialize_unsigned_tx;

    let view_sk = env_hex("SHLOSILO_TEST_XMR_VIEW_SK").expect("VIEW_SK");
    let spend_sk = env_hex("SHLOSILO_TEST_XMR_SPEND_SK").expect("SPEND_SK");

    let utx = deserialize_unsigned_tx(PLAIN).expect("deserialize");
    let tx_data = &utx.txes[0];
    let src = &tx_data.sources[0];

    // one-time input sk(spend + key_offset)
    let (_, key_offset) = shlosilo::chain::xmr::subaddress::derive_input_from_source(
        &view_sk,
        &spend_sk,
        src,
        tx_data.subaddr_account,
        &tx_data.subaddr_indices,
    )
    .expect("keyimage");
    let input_sk = shlosilo::chain::xmr::subaddress::derive_input_spend_key(&spend_sk, &key_offset)
        .expect("input_sk");

    // ring matches the signing path: (dest, on-chain C point) — OutputEntry.mask is the on-chain commitment point
    let ring: Vec<(
        monero_ed25519::CompressedPoint,
        monero_ed25519::CompressedPoint,
    )> = src
        .outputs
        .iter()
        .map(|o| {
            (
                monero_ed25519::CompressedPoint::from(o.dest),
                monero_ed25519::CompressedPoint::from(o.mask),
            )
        })
        .collect();
    assert_eq!(ring.len(), 16);

    // pseudo_mask = mask_real ± delta — use the real derivation: sum_out_masks − real_mask
    // but there are no outputs here; first use real_mask + 1 directly to test whether the CLSAG itself can be signed
    // true blinding factor = TxSourceEntry.mask (wallet2 sources[i].mask),
    // while OutputEntry.mask is the on-chain C point. ClsagContext asserts C == Commitment(blinding, amount).
    // P1-03: mask is now SecretBytes — diagnostic printing scenario, local copy discarded after use
    let mut real_mask_buf = [0u8; 32];
    src.mask.write_into(&mut real_mask_buf);
    let real_mask = real_mask_buf;
    let rm_d = curve25519_dalek::Scalar::from_bytes_mod_order(monerod_scalar_to_bytes(
        &bytes_to_monerod_scalar(&real_mask),
    ));
    let pseudo_mask: [u8; 32] = (rm_d + curve25519_dalek::Scalar::ONE).to_bytes();

    let mut rng = OsRng;
    let msg_hash = [0x42u8; 32];
    match clsag::sign(
        &input_sk,
        &ring,
        src.real_output as u8,
        &real_mask,
        src.amount,
        &pseudo_mask,
        &msg_hash,
        &mut rng,
    ) {
        Ok((_proof, _ki, po)) => eprintln!("C CLSAG OK {}", hex(&po)),
        Err(e) => {
            eprintln!("C CLSAG FAIL {:?}", e);
            panic!("clsag");
        }
    }
}

#[test]
fn diag_bp_size_and_verify() {
    use rand_core::OsRng;
    use shlosilo::chain::xmr::rct_sig::prove_bulletproofs_plus;

    let mut rng = OsRng;
    // same as the signing path: 2 outputs, amounts 1869360000 / 100000000
    let masks: Vec<[u8; 32]> = vec![[0xaau8; 32], [0xbbu8; 32]];
    use shlosilo::chain::xmr::transaction::bytes_to_monerod_scalar;
    let commitments = masks
        .iter()
        .map(|m| {
            let ms = bytes_to_monerod_scalar(m);
            monero_ed25519::Commitment::new(ms, 1_000_000)
        })
        .collect();
    let bp = prove_bulletproofs_plus(&mut rng, commitments).expect("bp");
    let mut buf = Vec::new();
    bp.write(&mut buf).unwrap();
    eprintln!("D BP+ wire size = {}", buf.len());
}
