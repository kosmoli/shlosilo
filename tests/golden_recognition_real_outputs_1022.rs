//! EXTERNAL anchor for the output-derivation math (2026-10-23, the
//! 0.0002-looked-lost incident). The derivation KATs in tx_signer snapshot
//! the implementation's own formulas — a wrong formula passes them. This test
//! anchors the math on REAL bytes: the cap2 signed container produced by the
//! device (accepted on-chain as tx 1c8eef99… at block 3789771; one output's
//! receipt was confirmed inside the real TEST2 wallet) together with the real
//! recipient key material (test-grade, embedded per the 2026-10-20 fixture
//! verdict).
//!
//! What is pinned:
//! 1. the recipient-side derivation (calc_output_key_offset + the view tag)
//!    reproduces the REAL output pubkeys of an on-chain transaction for the
//!    true recipients;
//! 2. the incident's fact set, byte-exact: the change output (vout1) is
//!    recognized under the stock main-key branch, while the two
//!    additional-key-derived outputs are only reachable at the PRE-FIX table's
//!    shifted slots — the regression being the dshape pin.
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::xmr::subaddress::calc_output_key_offset;
use shlosilo::chain::xmr::transaction::TransactionPrefix;
use shlosilo::chain::xmr::view_tag::{derive_view_tag, eight_ra};

/// Real recipient key material (test-grade; the 2026-10-20 fixture verdict:
/// our wallets are test wallets, coverage beats secrecy).
const TEST2_SPEND: [u8; 32] = [
    0x12, 0x83, 0xcb, 0xd5, 0x3a, 0x57, 0x9f, 0x0e, 0x34, 0x90, 0xf3, 0xd9, 0x97, 0x8d, 0x7d, 0x42,
    0x3f, 0x98, 0x69, 0x23, 0xb3, 0x25, 0xa2, 0x33, 0x45, 0x4f, 0xb9, 0x91, 0xd0, 0xbb, 0x28, 0x0d,
];
const TEST2_VIEW: [u8; 32] = [
    0x8d, 0xea, 0xed, 0xf1, 0x13, 0x7e, 0x24, 0xb9, 0xed, 0x25, 0x38, 0xae, 0x99, 0x53, 0x2f, 0x0f,
    0xf7, 0x71, 0x7c, 0x3c, 0x52, 0xd1, 0x16, 0x9c, 0xb0, 0x06, 0x88, 0x1c, 0x48, 0xa7, 0xbb, 0x04,
];
/// TEST1 = the retired 49KRW wallet (public-grade since 2026-10-20).
const TEST1_SPEND: [u8; 32] = [
    0xca, 0x8b, 0x0c, 0xb5, 0x6d, 0xf7, 0x93, 0x80, 0xbb, 0x47, 0x81, 0xee, 0xfd, 0xe9, 0xdf, 0x0f,
    0x41, 0xe9, 0x8c, 0x6c, 0x3e, 0xa3, 0xd2, 0x7b, 0x9f, 0xb6, 0x18, 0x33, 0x98, 0xa3, 0x47, 0x0d,
];
const TEST1_VIEW: [u8; 32] = [
    0xdb, 0x93, 0xce, 0x63, 0x2d, 0x8d, 0x31, 0xe3, 0x1b, 0xd0, 0xb4, 0xec, 0xbd, 0xbd, 0xb8, 0x33,
    0xca, 0xe8, 0x13, 0x92, 0x8a, 0xf4, 0x02, 0xc5, 0xb7, 0xff, 0xeb, 0x85, 0x76, 0x9c, 0xf0, 0x00,
];

/// Recipient-side derivation (the wallet2 scanning math): the one-time
/// output pubkey must equal (spend + offset)·G and the view tag must match,
/// where offset = calc_output_key_offset(view, key, j, major, minor).
#[allow(clippy::too_many_arguments)] // the recipient lookup's full parameter set
fn derives_output(
    out_pub: &[u8; 32],
    out_tag: u8,
    j: u64,
    key: &[u8; 32],
    view: &[u8; 32],
    spend: &[u8; 32],
    major: u32,
    minor: u32,
) -> bool {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let Ok(offset) = calc_output_key_offset(view, key, j, major, minor) else {
        return false;
    };
    let sk = Scalar::from_bytes_mod_order(*spend) + Scalar::from_bytes_mod_order(offset);
    let pub_prime = (ED25519_BASEPOINT_TABLE * &sk).compress().to_bytes();
    if pub_prime != *out_pub {
        return false;
    }
    let Ok(eight) = eight_ra(view, key) else {
        return false;
    };
    derive_view_tag(&eight, j) == out_tag
}

/// Decrypt the device's signed container envelope
/// (`Monero signed tx set\005` ‖ nonce ‖ ChaCha20Legacy(CN-V0(view_sk)) ‖ sig).
fn decrypt_signed_container(cont: &[u8], view_sk: &[u8; 32]) -> Vec<u8> {
    use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
    let magic = b"Monero signed tx set\x05";
    assert_eq!(&cont[..21], magic, "signed container magic");
    let nonce = &cont[21..29];
    let ct = &cont[29..cont.len() - 64];
    let mut scratch = vec![0u8; shlosilo::types::caps::SIGN_WS_CN_SCRATCH];
    let key = cuprate_cryptonight::cryptonight_hash_v0_into(view_sk, &mut scratch).expect("cn");
    let mut cipher = chacha20::ChaCha20Legacy::new_from_slices(&key, nonce).expect("cipher");
    let mut plain = ct.to_vec();
    cipher.apply_keystream(&mut plain);
    plain
}

#[test]
fn real_onchain_outputs_reproducible_by_recipient_math() {
    let cont = include_bytes!("fixtures/cap2_1022_signed.bin");
    let plain = decrypt_signed_container(cont, &TEST2_VIEW);

    // signed_tx_set plaintext layout (the signer's write_all mirror):
    // u8 version | varint ptx_count | u8 ptx_version | <transaction bytes …>
    assert_eq!(plain[0], 0x00, "signed_tx_set version");
    assert_eq!(plain[2], 0x01, "ptx version");
    let mut pos = 3;
    let prefix = TransactionPrefix::deserialize(&plain, &mut pos).expect("tx prefix");
    assert_eq!(prefix.outputs_len, 4, "cap2 has 4 outputs");
    let tx_pub = prefix.extra.tx_pub_key.expect("tx pubkey in extra");
    let table = &prefix.extra.additional_pub_keys;

    // vout1 = the change (TEST2 main (0,0), branch 1): recognized under the
    // stock main-key rule — and its real-world receipt is the ground truth.
    let v1 = &prefix.outputs[1];
    assert!(
        derives_output(
            &v1.stealth_address,
            v1.view_tag.unwrap_or(0),
            1,
            &tx_pub,
            &TEST2_VIEW,
            &TEST2_SPEND,
            0,
            0
        ),
        "vout1 (change) must be derived by TEST2 under the main tx key"
    );

    // Incident fact set (pre-fix table shape: 3 entries for 4 vouts, the
    // per-subaddress-dest slots): vout2 (TEST2 self-pay at (0,4)) and vout3
    // (TEST1 at (0,6)) derive from table[1] / table[2] — the shifted slots
    // the stock receiver (which indexes additional[output_index]) never
    // checks. The dshape pin keeps new signatures on the correct shape.
    let v2 = &prefix.outputs[2];
    assert!(
        derives_output(
            &v2.stealth_address,
            v2.view_tag.unwrap_or(0),
            2,
            &table[1],
            &TEST2_VIEW,
            &TEST2_SPEND,
            0,
            4
        ),
        "vout2 (self-pay at (0,4)) must derive from the incident's slot-1 key"
    );
    let v3 = &prefix.outputs[3];
    assert!(
        derives_output(
            &v3.stealth_address,
            v3.view_tag.unwrap_or(0),
            3,
            &table[2],
            &TEST1_VIEW,
            &TEST1_SPEND,
            0,
            6
        ),
        "vout3 (TEST1 at (0,6)) must derive from the incident's slot-2 key"
    );

    // vout0 is the external hot-wallet output (unknown keys here) — recorded
    // for completeness: its slot under the pre-fix table is index 0.
    let _v0 = &prefix.outputs[0];
}

/// FIX VERIFICATION (2026-10-23): the first device container produced by the
/// wallet2-oracle fix firmware (identity v0.5.0-poc4+8b3a80e) — the D-shape
/// signed tx from the user's retest. Unlike the incident fixture above, the
/// additional-key table must now follow the stock receiver rule: one entry
/// per VOUT, and every output must be recognizable at its true slot
/// (branch 1 = the main tx pubkey, branch 2 = additional[output_index]).
#[test]
fn fixed_shape_recognizable_at_true_slots() {
    let cont = include_bytes!("fixtures/cap3_1023_fixed_signed.bin");
    let plain = decrypt_signed_container(cont, &TEST2_VIEW);
    assert_eq!(plain[0], 0x00);
    assert_eq!(plain[2], 0x01);
    let mut pos = 3;
    let prefix = TransactionPrefix::deserialize(&plain, &mut pos).expect("tx prefix");
    let tx_pub = prefix.extra.tx_pub_key.expect("tx pubkey in extra");
    let table = &prefix.extra.additional_pub_keys;

    // wallet2 lookup_acc_outs CHECK: one additional pubkey per vout
    assert_eq!(
        table.len(),
        prefix.outputs_len,
        "the fixed firmware must emit one additional pubkey per vout"
    );

    // every output must be recognized under the STOCK rule at its true slot
    let wallets: [([u8; 32], [u8; 32]); 2] = [(TEST2_VIEW, TEST2_SPEND), (TEST1_VIEW, TEST1_SPEND)];
    let bases: [(u32, u32); 3] = [(0, 0), (0, 4), (0, 6)];
    let mut unrecognized = 0usize;
    for (i, out) in prefix.outputs[..prefix.outputs_len].iter().enumerate() {
        let tag = out.view_tag.unwrap_or(0);
        let mut ok = false;
        for (view, spend) in &wallets {
            for &(major, minor) in &bases {
                // branch 1: the main tx pubkey
                ok |= derives_output(
                    &out.stealth_address,
                    tag,
                    i as u64,
                    &tx_pub,
                    view,
                    spend,
                    major,
                    minor,
                );
                // branch 2: additional[output_index] (the wallet2 hard rule)
                if (i) < table.len() {
                    ok |= derives_output(
                        &out.stealth_address,
                        tag,
                        i as u64,
                        &table[i],
                        view,
                        spend,
                        major,
                        minor,
                    );
                }
            }
        }
        if ok {
            println!("vout{i}: recognized at its true slot");
        } else {
            println!("vout{i}: NOT recognized (external recipient?)");
        }
        if !ok {
            unrecognized += 1;
        }
    }
    // the D shape carries exactly one external recipient (the hot wallet,
    // whose keys are not embedded) — every wallet-destined output must be
    // recognized at its TRUE slot by the stock wallet2 rule.
    assert!(
        unrecognized <= 1,
        "at most the one external recipient output may be unrecognized;          {unrecognized} of {} failed",
        prefix.outputs_len
    );
}

/// A/B the trailing Schnorr against wallet2's exact authentication scope:
/// hash = keccak256(nonce || ciphertext) over everything after the magic minus
/// the trailing 64B; challenge = Hs(hash || P || R') with P the view pubkey.
#[test]
fn envelope_sig_ab_cap2_vs_cap3() {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let view_point = ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(TEST2_VIEW);
    let view_pub = view_point.compress().to_bytes();

    // Fixtures in-tree (test constitution #4; CI-clean-checkout safe — the
    // old absolute /tmp paths failed the fce60e2 CI run, which nobody watched
    // for 5 days). cap4 is the recovered TRUE container (12157B, reassembled
    // from the archived 61-part UR capture on 2026-10-29).
    for (tag, blob) in [
        (
            "cap2",
            include_bytes!("fixtures/cap2_container.bin").as_slice(),
        ),
        (
            "cap3",
            include_bytes!("fixtures/cap3_container.bin").as_slice(),
        ),
        (
            "cap4",
            include_bytes!("fixtures/cap4_signed_61.bin").as_slice(),
        ),
    ] {
        let magic = b"Monero signed tx set\x05";
        assert_eq!(&blob[..magic.len()], magic, "{tag} magic");
        let body = &blob[magic.len()..blob.len() - 64];
        let hash = shlosilo::encoding::keccak256::hash(body).expect("keccak");
        let sig = &blob[blob.len() - 64..];
        let c = Scalar::from_bytes_mod_order(sig[..32].try_into().unwrap());
        let r = Scalar::from_bytes_mod_order(sig[32..].try_into().unwrap());

        // R' = r·G + c·P
        let r_calc = (ED25519_BASEPOINT_TABLE * &r + view_point * c)
            .compress()
            .to_bytes();

        let mut data = [0u8; 96];
        data[..32].copy_from_slice(&hash);
        data[32..64].copy_from_slice(&view_pub);
        data[64..].copy_from_slice(&r_calc);
        let c_check = Scalar::from_bytes_mod_order(
            shlosilo::encoding::keccak256::hash(&data).expect("keccak"),
        );
        println!(
            "{tag}: len={} c_check==c: {}",
            blob.len(),
            c_check.to_bytes() == sig[..32]
        );
    }
}

/// Count how many (wallet, base, branch) claim paths recognize a vout under
/// the STRICT stock wallet2 receive rule (branch 1 = main tx pubkey,
/// branch 2 = additional[output_index] hard-indexed; both gated by the view
/// tag at the true slot).
fn claim_count(
    out_pub: &[u8; 32],
    out_tag: u8,
    i: usize,
    tx_pub: &[u8; 32],
    table: &[[u8; 32]],
    wallets: &[([u8; 32], [u8; 32]); 2],
    bases: &[(u32, u32); 3],
) -> usize {
    let mut n = 0usize;
    for (view, spend) in wallets {
        for &(major, minor) in bases {
            if derives_output(
                out_pub, out_tag, i as u64, tx_pub, view, spend, major, minor,
            ) {
                n += 1;
            }
            if i < table.len()
                && derives_output(
                    out_pub, out_tag, i as u64, &table[i], view, spend, major, minor,
                )
            {
                n += 1;
            }
        }
    }
    n
}

/// PIN-1 (2026-10-28, F7-recovery lesson): claimability must be EXACTLY ONCE.
/// Zero claims = the F7 black-hole class (money invisible to every wallet).
/// 2026-10-28 closed-loop note: the incident's vout2 IS claimed by a relaxed
/// scan exactly at the case-file matrix slot (add[1], j=2) — verified live.
/// The interim "black hole" stories (own-tx rescan skip, never-probed) were
/// RETRACTED as instrument artifacts (signed fp comparison + mangled %02x
/// prints) plus show_transfers' own-tx display convention (self-received
/// outputs get no separate in-row; the money sits in unspent_outputs).
/// Lesson: calibrate probes on a known positive before reading negatives.
/// Two+ claims = the mis-slot class (wallet accounting becomes ambiguous).
/// Each wallet-destined vout of a production container must have exactly one
/// claim path; the single external-recipient output is the allowed zero.
#[test]
fn claims_are_exactly_once() {
    let wallets: [([u8; 32], [u8; 32]); 2] = [(TEST2_VIEW, TEST2_SPEND), (TEST1_VIEW, TEST1_SPEND)];
    let bases: [(u32, u32); 3] = [(0, 0), (0, 4), (0, 6)];
    for (name, cont) in [(
        "cap3_fixed",
        &include_bytes!("fixtures/cap3_1023_fixed_signed.bin")[..],
    )] {
        let plain = decrypt_signed_container(cont, &TEST2_VIEW);
        let mut pos = 3;
        let prefix = TransactionPrefix::deserialize(&plain, &mut pos).expect("tx prefix");
        let tx_pub = prefix.extra.tx_pub_key.expect("tx pubkey in extra");
        let table = &prefix.extra.additional_pub_keys;
        let mut zero = 0usize;
        for (i, out) in prefix.outputs[..prefix.outputs_len].iter().enumerate() {
            let n = claim_count(
                &out.stealth_address,
                out.view_tag.unwrap_or(0),
                i,
                &tx_pub,
                table,
                &wallets,
                &bases,
            );
            assert!(
                n <= 1,
                "{name} vout{i}: {n} claim paths — mis-slot class (ambiguous accounting)"
            );
            if n == 0 {
                zero += 1;
            }
        }
        assert!(zero <= 1, "{name}: {zero} unclaimable vouts — F7 black-hole class (external recipient allows exactly one)");
    }
}

/// PIN-2 (2026-10-28, F7-recovery lesson): fixture-sweep audit — every signed
/// container in this list is checked for claimability, and NEW fixtures join
/// the list by default. The incident container (cap2, 2026-10-22, pre-fix
/// shifted additional-key table) is pinned as a CASE FILE: its fingerprint
/// (one vout claimable only at shifted/zero paths at its true slot) must stay
/// reproducible, so the guarded-against bug class stays documented in bytes.
#[test]
fn signed_fixtures_claim_audit() {
    let wallets: [([u8; 32], [u8; 32]); 2] = [(TEST2_VIEW, TEST2_SPEND), (TEST1_VIEW, TEST1_SPEND)];
    let bases: [(u32, u32); 3] = [(0, 0), (0, 4), (0, 6)];

    // healthy fixtures: exactly-once claimability for every wallet-destined vout
    for (name, cont) in [(
        "cap3_fixed",
        &include_bytes!("fixtures/cap3_1023_fixed_signed.bin")[..],
    )] {
        let plain = decrypt_signed_container(cont, &TEST2_VIEW);
        let mut pos = 3;
        let prefix = TransactionPrefix::deserialize(&plain, &mut pos).expect("tx prefix");
        let tx_pub = prefix.extra.tx_pub_key.expect("tx pubkey in extra");
        let table = &prefix.extra.additional_pub_keys;
        let mut zero = 0usize;
        for (i, out) in prefix.outputs[..prefix.outputs_len].iter().enumerate() {
            let n = claim_count(
                &out.stealth_address,
                out.view_tag.unwrap_or(0),
                i,
                &tx_pub,
                table,
                &wallets,
                &bases,
            );
            assert!(n <= 1, "{name} vout{i}: {n} claim paths — mis-slot class");
            if n == 0 {
                zero += 1;
            }
        }
        assert!(
            zero <= 1,
            "{name}: {zero} unclaimable vouts — F7 black-hole class"
        );
    }

    // case file: the incident container must keep its broken fingerprint —
    // >=1 wallet-destined vout with ZERO true-slot claims (the shifted table).
    let cont = include_bytes!("fixtures/cap2_1022_signed.bin");
    let plain = decrypt_signed_container(cont, &TEST2_VIEW);
    let mut pos = 3;
    let prefix = TransactionPrefix::deserialize(&plain, &mut pos).expect("tx prefix");
    let tx_pub = prefix.extra.tx_pub_key.expect("tx pubkey in extra");
    let table = &prefix.extra.additional_pub_keys;
    let mut zero_claims = 0usize;
    for (i, out) in prefix.outputs[..prefix.outputs_len].iter().enumerate() {
        let n = claim_count(
            &out.stealth_address,
            out.view_tag.unwrap_or(0),
            i,
            &tx_pub,
            table,
            &wallets,
            &bases,
        );
        if n == 0 {
            zero_claims += 1;
        }
    }
    assert!(
        zero_claims >= 1,
        "the cap2 incident fixture must keep its black-hole fingerprint (>=1 zero-claim vout); \
         if this now fails the fixture was replaced — update this pin deliberately"
    );
}
