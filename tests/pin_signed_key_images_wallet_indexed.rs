//! Regression suite: the signed container's outer `key_images` array must be
//! WALLET-TRANSFER-INDEXED, one TRUE key image per wallet transfer position.
//!
//! Oracle (wallet2 source, NOT keystone — Cake does not support keystone):
//! gold fill = wallet2.cpp:8074-8079 `signed_txes.key_images.resize(m_transfers.size())`
//! then `key_images[i] = m_transfers[i].m_key_image` — the full wallet array,
//! indexed by wallet transfer index.
//!
//! Phone-side facts (Cake v6.4.6, monero 0.18.5.3, APK .so strings + source +
//! the 2026-10-17 mirror replay of the real container under 0.18.5.3):
//! - pre-import sanity (`parse_tx_from_str` → `sanity_check_pending_tx_set`):
//!   resolver `kis.at(i)` with `i = ptx.selected_transfers[j]`; bounds CHECK
//!   text "failed loading signed tx: ptx selected transfer is outside the
//!   bounds of imported key images" — the packed per-source array with
//!   selected=[5] threw exactly this (the tx2 silent exit#4).
//! - `import_key_images(signed_txs.key_images)` writes EVERY entry positionally
//!   into `m_transfers[ki_idx]` ("trusting imported one") — a placeholder at a
//!   covered position corrupts the phone's spent-tracking (mirror replay:
//!   patching the array to 2 entries with a dummy at index 0 parsed fine but
//!   logged the warning and overwrote transfers[0]).
//!
//! Fixture: the real Cake-built unsigned (`tx2_cake_real_unsigned.bin`),
//! wallet with 8 transfers, `selected_transfers=[5]`, one source. The records
//! face (pairing-beat retention) supplies the non-selected positions; without
//! it the sign REFUSES (`KeyImageRecordMissing`) instead of shipping
//! placeholders.
//!
//! Keys are the PUBLISHED stagenet-lab test keys (see tests/tx2_whitebox_tools.rs).

use rand_chacha::rand_core::SeedableRng as _;
use shlosilo::business::sign::WalletKiRecord;
use shlosilo::chain::xmr::signed_txset::{decrypt_signed_txset, encrypt_unsigned_txset};
use shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset;

const TX2_LAB_VIEW_SK: [u8; 32] = [
    0xdb, 0x93, 0xce, 0x63, 0x2d, 0x8d, 0x31, 0xe3, 0x1b, 0xd0, 0xb4, 0xec, 0xbd, 0xbd, 0xb8, 0x33,
    0xca, 0xe8, 0x13, 0x92, 0x8a, 0xf4, 0x02, 0xc5, 0xb7, 0xff, 0xeb, 0x85, 0x76, 0x9c, 0xf0, 0x00,
];
/// real_out_tx_key of the fixture's single source entry (add-keys strip marker)
const TX2_LAB_SRC_TX_KEY: [u8; 32] = [
    0xd2, 0x3c, 0xb1, 0xc2, 0x9b, 0xd8, 0xd6, 0x25, 0xcf, 0x92, 0x2b, 0xcc, 0x13, 0xad, 0xb1, 0x1e,
    0xa7, 0x43, 0x77, 0x87, 0xb7, 0x4c, 0xaf, 0x98, 0x9c, 0x4c, 0xf4, 0x89, 0x9d, 0x09, 0x1a, 0x34,
];
/// The fixture wallet's selected transfer (wallet index of the spent input).
const FIXTURE_MAX_SELECTED: usize = 5;

/// The add-keys input of this fixture blocks signing (F2, separate pin) —
/// strip `real_out_additional_tx_keys` in the decrypted plaintext so these
/// tests exercise the key_images wire shape, not the F2 selection bug.
fn strip_add_keys(plain: &mut Vec<u8>) {
    let pos = plain
        .windows(32)
        .position(|w| w == TX2_LAB_SRC_TX_KEY)
        .expect("tx_key marker");
    let nkeys = plain[pos + 32];
    assert!((1..0x80).contains(&nkeys), "add-keys varint {nkeys}");
    plain[pos + 32] = 0;
    plain.drain(pos + 33..pos + 33 + nkeys as usize * 32);
}

/// Read one LEB128 varint ending exactly at `end` (backward scan).
/// Returns (value, start_index) or None if the varint is malformed.
fn varint_ending_at(buf: &[u8], end: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut start = end;
    loop {
        if start == 0 || shift > 63 {
            return None;
        }
        start -= 1;
        let b = buf[start];
        value |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((value, start));
        }
        shift += 7;
    }
}

/// Parse the signed_tx_set plaintext tail:
/// `... ptx section | varint ki_count | ki_count*32B | varint tki_count | tki_count*65B`.
/// Each tx_key_images entry is `0x02 | 32B pubkey | 32B key_image` = 65 B.
/// Returns (key_images, tki_count); structural ambiguity panics.
fn parse_signed_tail(plain: &[u8]) -> (Vec<[u8; 32]>, usize) {
    let len = plain.len();
    let mut candidates: Vec<(Vec<[u8; 32]>, usize)> = Vec::new();
    for tki_count in 0..=8usize {
        // varint(tki_count) directly precedes the tki entries
        let entries_len = tki_count * 65;
        let Some((c1, v1_start)) = varint_ending_at(plain, len - entries_len) else {
            continue;
        };
        if c1 != tki_count as u64 {
            continue;
        }
        let ki_section_end = v1_start;
        for ki_count in 1..=64usize {
            let Some((c2, v2_start)) = varint_ending_at(plain, ki_section_end - ki_count * 32)
            else {
                continue;
            };
            if c2 != ki_count as u64 {
                continue;
            }
            let ptx_end = v2_start;
            // structural checks: the ptx section must exist and start with the
            // signed_tx_set version byte 0x00 followed by the ptx version 0x01
            if ptx_end < 2 || plain[0] != 0x00 || plain[1] != 0x01 {
                continue;
            }
            let mut kis = Vec::with_capacity(ki_count);
            let ki_start = ki_section_end - ki_count * 32;
            for i in 0..ki_count {
                let mut k = [0u8; 32];
                k.copy_from_slice(&plain[ki_start + i * 32..ki_start + (i + 1) * 32]);
                kis.push(k);
            }
            candidates.push((kis, tki_count));
        }
    }
    assert_eq!(
        candidates.len(),
        1,
        "tail parse ambiguity: {} candidates (fixture framing drifted?)",
        candidates.len()
    );
    candidates.pop().expect("non-empty")
}

/// Extract the ptx-level `<64-hex>` key image of the spent input from the
/// signed plaintext (the per-tx `key_images_str` wire field) — the independent
/// anchor for the outer array's selected position. Pattern-anchored:
/// `<` + 64 lowercase hex + `>` + ` ` (the wire string shape).
fn ptx_key_image_from_str_field(plain: &[u8]) -> [u8; 32] {
    let is_hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    let mut found: Option<[u8; 32]> = None;
    for i in 0..plain.len().saturating_sub(67) {
        if plain[i] != b'<' || plain[i + 65] != b'>' || plain[i + 66] != b' ' {
            continue;
        }
        if !plain[i + 1..i + 65].iter().all(|&b| is_hex(b)) {
            continue;
        }
        assert!(found.is_none(), "multiple <hex> key image strings");
        let nib = |b: u8| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => unreachable!(),
        };
        let mut ki = [0u8; 32];
        for (j, slot) in ki.iter_mut().enumerate() {
            *slot = (nib(plain[i + 1 + j * 2]) << 4) | nib(plain[i + 2 + j * 2]);
        }
        found = Some(ki);
    }
    found.expect("<hex> key image string in ptx key_images_str")
}

/// Sign the add-keys-stripped fixture with the given wallet key image records;
/// returns (signed plaintext, outer key_images).
fn sign_stripped_fixture(ki_records: &[WalletKiRecord]) -> (Vec<u8>, Vec<[u8; 32]>) {
    use shlosilo::business::sign::sign_with_entropy_records;
    use shlosilo::entropy::mnemonic::Mnemonic;
    use shlosilo::ur::ur_encode::UrTypeTag;

    let enc = include_bytes!("fixtures/tx2_cake_real_unsigned.bin");
    let mut plain = decrypt_unsigned_txset(enc, &TX2_LAB_VIEW_SK)
        .expect("decrypt fixture")
        .to_vec();
    strip_add_keys(&mut plain);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x22);
    let patched =
        encrypt_unsigned_txset(zeroize::Zeroizing::new(plain), &TX2_LAB_VIEW_SK, &mut rng)
            .expect("re-encrypt");
    let m = Mnemonic::from_entropy(&[0x22u8; 32]).expect("mnemonic");
    let mut out = vec![0u8; 65536];
    let n = sign_with_entropy_records(
        shlosilo::business::sign::SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &patched,
        ki_records,
        &[0x77u8; 32],
        &mut out,
    )
    .expect("sign with records must succeed");
    let plain = decrypt_signed_txset(&out[..n], &TX2_LAB_VIEW_SK).expect("decrypt signed");
    let (kis, _tki) = parse_signed_tail(&plain);
    (plain.to_vec(), kis)
}

/// Wallet fingerprint of the fixture wallet: same seed path as
/// sign_stripped_fixture (Mnemonic::from_entropy([0x22;32]) -> restore_seed ->
/// 64B BIP-39 seed). fix37: records are wallet-bound; a record with a foreign
/// fp is treated as absent by the sign leg.
fn fixture_wallet_fp() -> [u8; 8] {
    use shlosilo::business::sign::wallet_fingerprint_from_seed;
    use shlosilo::entropy::mnemonic::Mnemonic;
    let m = Mnemonic::from_entropy(&[0x22u8; 32]).expect("mnemonic");
    let mut seed = [0u8; 64];
    shlosilo::business::restore_seed::restore_seed(&m, b"", &mut seed).expect("restore seed");
    wallet_fingerprint_from_seed(&seed)
}

/// Records for the fixture's non-selected positions 0..=4 (the sign path takes
/// non-selected positions verbatim; only the selected index is source-derived).
fn fixture_gap_records() -> Vec<WalletKiRecord> {
    let fp = fixture_wallet_fp();
    (0..FIXTURE_MAX_SELECTED as u32)
        .map(|i| WalletKiRecord {
            transfer_idx: i,
            wallet_fp: fp,
            key_image: [0x10 + i as u8; 32],
        })
        .collect()
}

/// GREEN contract (was the MUST-RED pin): with the pairing-beat records
/// supplied, the outer key_images array is wallet-transfer-indexed — records
/// land at their transfer indices, the spent input's derived key image at
/// `selected_transfers`.
#[test]
fn key_images_wallet_transfer_indexed_with_records() {
    let records = fixture_gap_records();
    let (plain, kis) = sign_stripped_fixture(&records);
    assert_eq!(
        kis.len(),
        FIXTURE_MAX_SELECTED + 1,
        "array must cover 0..=max(selected_transfers)"
    );
    for r in records.iter() {
        assert_eq!(
            kis[r.transfer_idx as usize], r.key_image,
            "record at wallet index {} must land verbatim",
            r.transfer_idx
        );
    }
    // the spent position carries the DERIVED key image — cross-anchored against
    // the ptx-level `<hex>` key_images_str of the same container
    let src_ki = ptx_key_image_from_str_field(&plain);
    assert_eq!(
        kis[FIXTURE_MAX_SELECTED], src_ki,
        "selected position must carry the source-derived key image"
    );
}

/// fix37 wallet-fingerprint binding: records carrying a FOREIGN wallet fp are
/// treated as absent by the sign leg (a plate swap without a power cycle must
/// not feed another wallet's key images into this wallet's wire array). The
/// output must equal the no-records conservative fill: the foreign key image
/// values must NOT appear anywhere in the outer array.
#[test]
fn foreign_fp_records_are_ignored() {
    let mut records = fixture_gap_records();
    for r in records.iter_mut() {
        // a valid-looking but foreign fingerprint (fixture fp, bit-flipped)
        r.wallet_fp[0] ^= 0xFF;
    }
    let (_plain, kis) = sign_stripped_fixture(&records);
    for r in records.iter() {
        assert_ne!(
            kis[r.transfer_idx as usize], r.key_image,
            "foreign-fp record at index {} must NOT land",
            r.transfer_idx
        );
    }
    // and the gap positions carry the conservative filler (same as recordless)
    let (_plain0, kis0) = sign_stripped_fixture(&[]);
    assert_eq!(
        kis, kis0,
        "foreign-fp records must produce exactly the recordless output"
    );
}

/// Without records (the REAL product case — Cake pairs key images once per
/// wallet, so every later sign runs recordless) the sign fills the uncovered
/// positions with the CONSERVATIVE filler: a derived key image of a spent
/// input. The phone then marks those transfers spent — the balance under-
/// counts until the next key-image re-sync, never inflates. A zero/unknown
/// filler would instead make actually-spent transfers look unspent (balance
/// inflation + double-spend UX), and refusing outright made every second tx
/// un-signable (fix35 field finding, 2026-10-17).
#[test]
fn conservative_fallback_without_records() {
    let (plain, kis) = sign_stripped_fixture(&[]);
    assert_eq!(
        kis.len(),
        FIXTURE_MAX_SELECTED + 1,
        "array must cover 0..=max(selected_transfers)"
    );
    let src_ki = ptx_key_image_from_str_field(&plain);
    assert_eq!(
        kis[FIXTURE_MAX_SELECTED], src_ki,
        "selected position must carry the source-derived key image"
    );
    for (i, ki) in kis.iter().enumerate().take(FIXTURE_MAX_SELECTED) {
        assert_eq!(
            *ki, src_ki,
            "gap position {i} must carry the conservative spent-marker filler"
        );
    }
}

/// A record disagreeing with the source-derived key image at the SAME wallet
/// index = record list misalignment — refuse (`KeyImageRecordMismatch`), never
/// import a shifted key image into the phone wallet.
#[test]
fn refuse_on_record_source_mismatch() {
    use shlosilo::business::sign::{sign_with_entropy_records, SignInput};
    use shlosilo::entropy::mnemonic::Mnemonic;
    use shlosilo::ur::ur_encode::UrTypeTag;

    let mut records = fixture_gap_records();
    records.push(WalletKiRecord {
        transfer_idx: FIXTURE_MAX_SELECTED as u32,
        wallet_fp: fixture_wallet_fp(),
        key_image: [0xBBu8; 32], // deliberately not the derived key image
    });

    let enc = include_bytes!("fixtures/tx2_cake_real_unsigned.bin");
    let mut plain = decrypt_unsigned_txset(enc, &TX2_LAB_VIEW_SK)
        .expect("decrypt fixture")
        .to_vec();
    strip_add_keys(&mut plain);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x22);
    let patched =
        encrypt_unsigned_txset(zeroize::Zeroizing::new(plain), &TX2_LAB_VIEW_SK, &mut rng)
            .expect("re-encrypt");
    let m = Mnemonic::from_entropy(&[0x22u8; 32]).expect("mnemonic");
    let mut out = vec![0u8; 65536];
    let err = sign_with_entropy_records(
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &patched,
        &records,
        &[0x77u8; 32],
        &mut out,
    )
    .expect_err("mismatched record at the selected index must refuse");
    assert!(
        matches!(
            err.kind,
            shlosilo::error::ShlosiloErrorKind::KeyImageRecordMismatch
        ),
        "expected KeyImageRecordMismatch, got {err:?}"
    );
}
