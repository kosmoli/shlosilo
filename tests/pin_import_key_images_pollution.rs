//! MUST-RED pin (pool §32, 修正案 `shlosilo-设计-keyimages全量填充修正案-2026-10-17.md`):
//! the phone wallet's `import_key_images(signed_txs.key_images)` writes EVERY
//! entry POSITIONALLY into `m_transfers[ki_idx]` ("trusting imported one") —
//! a mirror-replay-proven fact (0.18.5.3: patching the outer array to
//! `[dummy, ca88215e]` parsed fine but logged the warning and OVERWROTE
//! transfers[0]). Therefore an outer-array entry that does not belong to its
//! wallet position is a spent-tracking corruption, no matter how conservative
//! the value looks.
//!
//! > STATUS 2026-10-21: FLIPPED GREEN (the v2 gap policy landed, `c61d418`) — the red contract below is history.
//!
//! `import_does_not_pollute_transfers_zero` was INTENTIONALLY RED while
//! the sign leg can ship an UNRELATED key image at wallet index 0 (the
//! conservative gap filler = the derived KI of the spent input, which belongs
//! to the selected transfer, not to transfer 0): after importing the produced
//! array, the wallet model's `transfers[0]` must still hold its OWN true key
//! image. No `#[should_panic]`, no `#[ignore]`.
//!
//! Fixture + helpers: same real Cake-built unsigned container as
//! `tests/pin_signed_key_images_wallet_indexed.rs` (8 transfers,
//! `selected_transfers=[5]`, one source; keys = PUBLISHED stagenet-lab test
//! keys, see tests/tx2_whitebox_tools.rs).
#![cfg(feature = "alloc-fallback")]

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
/// Wallet-transfer count of the fixture wallet (tx2_whitebox: 8 transfers).
const FIXTURE_TRANSFERS: usize = 8;

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
/// Returns (key_images, tki_count); structural ambiguity panics.
fn parse_signed_tail(plain: &[u8]) -> (Vec<[u8; 32]>, usize) {
    let len = plain.len();
    let mut candidates: Vec<(Vec<[u8; 32]>, usize)> = Vec::new();
    for tki_count in 0..=8usize {
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

/// Sign the add-keys-stripped fixture with the given wallet key image records;
/// returns (signed plaintext, outer key_images).
fn sign_stripped_fixture(
    ki_records: &[WalletKiRecord],
) -> Result<(Vec<u8>, Vec<[u8; 32]>), shlosilo::error::ShlosiloError> {
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
    )?;
    let plain = decrypt_signed_txset(&out[..n], &TX2_LAB_VIEW_SK).expect("decrypt signed");
    let (kis, _tki) = parse_signed_tail(&plain);
    Ok((plain.to_vec(), kis))
}

/// Wallet fingerprint of the fixture wallet (same seed path as the sign leg).
fn fixture_wallet_fp() -> [u8; 8] {
    use shlosilo::business::sign::wallet_fingerprint_from_seed;
    use shlosilo::entropy::mnemonic::Mnemonic;
    let m = Mnemonic::from_entropy(&[0x22u8; 32]).expect("mnemonic");
    let mut seed = [0u8; 64];
    shlosilo::business::restore_seed::restore_seed(&m, b"", &mut seed).expect("restore seed");
    wallet_fingerprint_from_seed(&seed)
}

/// The fixture wallet's TRUE per-transfer key images as the pairing beat knows
/// them (`WalletKiRecord` values): positions 0..=4 carry their own distinct key
/// image, the spent input at `FIXTURE_MAX_SELECTED` is source-derived at sign
/// time, 6..=7 are untouched wallet transfers. These are the values the phone
/// wallet holds in `m_transfers[i].m_key_image` before any import.
fn true_key_image(i: usize) -> [u8; 32] {
    assert!(i < FIXTURE_TRANSFERS, "fixture wallet has 8 transfers");
    [0x10 + i as u8; 32]
}

/// MUST-RED (pool §32): importing the signed container's outer `key_images`
/// array writes every entry positionally into `m_transfers` — so a covered
/// position must carry ITS OWN true key image, never an unrelated record.
///
/// Scenario: the pairing retention covers transfers 1..=4 (transfer 0's record
/// is stale/lost — retention lives in flux RAM and is capped at 8 slots); the
/// spent input at index 5 is source-derived. The gap filler currently lands at
/// index 0 with the SPENT input's derived key image — an unrelated record for
/// transfer 0 — and `import_key_images` ("trusting imported one") overwrites
/// `transfers[0]`, corrupting the phone's spent-tracking (mirror-replay-proven
/// with the dummy-at-0 array, 2026-10-17).
#[test]
fn import_does_not_pollute_transfers_zero() {
    // Flipped GREEN 2026-10-21 (A案): the v2 gap policy refuses the sign when
    // a covered position has no own true key image — NOTHING positional ships,
    // so wallet2's positional import cannot pollute transfers[0] (pool #32).
    // The v1 conservative filler (the spent input's derived KI at every gap)
    // is retired; the endgames for recordless signing are the persistent
    // record store / keystone-shape empty array (LuckyFox phase).
    //
    // A set of pairing records that does NOT cover transfer 0.
    let fp = fixture_wallet_fp();
    let records: Vec<WalletKiRecord> = (1..=FIXTURE_MAX_SELECTED as u32 - 1)
        .map(|i| WalletKiRecord {
            transfer_idx: i,
            wallet_fp: fp,
            key_image: true_key_image(i as usize),
            out_pub: [0x70u8.wrapping_add(i as u8); 32],
        })
        .collect();
    let err = sign_stripped_fixture(&records)
        .expect_err("gap without a record must refuse the sign (v2 gap policy)");
    assert!(
        matches!(
            err.kind,
            shlosilo::error::ShlosiloErrorKind::KeyImageRecordMissing
        ),
        "expected KeyImageRecordMissing, got {err:?}"
    );
}
