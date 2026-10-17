//! MUST-RED pin: the signed container's outer `key_images` array must be
//! WALLET-TRANSFER-INDEXED, one TRUE key image per wallet transfer position.
//!
//! Oracle (wallet2 source, NOT keystone — Cake does not support keystone):
//! gold fill = wallet2.cpp:8074-8079 `signed_txes.key_images.resize(m_transfers.size())`
//! then `key_images[i] = m_transfers[i].m_key_image` — the full wallet array,
//! indexed by wallet transfer index.
//!
//! Phone-side facts (Cake v6.4.6, monero 0.18.5.3, from the APK .so + source):
//! - pre-import sanity (`parse_tx_from_str` → `sanity_check_pending_tx_set`):
//!   resolver `kis.at(i)` with `i = ptx.selected_transfers[j]`; bounds CHECK text
//!   "failed loading signed tx: ptx selected transfer is outside the bounds of
//!   imported key images" → our packed 1-entry array with selected=[5] throws
//!   (the tx2 silent exit#4 death; tx1 survived only because selected=[0]).
//! - `import_key_images(signed_txs.key_images)` writes EVERY entry positionally
//!   into `m_transfers[ki_idx]` ("trusting imported one") — so every position
//!   the array covers must carry the TRUE key image of that wallet transfer,
//!   otherwise the phone's spent-tracking is corrupted (observed: our
//!   single-entry array wrote the spent input's KI into transfers[0]).
//!
//! Fixture: the real Cake-built unsigned (`tx2_cake_real_unsigned.bin`),
//! wallet with 8 transfers, `selected_transfers=[5]`, one source. Today the
//! sign path packs one key image per SOURCE → len=1 → `kis.at(5)` out of
//! bounds. The fix (wallet-records face from the pairing beat) must fill
//! positions 0..=max(selected) with true KIs.
//!
//! Keys are the PUBLISHED stagenet-lab test keys (see tests/tx2_whitebox_tools.rs).

use shlosilo::chain::xmr::signed_txset::{decrypt_signed_txset, encrypt_unsigned_txset};
use shlosilo::chain::xmr::unsigned_txset::decrypt_unsigned_txset;
use rand_chacha::rand_core::SeedableRng as _;

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
/// strip `real_out_additional_tx_keys` in the decrypted plaintext so the pin
/// exercises the key_images wire shape, not the F2 selection bug.
fn strip_add_keys(plain: &mut Vec<u8>) {
    let pos = plain
        .windows(32)
        .position(|w| w == TX2_LAB_SRC_TX_KEY)
        .expect("tx_key marker");
    let nkeys = plain[pos + 32];
    assert!(nkeys >= 1 && nkeys < 0x80, "add-keys varint {nkeys}");
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

fn sign_stripped_fixture() -> Vec<[u8; 32]> {
    use shlosilo::business::sign::{sign_with_entropy, SignInput};
    use shlosilo::entropy::mnemonic::Mnemonic;
    use shlosilo::ur::ur_encode::UrTypeTag;

    let enc = include_bytes!("fixtures/tx2_cake_real_unsigned.bin");
    let mut plain = decrypt_unsigned_txset(enc, &TX2_LAB_VIEW_SK)
        .expect("decrypt fixture")
        .to_vec();
    strip_add_keys(&mut plain);
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x22);
    let patched = encrypt_unsigned_txset(
        zeroize::Zeroizing::new(plain),
        &TX2_LAB_VIEW_SK,
        &mut rng,
    )
    .expect("re-encrypt");
    let m = Mnemonic::from_entropy(&[0x22u8; 32]).expect("mnemonic");
    let mut out = vec![0u8; 65536];
    let n = sign_with_entropy(
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &patched,
        &[0x77u8; 32],
        &mut out,
    )
    .expect("sign stripped fixture (control path signs today)");
    let plain = decrypt_signed_txset(&out[..n], &TX2_LAB_VIEW_SK).expect("decrypt signed");
    let (kis, _tki) = parse_signed_tail(&plain);
    kis
}

/// MUST-RED until the wallet-records face lands: the outer key_images array
/// must extend past max(selected_transfers) with TRUE key images everywhere.
#[test]
fn pin_red_signed_container_key_images_wallet_transfer_indexed() {
    let kis = sign_stripped_fixture();
    if kis.len() <= FIXTURE_MAX_SELECTED {
        panic!(
            "PINNED RED: signed container key_images.len()={} but max(selected_transfers)={} — \
             wallet2 0.18.5.3 pre-import check does kis.at({}) -> out of bounds -> \
             \"failed loading signed tx: ptx selected transfer is outside the bounds of \
             imported key images\" (the tx2 silent exit#4). Fix: fill one TRUE key image \
             per wallet transfer position (wallet2.cpp:8074 gold semantics).",
            kis.len(),
            FIXTURE_MAX_SELECTED,
            FIXTURE_MAX_SELECTED
        );
    }
    for (i, ki) in kis.iter().enumerate().take(FIXTURE_MAX_SELECTED + 1) {
        assert_ne!(
            *ki,
            [0u8; 32],
            "key_images[{i}] is a zero placeholder — import_key_images would write it \
             positionally into m_transfers[{i}] and corrupt the phone's spent-tracking"
        );
    }
}
