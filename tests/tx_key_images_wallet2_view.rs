//! I12 pin (WP1 interface-freezing note §2): the sign leg's
//! `tx_key_images` content must follow the wallet2 view.
//!
//! Oracle (wallet2.cpp:8055-8070 `export_key_images`, fill loop): an entry is
//! added for every tx output that is BACK TO THIS WALLET
//! (`is_out_to_acc_precomp`) — the change output and any self-payment, keyed
//! by one-time address. External recipients are NOT recorded. The import side
//! (wallet2.cpp:8304) blindly inserts every entry into `m_cold_key_images`.
//!
//! Current code (forms/business/sign.rs, the splitted_dsts loop) does the
//! INVERSE: it records external receiving outputs and SKIPS the change (the
//! (amount, spend_pub) match). That is real-wallet bookkeeping damage (the
//! change key image misses the cold map; external entries pollute it) and a
//! wrong baseline for the keystone profile (which needs ALL outputs).
//! This pin froze the DESIRED contract and stayed RED until the WP2
//! first-batch fix landed the wallet2-view fill (2026-10-31: identity-based
//! ownership, no amount matching — GPT review 2026-10-30 item 3).
//!
//! Naming history: landed as `pin_red_tx_key_images_wallet2_view_includes_change`
//! (MUST-RED, 2026-10-31, per the red-pin convention 2026-10-20) and renamed
//! to its invariant name the same day when the WP2 first-batch fix turned it
//! green (fix36-style: red pins carry the pin_red_ prefix only while red).

#![cfg(feature = "alloc-fallback")]

use rand_chacha::rand_core::SeedableRng as _;
use shlosilo::business::sign::WalletKiRecord;
use shlosilo::chain::xmr::signed_txset::{
    decrypt_signed_txset, deserialize_signed_plain, encrypt_unsigned_txset, PendingTx,
    SignedTxSetPools, TxKeyImageEntry,
};
use shlosilo::chain::xmr::subaddress::calc_output_key_offset;
use shlosilo::chain::xmr::transaction::TransactionPrefix;
use shlosilo::chain::xmr::unsigned_txset::{
    decrypt_unsigned_txset, TxDestinationEntry, TxSourceEntry,
};

const TX2_LAB_VIEW_SK: [u8; 32] = [
    0xdb, 0x93, 0xce, 0x63, 0x2d, 0x8d, 0x31, 0xe3, 0x1b, 0xd0, 0xb4, 0xec, 0xbd, 0xbd, 0xb8, 0x33,
    0xca, 0xe8, 0x13, 0x92, 0x8a, 0xf4, 0x02, 0xc5, 0xb7, 0xff, 0xeb, 0x85, 0x76, 0x9c, 0xf0, 0x00,
];

/// The fixture wallet keys (same seed path as the sign harness:
/// Mnemonic::from_entropy([0x22;32]) -> restore_seed -> MoneroPath::mainnet(0)).
fn wallet_keys() -> ([u8; 32], [u8; 32]) {
    use shlosilo::business::restore_seed::restore_seed;
    use shlosilo::derivation::monero_reduce_scalar::{derive, MoneroPath};
    use shlosilo::entropy::mnemonic::Mnemonic;

    let m = Mnemonic::from_entropy(&[0x22u8; 32]).expect("mnemonic");
    let mut seed = [0u8; 64];
    restore_seed(&m, b"", &mut seed).expect("restore seed");
    let kp = derive(&seed, &MoneroPath::mainnet(0)).expect("derive monero path");
    (
        shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv()),
        shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv()),
    )
}

/// One tx_key_images wire entry: (output one-time address, key image).
type TkiEntry = ([u8; 32], [u8; 32]);
/// (outer key_images, tx_key_images entries) parsed from the signed tail.
type SignedTail = (Vec<[u8; 32]>, Vec<TkiEntry>);

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

/// Tail parse (same shape as tests/pin_signed_key_images_wallet_indexed.rs),
/// extended to return the tx_key_images entries:
/// `... ptx | varint ki_count | ki_count*32B | varint tki_count | tki_count*65B`.
fn parse_signed_tail(plain: &[u8]) -> SignedTail {
    let len = plain.len();
    let mut candidates: Vec<SignedTail> = Vec::new();
    for tki_count in 0..=8usize {
        let entries_len = tki_count * 65;
        let Some((c1, v1_start)) = varint_ending_at(plain, len - entries_len) else {
            continue;
        };
        if c1 != tki_count as u64 {
            continue;
        }
        let ki_section_end = v1_start;
        // 0..=64: the keystone view ships an EMPTY positional array (I4).
        for ki_count in 0..=64usize {
            let Some((c2, v2_start)) = varint_ending_at(plain, ki_section_end - ki_count * 32)
            else {
                continue;
            };
            if c2 != ki_count as u64 {
                continue;
            }
            if v2_start < 2 || plain[0] != 0x00 || plain[1] != 0x01 {
                continue;
            }
            let mut kis = Vec::with_capacity(ki_count);
            let ki_start = ki_section_end - ki_count * 32;
            for i in 0..ki_count {
                let mut k = [0u8; 32];
                k.copy_from_slice(&plain[ki_start + i * 32..ki_start + (i + 1) * 32]);
                kis.push(k);
            }
            let mut tkis = Vec::with_capacity(tki_count);
            let tki_start = len - entries_len;
            for i in 0..tki_count {
                let e = &plain[tki_start + i * 65..tki_start + (i + 1) * 65];
                assert_eq!(e[0], 0x02, "tx_key_images entry tag");
                let mut p = [0u8; 32];
                p.copy_from_slice(&e[1..33]);
                let mut k = [0u8; 32];
                k.copy_from_slice(&e[33..65]);
                tkis.push((p, k));
            }
            candidates.push((kis, tkis));
        }
    }
    assert_eq!(candidates.len(), 1, "tail parse ambiguity");
    candidates.pop().expect("non-empty")
}

fn strip_add_keys(plain: &mut Vec<u8>) {
    const TX2_LAB_SRC_TX_KEY: [u8; 32] = [
        0xd2, 0x3c, 0xb1, 0xc2, 0x9b, 0xd8, 0xd6, 0x25, 0xcf, 0x92, 0x2b, 0xcc, 0x13, 0xad, 0xb1,
        0x1e, 0xa7, 0x43, 0x77, 0x87, 0xb7, 0x4c, 0xaf, 0x98, 0x9c, 0x4c, 0xf4, 0x89, 0x9d, 0x09,
        0x1a, 0x34,
    ];
    let pos = plain
        .windows(32)
        .position(|w| w == TX2_LAB_SRC_TX_KEY)
        .expect("tx_key marker");
    let nkeys = plain[pos + 32];
    assert!((1..0x80).contains(&nkeys), "add-keys varint {nkeys}");
    plain[pos + 32] = 0;
    plain.drain(pos + 33..pos + 33 + nkeys as usize * 32);
}

fn fixture_gap_records() -> Vec<WalletKiRecord> {
    use shlosilo::business::restore_seed::restore_seed;
    use shlosilo::business::sign::{wallet_fingerprint_from_seed, WalletKiRecord};
    use shlosilo::entropy::mnemonic::Mnemonic;

    let m = Mnemonic::from_entropy(&[0x22u8; 32]).expect("mnemonic");
    let mut seed = [0u8; 64];
    restore_seed(&m, b"", &mut seed).expect("restore seed");
    let fp = wallet_fingerprint_from_seed(&seed);
    (0..=4u32)
        .map(|i| WalletKiRecord {
            transfer_idx: i,
            wallet_fp: fp,
            key_image: [0x11u8.wrapping_add(i as u8); 32],
            // I13 (WP3, Kosmo decision 2026-10-31): the mapping key rides the
            // record. Distinct per-record pattern so the pin can prove the
            // wire carries RECORD-sourced out_pubs (not derivable ones).
            out_pub: [0xA0u8.wrapping_add(i as u8); 32],
        })
        .collect()
}

/// Drive the real sign path over the add-keys-stripped tx2 fixture and return
/// the signed plaintext.
fn sign_fixture_plain() -> Vec<u8> {
    use shlosilo::business::sign::{sign_with_entropy_records, SignInput};
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
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &patched,
        &fixture_gap_records(),
        &[0x77u8; 32],
        &mut out,
    )
    .expect("sign fixture");
    let plain = decrypt_signed_txset(&out[..n], &TX2_LAB_VIEW_SK).expect("decrypt signed");
    plain.to_vec()
}

/// The same fixture drive with an explicit wire-tail view (WP3): the canonical
/// enum maps onto the dialect tails — Cake view by default.
fn sign_fixture_plain_with_tail(tail: shlosilo::canonical::TailView) -> Vec<u8> {
    use shlosilo::business::sign::{sign_with_entropy_ws_views, SignInput};
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
    let n = sign_with_entropy_ws_views(
        tail,
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        &patched,
        &fixture_gap_records(),
        &[0x77u8; 32],
        None,
        &mut out,
    )
    .expect("sign fixture");
    let plain = decrypt_signed_txset(&out[..n], &TX2_LAB_VIEW_SK).expect("decrypt signed");
    plain.to_vec()
}

/// THE RED PIN: tx_key_images must equal the wallet2 view of the tx — the set
/// of output one-time addresses owned by THIS wallet (change + self-pay),
/// decided by DERIVED IDENTITY (never by amount matching).
#[test]
fn tx_key_images_wallet2_view_includes_change() {
    let (spend_sk, view_sk) = wallet_keys();
    assert_eq!(view_sk, TX2_LAB_VIEW_SK, "derivation-chain guard");

    let plain = sign_fixture_plain();

    // ── what the sign leg recorded ────────────────────────────────────────
    let (_kis, tkis) = parse_signed_tail(&plain);
    let recorded: std::collections::BTreeSet<[u8; 32]> = tkis.iter().map(|(p, _k)| *p).collect();

    // ── what wallet2's is_out_to_acc says the set must be ─────────────────
    // Parse the signed plain model to reach the tx wire + construction data.
    let mut p_txes = core::array::from_fn::<Option<PendingTx<'_>>, 2, _>(|_| None);
    let mut sel = [0u8; 64];
    let mut ki_str = [0u8; 4096];
    let mut dests =
        core::array::from_fn::<TxDestinationEntry, 16, _>(|_| TxDestinationEntry::default());
    let mut sources = core::array::from_fn::<Option<TxSourceEntry>, 32, _>(|_| None);
    let mut splitted =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut cons_sel = [0usize; 256];
    let mut extra = [0u8; 8192];
    let mut cons_dests =
        core::array::from_fn::<TxDestinationEntry, 64, _>(|_| TxDestinationEntry::default());
    let mut subidx = [0u32; 256];
    let mut key_images = [[0u8; 32]; 16];
    let mut tx_key_images =
        core::array::from_fn::<TxKeyImageEntry, 16, _>(|_| TxKeyImageEntry::default());
    let set = deserialize_signed_plain(
        &plain,
        &mut SignedTxSetPools {
            ptx: &mut p_txes,
            sel: &mut sel,
            ki_str: &mut ki_str,
            dests: &mut dests,
            sources: &mut sources,
            splitted: &mut splitted,
            cons_sel: &mut cons_sel,
            extra: &mut extra,
            cons_dests: &mut cons_dests,
            subidx: &mut subidx,
            key_images: &mut key_images,
            tx_key_images: &mut tx_key_images,
        },
    )
    .expect("parse signed plain");

    // cross-check: the model's view of the wire records matches the tail parse
    let model_pubs: std::collections::BTreeSet<[u8; 32]> = set
        .tx_key_images
        .iter()
        .map(|e: &TxKeyImageEntry| e.output_pubkey)
        .collect();
    assert_eq!(model_pubs, recorded, "model and tail agree on the wire set");

    let ptx = set.ptx.iter().flatten().next().expect("one pending tx");
    let mut pos = 0usize;
    let prefix = TransactionPrefix::deserialize(ptx.tx_bytes, &mut pos).expect("tx prefix");
    let tx_pub = prefix.extra.tx_pub_key.expect("tx pub key in extra");
    let additional = &prefix.extra.additional_pub_keys;

    // wallet2 is_out_to_acc_precomp equivalence for THIS wallet (main-address
    // base (0,0); branch 1 = main tx pubkey, branch 2 = additional[i]).
    // Ownership is decided by DERIVED IDENTITY against the stealth address.
    let mut owned = std::collections::BTreeSet::<[u8; 32]>::new();
    for (i, out) in prefix.outputs[..prefix.outputs_len].iter().enumerate() {
        let try_key = |key: &[u8; 32]| -> bool {
            let Ok(off) = calc_output_key_offset(&view_sk, key, i as u64, 0, 0) else {
                return false;
            };
            use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
            use curve25519_dalek::scalar::Scalar;
            let sk = Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(off);
            (ED25519_BASEPOINT_TABLE * &sk).compress().to_bytes() == out.stealth_address
        };
        let owned_here = try_key(&tx_pub) || additional.get(i).map(try_key).unwrap_or(false);
        if owned_here {
            owned.insert(out.stealth_address);
        }
    }

    assert_eq!(
        recorded, owned,
        "(I12): tx_key_images must be the wallet2 view — every \
         wallet-owned output (change + self-pay) included, external \
         recipients excluded (oracle: wallet2.cpp:8055-8070 is_out_to_acc \
         fill loop; today's sign.rs inverted filter is the known defect)"
    );
}

/// WP3 I4 wire pin: the keystone view's tail = EMPTY positional `key_images`
/// plus the two-fill `tx_key_images` map — ALL new outputs first (external
/// included), then the retained transfer KIs (keystone transfer.rs:1250-1271
/// two-fill order). Cross-checked against the Cake view of the same fixture.
#[test]
fn keystone_wire_is_empty_positional_plus_two_fill_map() {
    use shlosilo::canonical::{KeyImagesPositionalView, TailView, TxKeyImagesView};

    let cake_plain = sign_fixture_plain();
    let ks_plain = sign_fixture_plain_with_tail(TailView {
        key_images: KeyImagesPositionalView::Empty,
        tx_key_images: TxKeyImagesView::AllPlusRetained,
    });
    let (cake_kis, cake_tkis) = parse_signed_tail(&cake_plain);
    let (ks_kis, ks_tkis) = parse_signed_tail(&ks_plain);
    let _ = &cake_kis; // the outer Cake array's content is pinned by the I12 test

    // I4: the positional array stays empty on the keystone view.
    assert!(
        ks_kis.is_empty(),
        "I4: keystone positional key_images must be empty, got {}",
        ks_kis.len()
    );

    // The new-outputs leg (first): byte-identical to the Cake view's map on
    // this all-owned fixture — every new output, ownership ignored.
    let retained_start = cake_tkis.len();
    assert!(
        ks_tkis.len() > retained_start,
        "the two-fill map must carry the retained leg"
    );
    assert_eq!(
        &ks_tkis[..retained_start],
        &cake_tkis[..],
        "new-outputs leg matches the Cake view (all-owned fixture)"
    );

    // The retained leg (second): the FULL retention set — every fp-matched
    // record, spent or not (keystone's transfers.details loop parity,
    // transfer.rs:1271). The out_pub KEYS come from the records themselves
    // (I13): a spent source's derivable out_pub cannot fake this — the
    // unspent records' pattern keys are only reachable through the record.
    assert_eq!(
        ks_tkis.len(),
        retained_start + 5,
        "the two-fill map must carry the FULL retention set (5 fixture records),          not just the spent source(s)"
    );
    for (e, i) in ks_tkis[retained_start..].iter().zip(0u8..5) {
        assert_eq!(
            e.0,
            [0xA0u8.wrapping_add(i); 32],
            "retained leg keys ride the RECORDS (I13) — record {}",
            i
        );
        assert_eq!(
            e.1,
            [0x11u8.wrapping_add(i); 32],
            "retained leg KIs are the record KIs (transfer_idx order)"
        );
    }
}
