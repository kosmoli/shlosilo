//! Golden decrypt-face pins for the real-wallet ciphertext fixtures (the
//! "p2in" family: the money-flow wallet `489yTDD…` and its counterparties).
//!
//! Fixture-key policy (Kosmo, 2026-10-20): test-wallet keys may be embedded
//! in the repository in exchange for CI-enforced coverage — the same ruling
//! that admitted `TEST0830_*_SK_HEX` (tests/golden_wallet2_bytes.rs) and
//! `TX2_LAB_VIEW_SK` (tests/tx2_whitebox_tools.rs). This supersedes the
//! earlier "real-wallet receipts stay env-gated" clause: the p2in view key
//! (and, where the address face needs it, the spend key) is embedded below
//! and every pin runs unconditionally in CI — no env gating.
//!
//! Key provenance and privacy assessment:
//!
//! * `P2IN_*` = the p2in funding/relay test wallet (full wallet
//!   `shlosilo_p2in`, watch-only `sh_p2in_view`; address `489yTDD…`), the
//!   wallet that funded and received the fixture transactions. Source:
//!   `~/monero-test-wallets/keys.env` (test-only key file, chmod 600, never
//!   committed).
//! * `DEV_*` = the device deterministic test wallet A' (address `4844Nk4X…`),
//!   same bytes as tests/golden_wallet2_bytes.rs::DEV_SPEND_SK / DEV_VIEW_SK
//!   (repeated here so this file is self-contained).
//! * Privacy: both wallets are mainnet **dust-class** test wallets (balances
//!   in the 0.001 XMR range; see tests/fixtures/README.md) with no real
//!   funds. The embedded spend secrets are used only to derive the public
//!   spend keys that pin the destination-address face of the fixtures; the
//!   ciphertext fixtures themselves contain no spend secrets.
//!
//! Fixture -> decrypt key (each mapping verified via the envelope Schnorr
//! signature against the wallet's view public key, pinned below):
//!
//! * `unsigned_txset_2in.bin`        -> P2IN view key
//! * `unsigned_txset_2in_dev.bin`    -> DEV view key
//! * `unsigned_txset_1in_fresh.bin`  -> DEV view key
//! * `signed_txset_1in_fresh.bin`    -> DEV view key
//!
//! Pinned faces per fixture (mirroring tests/golden_wallet2_bytes.rs):
//!
//! * unsigned fixtures: envelope signature verifies under the owner's view
//!   public key (and NOT under the other family's key), container decrypt,
//!   whole-plaintext byte identity (keccak256 golden — the plaintext is not
//!   stored as a fixture because wallet2 plaintexts carry one-time output
//!   secrets such as `real_out_tx_key` / masks), and parse -> re-serialize
//!   byte identity over the parsed span (including the `construction_data`
//!   extra field — the pool-#39 extra-drop gap is fixed as of 2026-10-20;
//!   same contract as tests/golden_wallet2_bytes.rs::roundtrip_unsigned_plain)
//!   plus the trailing transfers-segment length as a golden wire fact.
//! * field-level pins: input count, per-input amounts / ring size / real
//!   output indices, fee arithmetic, change and destination public keys
//!   (= the target addresses), use_rct, selected_transfers / subaddr indices.
//! * `signed_txset_1in_fresh.bin`: container decrypt + whole-plaintext
//!   keccak256 golden + a field walk of the deterministic tx prefix
//!   (input count, ring offsets, key image, output count / keys / view tags,
//!   extra).
//!
//! Known gaps (not pinned, never fabricated):
//!
//! * signed plaintext parse -> re-serialize identity: forms has no
//!   `signed_txset` deserializer (details pool §52 "signed 明文无
//!   deserializer"), so only the decrypt side of the signed fixture is
//!   byte-compared. Same gap as tests/golden_wallet2_bytes.rs Group B.
//! * `unsigned_txset.bin` / `txset_plain.bin` (Feather wallet-rpc, P6.3):
//!   the producing wallet is an independent wallet whose view key is not in
//!   keys.env — its decrypt face stays env-gated (tests/p63_xmr_unsigned.rs
//!   X7) and is out of scope here.
//!
//! Run: cargo test --offline --test golden_p2in_decrypt
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::xmr::signed_txset::decrypt_signed_txset;
use shlosilo::chain::xmr::unsigned_txset::{
    decrypt_unsigned_txset, deserialize_unsigned_tx, serialize_unsigned_tx,
    verify_monero_signature_pubkey, TxConstructionData, TxDestinationEntry, TxSourceEntry,
    UnsignedTx, UnsignedTxPools,
};

// ---------------------------------------------------------------------------
// Fixture keys — source: ~/monero-test-wallets/keys.env (test wallets only).
// See the header for provenance, the privacy assessment, and the 2026-10-20
// fixture-key policy basis.
// ---------------------------------------------------------------------------

/// p2in test wallet (shlosilo_p2in / sh_p2in_view) view secret key —
/// the decrypt key of fixtures/unsigned_txset_2in.bin. Test-only key.
const P2IN_VIEW_SK: [u8; 32] = [
    0x26, 0xd2, 0x92, 0x48, 0x48, 0x5b, 0x24, 0x64, 0x5e, 0xc1, 0xba, 0x4a, 0xef, 0xf5, 0x01, 0xed,
    0xad, 0x5c, 0xd7, 0x4a, 0x81, 0xf4, 0xbc, 0x4b, 0x14, 0x4a, 0x9a, 0x6f, 0x0f, 0x95, 0xdf, 0x07,
];

/// p2in test wallet spend secret key — test-only. Embedded (2026-10-20
/// fixture-key policy) solely so the destination-address face can be pinned
/// against the derived spend public key; never used for signing here.
const P2IN_SPEND_SK: [u8; 32] = [
    0x8d, 0x81, 0x35, 0x14, 0x80, 0xfd, 0x2b, 0xdd, 0x02, 0xbd, 0x30, 0x8d, 0x1d, 0x78, 0xd5, 0xe8,
    0x36, 0xf7, 0x23, 0x32, 0x78, 0xeb, 0x29, 0xb3, 0xbb, 0x00, 0x64, 0xbd, 0x1a, 0xbc, 0xd7, 0x06,
];

/// DEV test wallet A' view secret key — decrypt key of
/// unsigned_txset_2in_dev.bin / unsigned_txset_1in_fresh.bin /
/// signed_txset_1in_fresh.bin. Same bytes as
/// tests/golden_wallet2_bytes.rs::DEV_VIEW_SK. Test-only key.
const DEV_VIEW_SK: [u8; 32] = [
    0xdd, 0x87, 0x2c, 0xe8, 0x67, 0x39, 0xd7, 0x8d, 0xf0, 0x71, 0xd7, 0xf9, 0xef, 0x72, 0x91, 0x3b,
    0xd5, 0xf3, 0xc2, 0xdb, 0x02, 0xcb, 0x55, 0x5c, 0x24, 0x4b, 0x07, 0x6e, 0xfa, 0x5a, 0x9a, 0x0f,
];

/// DEV test wallet A' spend secret key — same bytes as
/// tests/golden_wallet2_bytes.rs::DEV_SPEND_SK. Test-only key; used only to
/// derive the change-address face anchor.
const DEV_SPEND_SK: [u8; 32] = [
    0xd8, 0xcd, 0x34, 0xaf, 0xac, 0x38, 0xfe, 0x95, 0xa2, 0x04, 0x39, 0xc2, 0x73, 0x8c, 0xb5, 0xfa,
    0xc0, 0xad, 0x29, 0x97, 0xe8, 0x35, 0x16, 0x45, 0x4b, 0x70, 0x20, 0x33, 0xb3, 0xed, 0xa5, 0x03,
];

/// p2in canonical address (keys.env P2IN_ADDRESS). Public data — the anchor
/// that ties the embedded p2in keys to the wallet identity in the fixtures.
const P2IN_ADDRESS: &str = "489yTDD88yiPuwTWTEwvYX7jqQbfmBp496rqiYwmuEtXithY5mAsXmsPJCc9xU8MFr66c7Yv91KgcGZAgddZ75Xs93qBWLM";

/// DEV wallet A' canonical address (keys.env DEV_WALLET_ADDRESS). Public data.
const DEV_ADDRESS: &str = "4844Nk4Xb2K2HcxUkfQSaLiJFHikLALiKX7re6aHrw1q8RUDg921rQTcwvwS4C8dK5YnUv3PHGHJQjaMyaxSfCEz7D6q5nM";

// ---------------------------------------------------------------------------
// Golden public keys (derived from the embedded secrets; asserted against
// these constants in the anchor test so a transcription slip fails loudly).
// ---------------------------------------------------------------------------

/// p2in spend public key (= P2IN_SPEND_SK * G).
const P2IN_SPEND_PUB: [u8; 32] = [
    0xac, 0x5f, 0x7d, 0x88, 0x7c, 0x58, 0xad, 0x88, 0xfc, 0x7f, 0x90, 0x66, 0xba, 0x3c, 0x58, 0x28,
    0x49, 0x7a, 0x6c, 0x2a, 0x04, 0x56, 0x62, 0x23, 0x07, 0xd0, 0x3e, 0xc0, 0x18, 0x43, 0x60, 0xfa,
];

/// p2in view public key (= P2IN_VIEW_SK * G).
const P2IN_VIEW_PUB: [u8; 32] = [
    0x73, 0xbb, 0x72, 0x20, 0x05, 0xb5, 0xc2, 0x85, 0x4d, 0x69, 0x08, 0x4f, 0x46, 0x45, 0xd5, 0x1e,
    0x78, 0x89, 0x7f, 0x7b, 0x67, 0xb1, 0xe1, 0x5c, 0xfe, 0xb1, 0x50, 0xef, 0x38, 0x24, 0x7e, 0x47,
];

/// DEV wallet A' spend public key (= DEV_SPEND_SK * G).
const DEV_SPEND_PUB: [u8; 32] = [
    0xa9, 0xae, 0x8a, 0x4d, 0xb4, 0x60, 0x94, 0x07, 0xb1, 0x18, 0xc1, 0xe7, 0x8b, 0x6d, 0x29, 0xf6,
    0xe6, 0x96, 0x29, 0x2e, 0xcf, 0x9c, 0xc0, 0xb4, 0x10, 0xa2, 0x76, 0xe7, 0xc1, 0xaa, 0xd0, 0x2c,
];

/// DEV wallet A' view public key (= DEV_VIEW_SK * G).
const DEV_VIEW_PUB: [u8; 32] = [
    0x5f, 0x5f, 0x36, 0x3c, 0x8c, 0x9c, 0x04, 0xd6, 0xe9, 0xd9, 0xde, 0x1e, 0x89, 0xf5, 0x10, 0xbe,
    0x06, 0x6b, 0x76, 0x9f, 0x93, 0xcd, 0x49, 0xfe, 0x8a, 0x5d, 0xdb, 0x76, 0x8c, 0x91, 0xd7, 0x37,
];

/// Payment target of unsigned_txset_2in.bin (0.0007 XMR): an external
/// counterparty address read off the fixture wire — NOT a keys.env wallet.
/// Pinned as a golden wire fact so the destination face cannot drift.
const DEST_2IN_SPEND_PUB: [u8; 32] = [
    0x64, 0xc9, 0xd0, 0x24, 0xa0, 0x6e, 0x47, 0x10, 0x24, 0x08, 0x70, 0x79, 0x2e, 0x65, 0xb1, 0x98,
    0xcb, 0xdd, 0x79, 0x5a, 0x02, 0x15, 0xf2, 0xd9, 0x34, 0xba, 0xc5, 0x8e, 0x13, 0x15, 0x54, 0x3f,
];

/// Payment target view public key of unsigned_txset_2in.bin (see above).
const DEST_2IN_VIEW_PUB: [u8; 32] = [
    0xd4, 0xa7, 0xc5, 0xe3, 0x7d, 0x46, 0x5b, 0x1b, 0xfb, 0xb2, 0xe6, 0xc3, 0x06, 0xb5, 0xa6, 0xe8,
    0x12, 0x57, 0x4d, 0xe9, 0x28, 0xe0, 0xe3, 0xcc, 0xce, 0xc4, 0xfe, 0x39, 0x9d, 0x91, 0x99, 0xf2,
];

// ---------------------------------------------------------------------------
// Whole-plaintext byte-identity goldens (keccak256 of the decrypted
// plaintext). The plaintexts themselves are deliberately NOT stored as
// fixtures: wallet2 plaintexts carry one-time output secrets
// (real_out_tx_key / mask / multisig k), so the golden is kept in hash form —
// same byte-identity claim, no new secret-bearing file.
// ---------------------------------------------------------------------------

/// keccak256 of the decrypted unsigned_txset_2in.bin plaintext (3434B).
const P2IN_2IN_PLAIN_KECCAK_HEX: &str =
    "7a0ccd904189f51672d5442fb6539f51af49af8980d76d9061808a90ba6ca134";

/// keccak256 of the decrypted unsigned_txset_2in_dev.bin plaintext (3355B).
const DEV_2IN_PLAIN_KECCAK_HEX: &str =
    "652ce17136820642a74634fd2d8b111b32ec6aa54fe7e44d46719a1525c66073";

/// keccak256 of the decrypted unsigned_txset_1in_fresh.bin plaintext (1875B).
const DEV_1IN_PLAIN_KECCAK_HEX: &str =
    "12b05a77bab49c52cdcfbd2c7e09ba15accb0a8aa314e5c77f9d839b320a04eb";

/// keccak256 of the decrypted signed_txset_1in_fresh.bin plaintext (3893B).
const DEV_SIGNED_1IN_PLAIN_KECCAK_HEX: &str =
    "d79a0df3049530088c05ebb20595022ca7bde1196507d05e505932002c48c201";

/// First key image of the signed_txset_1in_fresh.bin plaintext — a
/// deterministic value (x * Hp(P) of the one-time input secret), wallet2-
/// accepted on chain (tx 2d2c40d1…, 2026-09-15).
const DEV_SIGNED_1IN_KEY_IMAGE_HEX: &str =
    "9258618348b35049aff5d40e036e0f357812683d60c8c562719b7509c77571cb";

/// vout[0] stealth address (tagged key) of the signed plaintext.
const DEV_SIGNED_1IN_OUT0_KEY_HEX: &str =
    "e80d2bc04a8908c5f6b5484069188985d0ee14f7dd425e4f8c1034a83b406587";

/// vout[1] stealth address (tagged key) of the signed plaintext.
const DEV_SIGNED_1IN_OUT1_KEY_HEX: &str =
    "3cf549952256db30c88e70674ff857729a47b50ab48d01170478079a2bf5c750";

/// tx extra of the signed plaintext (44B: tx pub key tag + encrypted
/// payment id nonce).
const DEV_SIGNED_1IN_EXTRA_HEX: &str =
    "01b5e54ffb5ac0bfc7e9f669fdc8d0cdf553143ccf389eba98b1c42dc8d8a6dfa402090123c562e3522e1cdb";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Monero-correct pubkey: raw_scalar * G. NOT ed25519-dalek's RFC-8032
/// clamped derivation (`curve_primitive::ed25519::base_mul` clamps and yields
/// a different wallet); same pattern as tests/p64_xmr_multi_input.rs.
fn monero_pub(sec: &[u8; 32]) -> shlosilo::curve_primitive::ed25519::Ed25519Point {
    use shlosilo::curve_primitive::ed25519::point_from_compressed;
    let s = curve25519_dalek::Scalar::from_bytes_mod_order(*sec);
    let compressed = (curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &s)
        .compress()
        .to_bytes();
    point_from_compressed(&compressed).expect("valid point")
}

fn monero_pub_bytes(sec: &[u8; 32]) -> [u8; 32] {
    use shlosilo::curve_primitive::ed25519::point_to_compressed;
    point_to_compressed(&monero_pub(sec))
}

/// Container envelope face: the wallet2 container carries
/// `magic || nonce || ciphertext || 64B Monero Schnorr` — the signature is
/// computed by wallet2 under the wallet's VIEW secret key, so verifying it
/// under the derived view public key proves the fixture belongs to that
/// wallet (and decrypts under its view key).
fn assert_envelope_verifies(container: &[u8], magic: &[u8], owner_view_sk: &[u8; 32]) {
    let raw = &container[magic.len()..container.len() - 64];
    let sig = &container[container.len() - 64..];
    let msg_hash = shlosilo::encoding::keccak256::hash(raw).expect("keccak");
    let owner_pub = monero_pub_bytes(owner_view_sk);
    assert!(
        verify_monero_signature_pubkey(&msg_hash, &owner_pub, sig)
            .expect("envelope signature check"),
        "container envelope must verify under the owner wallet's view public key"
    );
}

fn assert_envelope_rejects(container: &[u8], magic: &[u8], other_view_sk: &[u8; 32]) {
    let raw = &container[magic.len()..container.len() - 64];
    let sig = &container[container.len() - 64..];
    let msg_hash = shlosilo::encoding::keccak256::hash(raw).expect("keccak");
    let other_pub = monero_pub_bytes(other_view_sk);
    assert!(
        !verify_monero_signature_pubkey(&msg_hash, &other_pub, sig).expect("envelope check"),
        "envelope is key-bound: it must NOT verify under the other wallet's view key"
    );
}

/// Parse a wallet2-produced unsigned plaintext against caller pools and hand
/// the parsed model to `f`.
fn with_parsed_unsigned<R>(plain: &[u8], f: impl FnOnce(&UnsignedTx<'_>) -> R) -> R {
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
        plain,
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
    .expect("deserialize wallet2-produced unsigned plaintext");
    f(&utx)
}

/// Parse -> re-serialize byte identity, ported from
/// tests/golden_wallet2_bytes.rs::roundtrip_unsigned_plain (same contract):
/// full byte identity over the parsed span INCLUDING the `construction_data`
/// extra field (the pool-#39 extra-drop gap is fixed as of 2026-10-20), and
/// returns the trailing transfers-display segment length (the writer does not
/// emit it — a per-fixture golden wire fact). Any divergence is a NEW bug and
/// panics loudly.
fn roundtrip_unsigned_plain(plain: &[u8]) -> usize {
    let out = with_parsed_unsigned(plain, |utx| {
        assert_eq!(
            utx.txes.iter().flatten().count(),
            1,
            "golden fixtures are single-tx (helper assumption)"
        );
        serialize_unsigned_tx(utx)
    });
    assert!(
        plain.len() >= out.len(),
        "re-serialized txes segment ({}B) longer than the wallet2 plaintext ({}B)",
        out.len(),
        plain.len()
    );
    if plain[..out.len()] != out[..] {
        let i = plain[..out.len()]
            .iter()
            .zip(out.iter())
            .position(|(a, b)| a != b)
            .expect("lengths differ but no byte mismatch?");
        let lo = i.saturating_sub(8);
        let hi = (i + 24).min(out.len());
        panic!(
            "NEW parse -> re-serialize divergence at plain offset {i} (construction_data.extra \
             must be preserved; the old extra-drop gap is fixed)\n  \
             plain[{}..{}]: {:02x?}\n  ours [{}..{}]: {:02x?}",
            lo,
            hi,
            &plain[lo..hi],
            lo,
            hi,
            &out[lo..hi]
        );
    }
    plain.len() - out.len()
}

/// Decrypt a wallet2 unsigned container into its plaintext.
fn unsigned_plain(container: &[u8], view_sk: &[u8; 32]) -> zeroize::Zeroizing<Vec<u8>> {
    decrypt_unsigned_txset(container, view_sk).expect("decrypt wallet2 unsigned container")
}

fn assert_plain_keccak(plain: &[u8], golden_hex: &str) {
    let h = shlosilo::encoding::keccak256::hash(plain).expect("keccak");
    assert_eq!(
        hex(&h),
        golden_hex,
        "decrypted plaintext must be byte-identical to the golden (keccak form)"
    );
}

fn assert_dest(d: &TxDestinationEntry, amount: u64, spend_pub: &[u8; 32], view_pub: &[u8; 32]) {
    assert_eq!(d.amount, amount, "destination amount");
    assert_eq!(
        &d.spend_public_key, spend_pub,
        "destination spend public key"
    );
    assert_eq!(&d.view_public_key, view_pub, "destination view public key");
    assert!(!d.is_subaddress, "fixture destinations are main addresses");
    assert!(!d.is_integrated, "fixture destinations are not integrated");
}

// ---------------------------------------------------------------------------
// Group 0 — key anchor: the embedded secrets must reproduce the canonical
// wallet addresses and the golden public keys (transcription guard).
// ---------------------------------------------------------------------------

#[test]
fn fixture_keys_anchor_to_wallet_addresses_and_public_keys() {
    use shlosilo::address::xmr::encode;
    use shlosilo::network::Network;
    for (label, spend_sk, view_sk, address, spend_pub_gold, view_pub_gold) in [
        (
            "p2in",
            &P2IN_SPEND_SK,
            &P2IN_VIEW_SK,
            P2IN_ADDRESS,
            &P2IN_SPEND_PUB,
            &P2IN_VIEW_PUB,
        ),
        (
            "dev",
            &DEV_SPEND_SK,
            &DEV_VIEW_SK,
            DEV_ADDRESS,
            &DEV_SPEND_PUB,
            &DEV_VIEW_PUB,
        ),
    ] {
        assert_eq!(
            &monero_pub_bytes(spend_sk),
            spend_pub_gold,
            "{label} spend public key"
        );
        assert_eq!(
            &monero_pub_bytes(view_sk),
            view_pub_gold,
            "{label} view public key"
        );
        let derived = encode(
            &monero_pub(spend_sk),
            &monero_pub(view_sk),
            Network::MoneroMainnet,
        )
        .expect("address encode");
        assert_eq!(
            derived.as_ref(),
            address,
            "{label} embedded keys must reproduce the canonical wallet address"
        );
    }
}

// ---------------------------------------------------------------------------
// Group A — p2in: unsigned_txset_2in.bin (2-input, 0.0007 XMR to an external
// address; produced by the sh_p2in_view watch-only `transfer`).
// ---------------------------------------------------------------------------

#[test]
fn p2in_2in_envelope_decrypt_and_parse_reserialize_identity() {
    use shlosilo::chain::xmr::unsigned_txset::UNSIGNED_TX_PREFIX;
    let enc: &[u8] = include_bytes!("fixtures/unsigned_txset_2in.bin");
    assert_envelope_verifies(enc, UNSIGNED_TX_PREFIX, &P2IN_VIEW_SK);
    assert_envelope_rejects(enc, UNSIGNED_TX_PREFIX, &DEV_VIEW_SK);
    let plain = unsigned_plain(enc, &P2IN_VIEW_SK);
    assert_eq!(plain.len(), 3434, "golden plaintext length");
    assert_plain_keccak(&plain, P2IN_2IN_PLAIN_KECCAK_HEX);
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        241,
        "golden wire fact: 241B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

#[test]
fn p2in_2in_field_level_golden() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_txset_2in.bin");
    let plain = unsigned_plain(enc, &P2IN_VIEW_SK);
    with_parsed_unsigned(&plain, |utx| {
        assert_eq!(utx.txes.iter().flatten().count(), 1, "single tx");
        let tx = utx.txes.iter().flatten().next().unwrap();
        let srcs: Vec<_> = tx.sources.iter().flatten().collect();
        assert_eq!(srcs.len(), 2, "golden input count");
        assert_eq!(srcs[0].amount, 500_000_000, "input 0 amount (0.0005 XMR)");
        assert_eq!(srcs[1].amount, 500_000_000, "input 1 amount (0.0005 XMR)");
        for (i, s) in srcs.iter().enumerate() {
            assert_eq!(s.outputs.len(), 16, "input {i} ring size 16");
            assert!(s.rct, "input {i} is RingCT");
            assert!(
                s.real_out_additional_tx_keys.is_empty(),
                "input {i} carries no additional tx keys"
            );
        }
        assert_eq!(srcs[0].real_output, 15, "input 0 real ring index");
        assert_eq!(srcs[1].real_output, 11, "input 1 real ring index");
        assert_eq!(srcs[0].real_output_in_tx_index, 0, "input 0 in-tx index");
        assert_eq!(srcs[1].real_output_in_tx_index, 1, "input 1 in-tx index");

        assert_eq!(tx.unlock_time, 0, "golden unlock time");
        assert_eq!(tx.use_rct, 3, "golden RCT type (RingCT simple)");

        // Change goes back to the p2in wallet itself.
        assert_dest(&tx.change_dts, 255_560_000, &P2IN_SPEND_PUB, &P2IN_VIEW_PUB);

        let dsts: Vec<_> = tx.splitted_dsts.iter().collect();
        assert_eq!(
            dsts.len(),
            2,
            "golden splitted_dsts count (payment + change)"
        );
        assert_dest(dsts[0], 255_560_000, &P2IN_SPEND_PUB, &P2IN_VIEW_PUB);
        assert_dest(
            dsts[1],
            700_000_000,
            &DEST_2IN_SPEND_PUB,
            &DEST_2IN_VIEW_PUB,
        );
        let dests: Vec<_> = tx.dests.iter().collect();
        assert_eq!(dests.len(), 1, "single payment target");
        assert_dest(
            dests[0],
            700_000_000,
            &DEST_2IN_SPEND_PUB,
            &DEST_2IN_VIEW_PUB,
        );

        let src_sum: u64 = srcs.iter().map(|s| s.amount).sum();
        let dst_sum: u64 = dsts.iter().map(|d| d.amount).sum();
        assert_eq!(src_sum, 1_000_000_000, "golden input sum");
        assert_eq!(dst_sum, 955_560_000, "golden output sum");
        assert_eq!(
            src_sum - dst_sum,
            44_440_000,
            "golden fee (README 44,440,000)"
        );

        assert_eq!(
            tx.selected_transfers.iter().copied().collect::<Vec<_>>(),
            vec![2, 0],
            "golden selected_transfers"
        );
        assert_eq!(tx.subaddr_account, 0, "golden subaddr account");
        assert_eq!(
            tx.subaddr_indices.iter().copied().collect::<Vec<_>>(),
            vec![0],
            "golden subaddr indices"
        );
    });
}

// ---------------------------------------------------------------------------
// Group B — DEV wallet A': unsigned_txset_2in_dev.bin (2-input device-wallet
// fixture) and unsigned_txset_1in_fresh.bin (1-input, 0.0006 -> p2in).
// ---------------------------------------------------------------------------

#[test]
fn dev_2in_envelope_decrypt_and_parse_reserialize_identity() {
    use shlosilo::chain::xmr::unsigned_txset::UNSIGNED_TX_PREFIX;
    let enc: &[u8] = include_bytes!("fixtures/unsigned_txset_2in_dev.bin");
    assert_envelope_verifies(enc, UNSIGNED_TX_PREFIX, &DEV_VIEW_SK);
    assert_envelope_rejects(enc, UNSIGNED_TX_PREFIX, &P2IN_VIEW_SK);
    let plain = unsigned_plain(enc, &DEV_VIEW_SK);
    assert_eq!(plain.len(), 3355, "golden plaintext length");
    assert_plain_keccak(&plain, DEV_2IN_PLAIN_KECCAK_HEX);
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        162,
        "golden wire fact: 162B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

#[test]
fn dev_2in_field_level_golden() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_txset_2in_dev.bin");
    let plain = unsigned_plain(enc, &DEV_VIEW_SK);
    with_parsed_unsigned(&plain, |utx| {
        assert_eq!(utx.txes.iter().flatten().count(), 1, "single tx");
        let tx = utx.txes.iter().flatten().next().unwrap();
        let srcs: Vec<_> = tx.sources.iter().flatten().collect();
        assert_eq!(srcs.len(), 2, "golden input count");
        assert_eq!(srcs[0].amount, 350_000_000, "input 0 amount (0.00035 XMR)");
        assert_eq!(srcs[1].amount, 350_000_000, "input 1 amount (0.00035 XMR)");
        for (i, s) in srcs.iter().enumerate() {
            assert_eq!(s.outputs.len(), 16, "input {i} ring size 16");
            assert!(s.rct, "input {i} is RingCT");
            assert_eq!(s.real_output, 14, "input {i} real ring index");
        }
        assert_eq!(srcs[0].real_output_in_tx_index, 1, "input 0 in-tx index");
        assert_eq!(srcs[1].real_output_in_tx_index, 0, "input 1 in-tx index");

        assert_eq!(tx.unlock_time, 0, "golden unlock time");
        assert_eq!(tx.use_rct, 3, "golden RCT type (RingCT simple)");

        // Change goes back to the DEV wallet; the payment target is p2in.
        assert_dest(&tx.change_dts, 5_620_000, &DEV_SPEND_PUB, &DEV_VIEW_PUB);
        let dsts: Vec<_> = tx.splitted_dsts.iter().collect();
        assert_eq!(
            dsts.len(),
            2,
            "golden splitted_dsts count (payment + change)"
        );
        assert_dest(dsts[0], 650_000_000, &P2IN_SPEND_PUB, &P2IN_VIEW_PUB);
        assert_dest(dsts[1], 5_620_000, &DEV_SPEND_PUB, &DEV_VIEW_PUB);
        let dests: Vec<_> = tx.dests.iter().collect();
        assert_eq!(dests.len(), 1, "single payment target");
        assert_dest(dests[0], 650_000_000, &P2IN_SPEND_PUB, &P2IN_VIEW_PUB);

        let src_sum: u64 = srcs.iter().map(|s| s.amount).sum();
        let dst_sum: u64 = dsts.iter().map(|d| d.amount).sum();
        assert_eq!(src_sum, 700_000_000, "golden input sum");
        assert_eq!(dst_sum, 655_620_000, "golden output sum");
        assert_eq!(
            src_sum - dst_sum,
            44_380_000,
            "golden fee (README 44,380,000)"
        );

        assert_eq!(
            tx.selected_transfers.iter().copied().collect::<Vec<_>>(),
            vec![1, 0],
            "golden selected_transfers"
        );
        assert_eq!(tx.subaddr_account, 0, "golden subaddr account");
        assert_eq!(
            tx.subaddr_indices.iter().copied().collect::<Vec<_>>(),
            vec![0],
            "golden subaddr indices"
        );
    });
}

#[test]
fn dev_1in_envelope_decrypt_and_parse_reserialize_identity() {
    use shlosilo::chain::xmr::unsigned_txset::UNSIGNED_TX_PREFIX;
    let enc: &[u8] = include_bytes!("fixtures/unsigned_txset_1in_fresh.bin");
    assert_envelope_verifies(enc, UNSIGNED_TX_PREFIX, &DEV_VIEW_SK);
    assert_envelope_rejects(enc, UNSIGNED_TX_PREFIX, &P2IN_VIEW_SK);
    let plain = unsigned_plain(enc, &DEV_VIEW_SK);
    assert_eq!(plain.len(), 1875, "golden plaintext length");
    assert_plain_keccak(&plain, DEV_1IN_PLAIN_KECCAK_HEX);
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        4,
        "golden wire fact: 4B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

#[test]
fn dev_1in_field_level_golden() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_txset_1in_fresh.bin");
    let plain = unsigned_plain(enc, &DEV_VIEW_SK);
    with_parsed_unsigned(&plain, |utx| {
        assert_eq!(utx.txes.iter().flatten().count(), 1, "single tx");
        let tx = utx.txes.iter().flatten().next().unwrap();
        let srcs: Vec<_> = tx.sources.iter().flatten().collect();
        assert_eq!(srcs.len(), 1, "golden input count");
        let s = srcs[0];
        assert_eq!(s.amount, 900_000_000, "input amount (0.0009 XMR)");
        assert_eq!(s.outputs.len(), 16, "ring size 16");
        assert!(s.rct, "RingCT input");
        assert_eq!(s.real_output, 14, "real ring index");
        assert_eq!(s.real_output_in_tx_index, 0, "in-tx index");

        assert_eq!(tx.unlock_time, 0, "golden unlock time");
        assert_eq!(tx.use_rct, 3, "golden RCT type (RingCT simple)");

        // Change back to DEV; payment target 0.0006 -> p2in (README chain
        // record: tx 2d2c40d1…, p2in received 0.0006).
        assert_dest(&tx.change_dts, 269_420_000, &DEV_SPEND_PUB, &DEV_VIEW_PUB);
        let dsts: Vec<_> = tx.splitted_dsts.iter().collect();
        assert_eq!(
            dsts.len(),
            2,
            "golden splitted_dsts count (change + payment)"
        );
        assert_dest(dsts[0], 269_420_000, &DEV_SPEND_PUB, &DEV_VIEW_PUB);
        assert_dest(dsts[1], 600_000_000, &P2IN_SPEND_PUB, &P2IN_VIEW_PUB);
        let dests: Vec<_> = tx.dests.iter().collect();
        assert_eq!(dests.len(), 1, "single payment target");
        assert_dest(dests[0], 600_000_000, &P2IN_SPEND_PUB, &P2IN_VIEW_PUB);

        let src_sum: u64 = srcs.iter().map(|s| s.amount).sum();
        let dst_sum: u64 = dsts.iter().map(|d| d.amount).sum();
        assert_eq!(src_sum, 900_000_000, "golden input sum");
        assert_eq!(dst_sum, 869_420_000, "golden output sum");
        assert_eq!(src_sum - dst_sum, 30_580_000, "golden fee (README 30,580)");

        assert_eq!(
            tx.selected_transfers.iter().copied().collect::<Vec<_>>(),
            vec![3],
            "golden selected_transfers"
        );
        assert_eq!(tx.subaddr_account, 0, "golden subaddr account");
        assert_eq!(
            tx.subaddr_indices.iter().copied().collect::<Vec<_>>(),
            vec![0],
            "golden subaddr indices"
        );
    });
}

// ---------------------------------------------------------------------------
// Group C — signed_txset_1in_fresh.bin (device-signed counterpart of the
// 1-input fixture; wallet2 `submit_transfer` accepted it, chain tx
// 2d2c40d1…). Decrypt side is byte-pinned (whole-plaintext keccak golden +
// a field walk of the deterministic tx prefix).
//
// NOT pinned: parse -> re-serialize identity of the SIGNED plaintext — forms
// has no `signed_txset` deserializer (details pool §52 gap, same as
// tests/golden_wallet2_bytes.rs Group B). The amounts / target addresses of
// the signed tx live in that unparsed region (RingCT hides the amounts in
// ecdhInfo and the construction_data echo has no reader), so those faces stay
// with the §52 gap instead of being hand-fabricated here.
// ---------------------------------------------------------------------------

#[test]
fn dev_signed_1in_decrypts_and_prefix_field_walk() {
    use shlosilo::chain::xmr::signed_txset::SIGNED_TX_PREFIX;
    let enc: &[u8] = include_bytes!("fixtures/signed_txset_1in_fresh.bin");
    assert_envelope_verifies(enc, SIGNED_TX_PREFIX, &DEV_VIEW_SK);
    assert_envelope_rejects(enc, SIGNED_TX_PREFIX, &P2IN_VIEW_SK);
    let plain = decrypt_signed_txset(enc, &DEV_VIEW_SK).expect("decrypt signed container");
    assert_eq!(plain.len(), 3893, "golden signed plaintext length");
    assert_plain_keccak(&plain, DEV_SIGNED_1IN_PLAIN_KECCAK_HEX);

    // Deterministic tx-prefix walk (framing -> vin -> vout -> extra).
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
    let mut pos = 0usize;
    assert_eq!(plain[pos], 0, "signed_tx_set version 0");
    pos += 1;
    assert_eq!(varint(&plain, &mut pos), 1, "single ptx");
    assert_eq!(plain[pos], 1, "ptx version 1");
    pos += 1;
    assert_eq!(varint(&plain, &mut pos), 2, "tx version 2");
    assert_eq!(varint(&plain, &mut pos), 0, "golden unlock time");
    assert_eq!(varint(&plain, &mut pos), 1, "golden input count (1 input)");
    assert_eq!(plain[pos], 0x02, "txin_to_key tag");
    pos += 1;
    assert_eq!(varint(&plain, &mut pos), 0, "RingCT vin amount 0");
    let n_off = varint(&plain, &mut pos);
    assert_eq!(n_off, 16, "ring size 16");
    for _ in 0..n_off {
        let _rel = varint(&plain, &mut pos);
    }
    assert_eq!(
        hex(&plain[pos..pos + 32]),
        DEV_SIGNED_1IN_KEY_IMAGE_HEX,
        "key image (deterministic x * Hp(P)) must match the wallet2-accepted golden"
    );
    pos += 32;

    // vout: 2 RingCT outputs as tagged keys (type 0x03 + 1B view tag).
    assert_eq!(varint(&plain, &mut pos), 2, "golden output count");
    for (i, key_gold, view_tag_gold) in [
        (0, DEV_SIGNED_1IN_OUT0_KEY_HEX, 0x13u8),
        (1, DEV_SIGNED_1IN_OUT1_KEY_HEX, 0x90u8),
    ] {
        assert_eq!(varint(&plain, &mut pos), 0, "vout[{i}] RingCT amount 0");
        assert_eq!(plain[pos], 0x03, "vout[{i}] tagged-key output type");
        pos += 1;
        assert_eq!(
            hex(&plain[pos..pos + 32]),
            key_gold,
            "vout[{i}] stealth address (tagged key)"
        );
        pos += 32;
        assert_eq!(plain[pos], view_tag_gold, "vout[{i}] view tag");
        pos += 1;
    }

    // tx extra (deterministic: tx pub key + encrypted payment id nonce).
    let extra_len = varint(&plain, &mut pos) as usize;
    assert_eq!(extra_len, 44, "golden tx extra length");
    assert_eq!(
        hex(&plain[pos..pos + extra_len]),
        DEV_SIGNED_1IN_EXTRA_HEX,
        "golden tx extra bytes"
    );
    println!(
        "signed 1in plaintext: {}B, prefix walk consumed {}B (framing+vin+vout+extra); \
         parse -> re-serialize face is a known gap (details pool §52: no signed_txset deserializer)",
        plain.len(),
        pos + extra_len
    );
}
