//! Golden byte-comparison pins against wallet2 / monero-wallet-cli artifacts
//! (pool item #40: "金标字节对拍缺位").
//!
//! Oracle policy (Kosmo): wallet2 source + monero-wallet-cli golden containers
//! are the sole authority for protocol/wire semantics. This file pins our
//! serializers byte-for-byte against real wallet2-produced bytes, in CI, with
//! no env gating (fixture-key policy: public fixture keys may be embedded in
//! exchange for coverage — same class as `xmr_sign_reuse_determinism.rs` and
//! `tx2_whitebox_tools.rs`; see tests/fixtures/README.md).
//!
//! Face classification:
//!
//! * PINNED (deterministic, byte-compared here):
//!   - unsigned_txset plaintext parse -> re-serialize byte identity against
//!     wallet2-produced plaintexts (incl. the real-chain add-keys shapes and
//!     the `construction_data.extra` field — preserved since the pool #39
//!     fix, 2026-10-20), so any divergence fails loudly.
//!   - wallet2 container decrypt == stored golden plaintext (envelope +
//!     keystream fidelity against a real phone-flow container).
//!   - key image export: our computed key images vs the CLI self-computed
//!     golden images (32B values are deterministic), key-image wire
//!     parse -> re-serialize identity.
//!   - our signer's deterministic output vs golden signed containers under
//!     fixed entropy (whole-tx byte identity where the signer revision
//!     matches; deterministic vin region where it does not).
//!   - deterministic region of the signed plaintext vs wallet2's own
//!     `sign_transfer` gold (vin region: ring offsets + key image).
//!
//! * NOT byte-comparable (by construction — verified in place, never
//!   byte-compared):
//!   - `export_key_images` / `export_outputs` container envelope: 8B random
//!     nonce + Monero Schnorr signature with random nonce `k`. The 64B
//!     accompanying per-record key-image signature is likewise randomized.
//!     Rule (established in tests/real_fixture.rs): verify, don't compare.
//!   - wallet2's signed container envelope (ChaCha nonce + Schnorr sig):
//!     wallet2 draws from its own RNG, so gold container bytes can never
//!     match ours. (Our own signer is deterministic given inputs — pinned by
//!     tests/xmr_sign_reuse_determinism.rs — and byte-compared below.)
//!   - signed plaintext `vout` output keys across IMPLEMENTATIONS: the tx
//!     secret key `r` is drawn per implementation (wallet2 random, ours
//!     derived from the signer entropy), so the vout region of wallet2 gold
//!     vs our plaintext diverges by design. See
//!     `golden_ours_vs_wallet2_gold_deterministic_region`.
//!   - our signed output vs ARCHIVED golds from older signer revisions: the
//!     only sanctioned divergence is the `key_images` fill policy (gold =
//!     per-tx, current writer = wallet-transfer-indexed; see
//!     `pin_signed_key_images_wallet_indexed`). The September dev gold
//!     (`golden_resign_dev_1in_fresh_matches_signed_gold`) is reproduced
//!     byte-for-byte up to that array — the old "r derivation drift" note was
//!     misattributed: the divergence WAS the pool #39 extra drop (the per-tx
//!     context digest absorbs `extra`, and that digest feeds the derived tx
//!     key `r`). The fa gold was regenerated 2026-10-20 with the SAME fixed
//!     entropy after the extra fix (its 2026-10-16 revision dropped `extra`
//!     in the digest, so its whole wire is superseded) — see
//!     `golden_resign_fa_matches_archived_our_container`.
//!
//! Run: cargo test --release --test golden_wallet2_bytes (sign pins are slow
//! in debug builds; `make test` runs them anyway).
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::xmr::key_image_export::{
    decrypt_export_payload, generate_key_image_export, KEY_IMAGE_EXPORT_MAGIC, OUTPUT_EXPORT_MAGIC,
};
use shlosilo::chain::xmr::output_export::{
    deserialize_key_images_into, serialize_key_images_into, ExportedTransferDetail,
    ExportedTransferDetails, KEY_IMAGE_RECORD_LEN,
};
use shlosilo::chain::xmr::signed_txset::decrypt_signed_txset;
use shlosilo::chain::xmr::unsigned_txset::{
    decrypt_unsigned_txset, deserialize_unsigned_tx, serialize_unsigned_tx, TxConstructionData,
    TxDestinationEntry, TxSourceEntry, UnsignedTxPools,
};

// ---------------------------------------------------------------------------
// Fixture keys (all previously public in this repo's test sources; the
// derived ones are checked against their public constants below).
// ---------------------------------------------------------------------------

/// Lab wallet (stage_disk / mainnet device-disk group) view secret key.
/// Already public in tests/tx2_whitebox_tools.rs (TX2_LAB_VIEW_SK) and
/// tests/cake_real_container_probe.rs (KNOWN_VIEW_SK).
const LAB_VIEW_SK: [u8; 32] = [
    0xdb, 0x93, 0xce, 0x63, 0x2d, 0x8d, 0x31, 0xe3, 0x1b, 0xd0, 0xb4, 0xec, 0xbd, 0xbd, 0xb8, 0x33,
    0xca, 0xe8, 0x13, 0x92, 0x8a, 0xf4, 0x02, 0xc5, 0xb7, 0xff, 0xeb, 0x85, 0x76, 0x9c, 0xf0, 0x00,
];

/// DEV test wallet spend secret key. Public fixture key, same bytes as
/// tests/xmr_sign_reuse_determinism.rs::DEV_SPEND_SK.
const DEV_SPEND_SK: [u8; 32] = [
    0xd8, 0xcd, 0x34, 0xaf, 0xac, 0x38, 0xfe, 0x95, 0xa2, 0x04, 0x39, 0xc2, 0x73, 0x8c, 0xb5, 0xfa,
    0xc0, 0xad, 0x29, 0x97, 0xe8, 0x35, 0x16, 0x45, 0x4b, 0x70, 0x20, 0x33, 0xb3, 0xed, 0xa5, 0x03,
];

/// DEV test wallet view secret key. Public fixture key, same bytes as
/// tests/xmr_sign_reuse_determinism.rs::DEV_VIEW_SK.
const DEV_VIEW_SK: [u8; 32] = [
    0xdd, 0x87, 0x2c, 0xe8, 0x67, 0x39, 0xd7, 0x8d, 0xf0, 0x71, 0xd7, 0xf9, 0xef, 0x72, 0x91, 0x3b,
    0xd5, 0xf3, 0xc2, 0xdb, 0x02, 0xcb, 0x55, 0x5c, 0x24, 0x4b, 0x07, 0x6e, 0xfa, 0x5a, 0x9a, 0x0f,
];

/// DEV test wallet BIP-39 entropy (32B -> 24 words; the device `entropy`
/// command and the host `P64_ENTROPY_HEX` carry the same value). Deriving
/// MoneroPath::mainnet(0) from it must reproduce DEV_SPEND_SK/DEV_VIEW_SK
/// (asserted below) — it is therefore no more secret than those public keys.
const DEV_WALLET_ENTROPY: [u8; 32] = [
    0x4a, 0x92, 0x91, 0xa7, 0x02, 0xc0, 0xba, 0x28, 0xaa, 0x28, 0x58, 0x82, 0xef, 0xde, 0x4f, 0x2c,
    0x92, 0x37, 0x55, 0x6c, 0xeb, 0x68, 0x55, 0x70, 0xd5, 0x95, 0xfd, 0x65, 0x86, 0x07, 0x45, 0x30,
];

/// test0830 mainnet test wallet (the wallet behind the `test0830_*` golden
/// containers, dust-class: received 0.001 XMR for the export_outputs /
/// export_key_images watch-only experiments). Keys embedded per the fixture
/// key policy; provenance/privacy notes in tests/fixtures/README.md.
const TEST0830_SPEND_SK_HEX: &str =
    "e79adeb18e8ba56cd18589e86b35676da68d1158d21e525d5d7083a2e8c7ec03";
const TEST0830_VIEW_SK_HEX: &str =
    "c16b3a4be2a4d1206d715988401174d9fae7ac682e8312a3826d1876569d5b04";

/// The signer entropy used for every fixed-entropy A/B golden (device
/// `xmrseed` = 0x77x32; see tests/xmr_device_blob_verify.rs::FIXED_ENTROPY).
const FIXED_SIGN_ENTROPY: [u8; 32] = [0x77u8; 32];

/// Lab wallet BIP-39 entropy (tests/xmr_subaddr_sign_roundtrip.rs line 605:
/// "stage_disk / device disk keys"). The MoneroPath derivation below asserts
/// it reproduces LAB_VIEW_SK, so it carries no secret beyond what is public.
const LAB_WALLET_ENTROPY: [u8; 32] = [0x22u8; 32];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    for i in 0..32 {
        a[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    a
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Derive the Monero spend/view key pair from 32B BIP-39 entropy via the
/// device-identical path (restore_seed -> MoneroPath::mainnet(0)).
fn monero_keys_from_entropy(entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use shlosilo::derivation::monero_reduce_scalar::{derive, MoneroPath};
    use shlosilo::entropy::mnemonic::Mnemonic;
    let m = Mnemonic::from_entropy(entropy).expect("mnemonic from entropy");
    let mut seed = [0u8; 64];
    shlosilo::business::restore_seed::restore_seed(&m, b"", &mut seed).expect("restore seed");
    let kp = derive(&seed, &MoneroPath::mainnet(0)).expect("derive monero keys");
    (
        shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.spend_priv()),
        shlosilo::curve_primitive::ed25519::scalar_to_bytes(kp.view_priv()),
    )
}

/// Parse a wallet2-produced unsigned plaintext into caller pools and pin the
/// parse -> re-serialize byte identity against the wallet2 bytes.
///
/// EXTRA PRESERVED (pool #39, fixed 2026-10-20): `read_tx_construction_data`
/// used to copy the `extra` bytes into the caller pool and then wrap the chunk
/// with `SliceVec::new`, which RESETS the chunk to defaults and reports len 0 —
/// the parsed `extra` was silently lost, so the writer re-emitted
/// `extra_len = 0` and the re-serialization came out short by exactly one wire
/// field (`varint(extra_len) || extra`, 45B on every fixture here) at the
/// extra field position. The product now fills the payload through the
/// SliceVec, so this helper is a plain byte equality: full identity over the
/// parsed span INCLUDING the extra field, no divergence branch.
///
/// The plaintext may additionally end with the unparsed "transfers" display
/// segment (unsigned_txset.rs module doc); the writer does not emit it, so the
/// byte-identity claim covers the parsed span only. Returns the
/// transfers-segment length (a per-fixture golden wire fact).
fn roundtrip_unsigned_plain(plain: &[u8]) -> usize {
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
    let tx_count = utx.txes.iter().flatten().count();
    assert_eq!(
        tx_count, 1,
        "golden fixtures are single-tx (helper assumption)"
    );
    let out = serialize_unsigned_tx(&utx);
    assert!(
        plain.len() >= out.len(),
        "re-serialized txes segment ({}B) longer than the wallet2 plaintext ({}B)",
        out.len(),
        plain.len()
    );
    if plain[..out.len()] != out[..] {
        // Any mismatch is a NEW divergence — the extra-drop gap is fixed and
        // this helper no longer reconstructs it.
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
    let trailing = plain.len() - out.len();
    println!(
        "roundtrip: plain={}B reserialized={}B — byte-identical over the parsed span \
         (construction_data.extra preserved), trailing={}B transfers segment",
        plain.len(),
        out.len(),
        trailing
    );
    trailing
}

/// Decrypt a wallet2 unsigned container into its plaintext.
fn unsigned_plain(container: &[u8], view_sk: &[u8; 32]) -> zeroize::Zeroizing<Vec<u8>> {
    decrypt_unsigned_txset(container, view_sk).expect("decrypt wallet2 unsigned container")
}

// ---------------------------------------------------------------------------
// Group A — wallet2-produced unsigned plaintexts: parse -> re-serialize
// byte identity (our epee writer vs wallet2 bytes).
// ---------------------------------------------------------------------------

/// Feather wallet-rpc produced unsigned_txset plaintext (tests/fixtures/
/// txset_plain.bin; decrypted counterpart of fixtures/unsigned_txset.bin).
/// No key needed — the plaintext itself is the wallet2 artifact.
#[test]
fn golden_plain_txset_parse_reserialize_identity() {
    let plain: &[u8] = include_bytes!("fixtures/txset_plain.bin");
    assert_eq!(
        roundtrip_unsigned_plain(plain),
        83,
        "golden wire fact: 83B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

/// Real Cake Wallet tx2 construction (mainnet add-keys funding-tx change
/// input): `real_out_additional_tx_keys` NON-EMPTY. This is the pool-#40
/// "additional_tx_keys 非空真链情形" face. The plaintext of
/// fixtures/tx2_cake_real_unsigned.bin is compared byte-for-byte against our
/// re-serialization.
#[test]
fn golden_tx2_cake_addkeys_parse_reserialize_identity() {
    let enc: &[u8] = include_bytes!("fixtures/tx2_cake_real_unsigned.bin");
    let plain = unsigned_plain(enc, &LAB_VIEW_SK);
    // The fixture must actually exercise the add-keys face, otherwise this
    // pin silently stops covering what it exists for.
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
    .expect("deserialize tx2 plaintext");
    let add_keys: usize = utx
        .txes
        .iter()
        .flatten()
        .flat_map(|t| t.sources.iter().flatten())
        .map(|s| s.real_out_additional_tx_keys.len())
        .sum();
    assert!(
        add_keys > 0,
        "fixture guard: tx2 gold must carry non-empty real_out_additional_tx_keys"
    );
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        4,
        "golden wire fact: 4B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

/// Stagenet real-chain fixture with `real_out_additional_tx_keys` = 3
/// (funding tx to two own subaddresses -> extra carries one additional tx key
/// per vout; wallet2 CLI `transfer` produced the container). Source:
/// ~/works/xmr-stagenet-lab/watchonly_probe/signed_rt/fc/unsigned_monero_tx,
/// see SIGNED_TX_PARSE_FAIL_REPORT.md §9.2.
#[test]
fn golden_fc_addkeys3_parse_reserialize_identity() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_fc_addkeys3.bin");
    let (spend_sk, view_sk) = monero_keys_from_entropy(&LAB_WALLET_ENTROPY);
    let _ = spend_sk;
    assert_eq!(
        view_sk, LAB_VIEW_SK,
        "lab entropy must reproduce the public lab view key"
    );
    let plain = unsigned_plain(enc, &view_sk);
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        690,
        "golden wire fact: 690B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

/// Stagenet real-chain subaddress-input shape (F_A: spending from address
/// index 1, add_keys=0). wallet2 CLI produced.
#[test]
fn golden_fa_subaddr_input_parse_reserialize_identity() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_fa_subaddr.bin");
    let plain = unsigned_plain(enc, &LAB_VIEW_SK);
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        4,
        "golden wire fact: 4B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

/// Stagenet real-chain change-input shape (F_B: change-to-own-address input,
/// main tx key derived). wallet2 CLI produced.
#[test]
fn golden_fb_change_input_parse_reserialize_identity() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_fb_change.bin");
    let plain = unsigned_plain(enc, &LAB_VIEW_SK);
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        4,
        "golden wire fact: 4B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

/// DEV-wallet 1-input fixture (wallet2 CLI watch-only `transfer`; later
/// signed by the device into fixtures/signed_txset_1in_fresh.bin).
#[test]
fn golden_dev_1in_fresh_parse_reserialize_identity() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_txset_1in_fresh.bin");
    let plain = unsigned_plain(enc, &DEV_VIEW_SK);
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        4,
        "golden wire fact: 4B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

/// DEV-wallet 2-input fixture (wallet2 CLI watch-only `transfer`).
#[test]
fn golden_dev_2in_parse_reserialize_identity() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_txset_2in_dev.bin");
    let plain = unsigned_plain(enc, &DEV_VIEW_SK);
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        162,
        "golden wire fact: 162B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

/// wallet2 RPC-produced unsigned container (`transfer` JSON-RPC response
/// captured 2026-10-07, extracted by /tmp/take_oracle.py: amount 150000000,
/// fee 30580000, single input). Envelope is the same
/// `Monero unsigned tx set\x05` family. Decrypt under the DEV wallet view key.
#[test]
fn golden_oracle_unsigned_parse_reserialize_identity() {
    let enc: &[u8] = include_bytes!("fixtures/oracle_unsigned.bin");
    let plain = unsigned_plain(enc, &DEV_VIEW_SK);
    assert_eq!(
        roundtrip_unsigned_plain(&plain),
        83,
        "golden wire fact: 83B trailing transfers segment (parsed span incl. the \
         45B extra field is byte-identical — helper asserts full identity)"
    );
}

// ---------------------------------------------------------------------------
// Group B — container decrypt vs stored golden plaintext (envelope +
// keystream fidelity against real containers).
// ---------------------------------------------------------------------------

/// The 2026-10-19 phone-flow signed container (pool #47 forensics: 30 QR
/// frames reassembled from ~/works/1019-st/, mainnet tx2 case). Decrypting
/// the container must reproduce the stored golden plaintext byte-for-byte —
/// this pins the whole envelope chain (magic + nonce + Monero Schnorr verify
/// + ChaCha keystream) against real bytes seen on the real chain case.
///
/// NOTE: parse -> re-serialize identity for SIGNED plaintexts is not pinned
/// here: forms has no signed_txset deserializer (gap listed in the report),
/// so only the decrypt side is byte-compared.
#[test]
fn golden_st1019_signed_container_decrypts_to_golden_plain() {
    let container: &[u8] = include_bytes!("fixtures/st1019_signed_container.bin");
    let golden_plain: &[u8] = include_bytes!("fixtures/st1019_signed_plain.bin");
    let plain =
        decrypt_signed_txset(container, &LAB_VIEW_SK).expect("decrypt phone-flow container");
    assert_eq!(
        &plain[..],
        golden_plain,
        "container decrypt must reproduce the golden plaintext byte-for-byte"
    );
}

// ---------------------------------------------------------------------------
// Group C — key image export / output export goldens (monero-wallet-cli
// test0830 artifacts).
// ---------------------------------------------------------------------------

/// CLI `export_outputs all` golden (test0830 full wallet). Deterministic
/// faces pinned here: the magic + container version byte (`\x04`), and the
/// decrypted plaintext's parse result (stream-exhaustive epee parse). The
/// envelope (8B nonce + 64B Schnorr with random k) is verified, never
/// byte-compared (see file header).
#[test]
fn golden_output_export_parses() {
    let container: &[u8] = include_bytes!("fixtures/test0830_outputs_all.bin");
    assert_eq!(&container[..20], b"Monero output export", "magic prefix");
    assert_eq!(
        container[20], 0x04,
        "wallet2 output-export container version byte"
    );
    let view_sk = hex_to_32(TEST0830_VIEW_SK_HEX);
    let (_pk1, _pk2, plain) = decrypt_export_payload(container, OUTPUT_EXPORT_MAGIC, &view_sk)
        .expect("decrypt output export");
    let mut pool: [ExportedTransferDetail; 8] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    let details =
        ExportedTransferDetails::from_bytes(&plain, &mut pool).expect("parse golden export");
    assert_eq!(
        details.details.len(),
        1,
        "golden export carries exactly 1 output"
    );
    let d0 = &details.details[0];
    println!(
        "output export golden: pubkey={} tx_pubkey={} amount={} flags={:#x} \
         internal={} global={} major={} minor={} add_keys={}",
        hex(&d0.pubkey),
        hex(&d0.tx_pubkey),
        d0.amount,
        d0.flags,
        d0.internal_output_index,
        d0.global_output_index,
        d0.major,
        d0.minor,
        d0.additional_tx_keys.len()
    );
    // Field-level golden pins (values read out of the golden bytes; a layout
    // divergence in the reader would move any of them).
    assert_eq!(d0.amount, 1_000_000_000, "golden amount (0.001 XMR)");
    assert_eq!(
        d0.flags, 0x0c,
        "full-wallet export flags (rct + key_image_known)"
    );
    assert_eq!(d0.internal_output_index, 1, "golden internal output index");
    assert_eq!(
        d0.global_output_index, 162_437_014,
        "golden global output index"
    );
    assert_eq!(d0.major, 0, "golden subaddress major index");
    assert_eq!(d0.minor, 0, "golden subaddress minor index");
    assert_eq!(
        hex(&d0.pubkey),
        "2af83979cc8d61886b8e4eda275447168dc7734407bd912a7199d7b8403b29e6",
        "golden output pubkey"
    );
    assert_eq!(
        hex(&d0.tx_pubkey),
        "8e55f942d2f6fb55b2621c84d75f9dbf376b4bc8ebd2b4eff0d8944299ca60bb",
        "golden tx pubkey"
    );
    assert!(
        d0.additional_tx_keys.is_empty(),
        "golden output carries no additional tx keys"
    );
}

/// CLI `export_key_images` golden vs our key image computation.
///
/// Deterministic (byte-compared): the 32B key image values — key image is a
/// deterministic function of the output secret key, so our computed image
/// must equal the CLI's self-computed golden image byte-for-byte. This is the
/// "我们序列化器输出与金标件的逐字节对拍" pin for the key-image face.
///
/// NOT deterministic (verified, not compared): the 64B accompanying
/// per-record signature and the container envelope (random nonce k in the
/// Schnorr sig + 8B random container nonce). See tests/real_fixture.rs for
/// the full verify-formula provenance.
#[test]
fn golden_cli_key_image_matches_our_computation() {
    use rand_chacha::rand_core::SeedableRng as _;

    let view_sk = hex_to_32(TEST0830_VIEW_SK_HEX);
    let spend_sk = hex_to_32(TEST0830_SPEND_SK_HEX);
    let outputs: &[u8] = include_bytes!("fixtures/test0830_outputs_all.bin");
    let cli_ki: &[u8] = include_bytes!("fixtures/test0830_cli_ki_all.bin");

    // CLI key image export container: magic + version byte 0x03 (wallet2
    // export_key_images container version — note: NOT the same version byte
    // as export_outputs' \x04).
    assert_eq!(&cli_ki[..23], b"Monero key image export");
    assert_eq!(
        cli_ki[23], 0x03,
        "wallet2 key-image-export container version byte"
    );

    // Our computation over the CLI's own output export request.
    let mut pool: [ExportedTransferDetail; 8] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
    let ours = generate_key_image_export(&view_sk, &spend_sk, outputs, &mut pool, &mut rng)
        .expect("generate key image export");

    // Read both back from the wire (decrypt + 96B record parse).
    let (_o1, _o2, our_wire) =
        decrypt_export_payload(&ours, KEY_IMAGE_EXPORT_MAGIC, &view_sk).expect("decrypt ours");
    let (_c1, _c2, cli_wire) = decrypt_export_payload(cli_ki, KEY_IMAGE_EXPORT_MAGIC, &view_sk)
        .expect("decrypt CLI golden");
    assert_eq!(
        our_wire.len(),
        KEY_IMAGE_RECORD_LEN,
        "1 output = one 96B record"
    );
    assert_eq!(
        cli_wire.len(),
        KEY_IMAGE_RECORD_LEN,
        "1 output = one 96B record"
    );

    // THE golden byte pin: key image bytes (32B, deterministic).
    assert_eq!(
        &our_wire[..32],
        &cli_wire[..32],
        "our key image must be byte-identical to the CLI self-computed golden image"
    );

    // The 64B accompanying signatures are randomized on both sides (random
    // nonce k): verify both against the ring=1 formula instead of comparing.
    let mut req_pool: [ExportedTransferDetail; 8] =
        core::array::from_fn(|_| ExportedTransferDetail::default());
    let (_r1, _r2, req_plain) =
        decrypt_export_payload(outputs, OUTPUT_EXPORT_MAGIC, &view_sk).expect("decrypt request");
    let req =
        ExportedTransferDetails::from_bytes(&req_plain, &mut req_pool).expect("parse request");
    let out_pub = req.details[0].pubkey;
    assert!(
        verify_key_image_sig(&cli_wire, &out_pub),
        "CLI golden accompanying sig verifies"
    );
    assert!(
        verify_key_image_sig(&our_wire, &out_pub),
        "our accompanying sig verifies"
    );
    // Container envelopes (random 8B nonce + random-nonce Schnorr): verify.
    assert!(
        verify_container_sig(cli_ki, KEY_IMAGE_EXPORT_MAGIC, &view_sk),
        "CLI golden envelope verifies"
    );
    assert!(
        verify_container_sig(&ours, KEY_IMAGE_EXPORT_MAGIC, &view_sk),
        "our envelope verifies"
    );
}

/// Key-image wire (flat `[32B image][64B sig]` records) parse -> re-serialize
/// byte identity over the CLI golden wire.
#[test]
fn golden_key_image_wire_parse_reserialize_identity() {
    let view_sk = hex_to_32(TEST0830_VIEW_SK_HEX);
    let cli_ki: &[u8] = include_bytes!("fixtures/test0830_cli_ki_all.bin");
    let (_c1, _c2, cli_wire) = decrypt_export_payload(cli_ki, KEY_IMAGE_EXPORT_MAGIC, &view_sk)
        .expect("decrypt CLI golden");
    let mut recs = [([0u8; 32], [0u8; 64]); 8];
    let n = deserialize_key_images_into(&cli_wire, &mut recs).expect("parse key image records");
    let mut re = vec![0u8; cli_wire.len() + 32];
    let m = serialize_key_images_into(&recs[..n], &mut re).expect("re-serialize key image records");
    assert_eq!(
        &re[..m],
        &cli_wire[..],
        "key-image record wire must survive parse -> re-serialize byte-identically"
    );
}

// ---------------------------------------------------------------------------
// Group D — our signer output vs golden signed containers (fixed-entropy
// determinism), and our output vs wallet2's own `sign_transfer` gold.
// ---------------------------------------------------------------------------

/// Sign an unsigned container through the product path
/// (`business::sign::sign_with_entropy`, device-identical) with the wallet
/// seed from 32B BIP-39 entropy and the fixed signer entropy that produced
/// every archived A/B golden (device `xmrseed` = 0x77x32). Fully
/// deterministic: the A/B runs (device vs host byte-identical,
/// tests/xmr_device_blob_verify.rs) and
/// tests/xmr_sign_reuse_determinism.rs pin that property.
/// Session wallet fingerprint (fix37 record binding: keccak256(spend_pub ||
/// view_pub) truncated to 8 bytes — same seed path as the sign leg).
fn wallet_fp_of(wallet_entropy: &[u8; 32]) -> [u8; 8] {
    use shlosilo::business::sign::wallet_fingerprint_from_seed;
    use shlosilo::entropy::mnemonic::Mnemonic;
    let m = Mnemonic::from_entropy(wallet_entropy).expect("mnemonic from wallet entropy");
    let mut seed = [0u8; 64];
    shlosilo::business::restore_seed::restore_seed(&m, b"", &mut seed).expect("restore seed");
    wallet_fingerprint_from_seed(&seed)
}

/// Deterministic re-sign WITH pairing records (v2 gap policy: a gap without a
/// record refuses, so gap positions must be covered by records). Used by the
/// archived-receipt goldens to reproduce the historical v1 fill bytes exactly:
/// the v1 gap filler was the source-derived key image, so feeding that value
/// as the gap records reproduces the archive while pinning the signer's
/// determinism (the fill POLICY itself is pinned by the red-pin suite).
fn sign_with_fixed_entropy_records(
    container: &[u8],
    wallet_entropy: &[u8; 32],
    ki_records: &[shlosilo::business::sign::WalletKiRecord],
) -> Vec<u8> {
    use shlosilo::business::sign::{sign_with_entropy_records, SignInput};
    use shlosilo::entropy::mnemonic::Mnemonic;
    use shlosilo::ur::ur_encode::UrTypeTag;
    let m = Mnemonic::from_entropy(wallet_entropy).expect("mnemonic from wallet entropy");
    let mut out = vec![0u8; 65536];
    let n = sign_with_entropy_records(
        SignInput::Mnemonic {
            mnemonic: m,
            passphrase: b"",
        },
        UrTypeTag::XmrTxUnsigned,
        container,
        ki_records,
        &FIXED_SIGN_ENTROPY,
        &mut out,
    )
    .expect("sign with records must succeed");
    out.truncate(n);
    out
}

/// Fixture-key guard: the public BIP-39 entropies must reproduce the public
/// fixture key constants embedded above (and in
/// tests/xmr_sign_reuse_determinism.rs). If this test moves, every key-based
/// pin in this file loses its anchor.
#[test]
fn fixture_entropies_reproduce_public_fixture_keys() {
    let (lab_spend, lab_view) = monero_keys_from_entropy(&LAB_WALLET_ENTROPY);
    assert_eq!(
        lab_view, LAB_VIEW_SK,
        "lab entropy must reproduce the public lab view key"
    );
    // The lab spend key is derivable from the same public entropy; its value
    // is therefore not an embedded secret beyond LAB_WALLET_ENTROPY.
    let _ = lab_spend;
    let (dev_spend, dev_view) = monero_keys_from_entropy(&DEV_WALLET_ENTROPY);
    assert_eq!(
        dev_spend, DEV_SPEND_SK,
        "DEV entropy must reproduce DEV_SPEND_SK"
    );
    assert_eq!(
        dev_view, DEV_VIEW_SK,
        "DEV entropy must reproduce DEV_VIEW_SK"
    );
}

/// Fixed-entropy re-sign of the DEV 1-input fixture vs
/// fixtures/signed_txset_1in_fresh.bin — the archived, wallet2-accepted
/// `signed_monero_tx` produced by the device (fce3d9d) + host A/B on
/// 2026-09-15 (`submit_transfer` accepted it, chain tx 2d2c40d1…).
///
/// Byte-compared: the WHOLE transaction — framing + vin (ring offsets + key
/// image) + vout output keys + CLSAG + ptx fields — reproduces the September
/// gold byte-for-byte up to the `key_images` array (offset 3794). This also
/// settles the old "r derivation drift" note (pool #40): the divergence at
/// the first vout key WAS the pool #39 extra drop — the per-tx context digest
/// absorbs `extra`, and that digest feeds the derived tx secret key r; the
/// September signer absorbed the field, the pre-fix signer lost it. With the
/// extra preserved the re-sign reproduces the September output exactly.
///
/// Known tail divergence (documented, shape-pinned): at offset 3794 the
/// `key_images` outer array differs — the gold writes the per-tx key image
/// (count 1), while the current writer applies the wallet-transfer-indexed
/// fill policy (pin_signed_key_images_wallet_indexed: one entry per wallet
/// transfer position — 4 here). Both are wallet2-parse-clean; the policy
/// change postdates the gold.
#[test]
fn golden_resign_dev_1in_fresh_matches_signed_gold() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_txset_1in_fresh.bin");
    let gold: &[u8] = include_bytes!("fixtures/signed_txset_1in_fresh.bin");
    let gold_plain = decrypt_signed_txset(gold, &DEV_VIEW_SK).expect("decrypt archived gold");
    // v2 gap policy (2026-10-21): the recordless sign refuses gaps. The
    // archived receipt carries the v1 fill shape (4 slots = the source-derived
    // key image repeated), so feed exactly that value as the gap-covering
    // records: the re-sign reproduces the archive byte-for-byte and the pin
    // keeps measuring signer determinism (the fill POLICY is pinned by the
    // red-pin suite).
    let src_ki = signed_plain_first_key_image(&gold_plain);
    let fp = wallet_fp_of(&DEV_WALLET_ENTROPY);
    let records: Vec<shlosilo::business::sign::WalletKiRecord> = (0..4u32)
        .map(|i| shlosilo::business::sign::WalletKiRecord {
            transfer_idx: i,
            wallet_fp: fp,
            key_image: src_ki,
            out_pub: [i as u8; 32],
        })
        .collect();
    let out = sign_with_fixed_entropy_records(enc, &DEV_WALLET_ENTROPY, &records);
    let ours_plain = decrypt_signed_txset(&out, &DEV_VIEW_SK).expect("decrypt our re-sign");
    assert_eq!(
        &ours_plain[..3794],
        &gold_plain[..3794],
        "the whole transaction (framing + vin + vout keys + CLSAG + ptx fields) must \
         reproduce the wallet2-accepted September gold byte-for-byte"
    );
    assert_eq!(
        signed_plain_first_key_image(&ours_plain),
        signed_plain_first_key_image(&gold_plain),
        "key image must match the wallet2-accepted gold byte-for-byte"
    );
    let first_diff = ours_plain
        .iter()
        .zip(gold_plain.iter())
        .position(|(a, b)| a != b)
        .expect("re-sign must diverge from the gold at the key_images policy boundary");
    assert_eq!(
        first_diff, 3794,
        "the only sanctioned divergence is the `key_images` fill policy at offset 3794 \
         (gold per-tx vs ours wallet-indexed); any earlier divergence is a NEW drift \
         in the deterministic part of the signer"
    );
    // Tail shape: `key_images` count 0x04 (ours, wallet-indexed) vs 0x01
    // (gold, per-tx), then the entries; everything after the array is
    // identical shifted by the 3 extra 32B entries (96B).
    assert_eq!(
        gold_plain[3794], 1,
        "gold: per-tx key_images fill (1 input)"
    );
    assert_eq!(
        ours_plain[3794], 4,
        "ours: wallet-indexed key_images fill (4 entries)"
    );
    assert_eq!(
        &gold_plain[3795..3827],
        &ours_plain[3795..3827],
        "the first key_images entry (the true per-tx image) must match byte-for-byte"
    );
    // Second sanctioned divergence (2026-10-31, I12 fix): beyond the
    // key_images array sits the tx_key_images section, and its fill POLICY
    // changed from the historical amount-based filter to the wallet2
    // is_out_to_acc view (tests/tx_key_images_wallet2_view.rs — the fill
    // policy pin). The September gold predates the fix, so the tail is shape-
    // pinned here instead of byte-compared: both sides must stay well-formed
    // tki sections (varint count + 65B entries).
    fn tki_shape_ok(tail: &[u8]) -> usize {
        assert!(
            !tail.is_empty() && tail[0] < 0x80,
            "tki count: single-byte varint"
        );
        let n = tail[0] as usize;
        assert_eq!(
            tail.len(),
            1 + n * 65,
            "tki section geometry: varint + 65B entries"
        );
        n
    }
    let g = tki_shape_ok(&gold_plain[3827..]);
    let o = tki_shape_ok(&ours_plain[3795 + 128..]);
    assert!(
        o >= g,
        "the new fill never records FEWER entries than the old one on this fixture shape"
    );
}

/// Fixed-entropy re-sign of the stagenet fa fixture vs fixtures/ours_signed_fa.bin
/// (the archived shlosilo output of
/// tests/xmr_subaddr_sign_roundtrip.rs::sign_real_fixture_for_wallet2_compare).
/// Full determinism pin: the signer is a pure function of
/// (container, wallet entropy, signer entropy), and the whole signed
/// CONTAINER — envelope, tx_bytes (vout output keys + CLSAG), construction
/// data (incl. the `extra` field) and the key_images tail — reproduces the
/// gold byte-for-byte.
///
/// Gold regenerated 2026-10-20 on the host with the SAME fixed entropy after
/// the pool #39 `construction_data.extra` fix: the signed wire changed (the
/// per-tx context digest absorbs `extra`, and that digest feeds the derived tx
/// key `r`), and the current writer applies the wallet-transfer-indexed
/// `key_images` fill policy (pin_signed_key_images_wallet_indexed) that
/// postdates the previous 2026-10-16 gold. The old gold's shape pins (prefix
/// identity up to offset 3745, per-tx 1-entry vs wallet-indexed 2-entry
/// `key_images` tail) are retired together with that gold.
#[test]
fn golden_resign_fa_matches_archived_our_container() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_fa_subaddr.bin");
    let gold: &[u8] = include_bytes!("fixtures/ours_signed_fa.bin");
    // v2 gap policy: reproduce the archived v1 fill shape via gap-covering
    // records (see golden_resign_dev_1in_fresh_matches_signed_gold). 0..8
    // oversupplies the span on purpose — span-excess records are dropped by
    // the fix37 span tightening.
    let gold_plain = decrypt_signed_txset(gold, &LAB_VIEW_SK).expect("decrypt archived gold");
    let src_ki = signed_plain_first_key_image(&gold_plain);
    let fp = wallet_fp_of(&LAB_WALLET_ENTROPY);
    let records: Vec<shlosilo::business::sign::WalletKiRecord> = (0..8u32)
        .map(|i| shlosilo::business::sign::WalletKiRecord {
            transfer_idx: i,
            wallet_fp: fp,
            key_image: src_ki,
            out_pub: [i as u8; 32],
        })
        .collect();
    let out = sign_with_fixed_entropy_records(enc, &LAB_WALLET_ENTROPY, &records);
    assert_eq!(
        &out[..],
        gold,
        "the whole signed container must reproduce the regenerated gold byte-for-byte \
         (same fixed entropy; construction_data.extra preserved)"
    );
}

/// Regen tool (10-20 precedent, re-run 2026-10-31 for the I12 fill-policy
/// fix): regenerate tests/fixtures/ours_signed_fa.bin from the CURRENT signer
/// under the same fixed entropy and the same gap-record input shape. Run:
///   cargo test --test golden_wallet2_bytes -- --ignored --nocapture dump_ours_signed_fa_gold
#[test]
#[ignore = "host tool: regenerate the archived fa container gold"]
fn dump_ours_signed_fa_gold() {
    let enc: &[u8] = include_bytes!("fixtures/unsigned_fa_subaddr.bin");
    let gold: &[u8] = include_bytes!("fixtures/ours_signed_fa.bin");
    let gold_plain = decrypt_signed_txset(gold, &LAB_VIEW_SK).expect("decrypt archived gold");
    let src_ki = signed_plain_first_key_image(&gold_plain);
    let fp = wallet_fp_of(&LAB_WALLET_ENTROPY);
    let records: Vec<shlosilo::business::sign::WalletKiRecord> = (0..8u32)
        .map(|i| shlosilo::business::sign::WalletKiRecord {
            transfer_idx: i,
            wallet_fp: fp,
            key_image: src_ki,
            out_pub: [i as u8; 32],
        })
        .collect();
    let out = sign_with_fixed_entropy_records(enc, &LAB_WALLET_ENTROPY, &records);
    std::fs::write("tests/fixtures/ours_signed_fa.bin", &out).expect("write gold");
    println!(
        "regenerated tests/fixtures/ours_signed_fa.bin ({} bytes)",
        out.len()
    );
}

/// Invariant pin — "signed_tx_set round-trip must be byte-identical, extra
/// preserved" (Kosmo 2026-10-20), sign-path face: the construction data
/// embedded in OUR signed output must carry the wallet2 `extra` verbatim. The
/// old `SliceVec::new` wipe dropped it, so the signer echoed no payment id
/// where wallet2's output echoes one (the historical "ours: no payment id"
/// divergence vs wallet2). Pin: parse the unsigned
/// fixture with the product parser, sign through the product path
/// (`business::sign::sign_with_entropy`, device-identical) under the fixed
/// entropy, and require the parsed `extra` payload to appear verbatim in the
/// signed plaintext — exactly once, since our signer's own tx extra embeds a
/// different tx pub key / payment-id echo and cannot collide with the
/// preserved wallet2 field.
#[test]
fn golden_sign_path_embeds_construction_data_extra() {
    // Parse side: the product parser must hand the extra to the model.
    let enc: &[u8] = include_bytes!("fixtures/unsigned_fa_subaddr.bin");
    let plain = unsigned_plain(enc, &LAB_VIEW_SK);
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
    .expect("deserialize fa fixture");
    let d = utx.txes.iter().flatten().next().expect("single-tx fixture");
    let extra: Vec<u8> = d.extra.to_vec();
    assert_eq!(
        extra.len(),
        44,
        "fixture wire fact: 44B extra payload (tx pub key + encrypted payment id)"
    );
    // Sign path: the embedded construction data must echo it. (v2 gap policy:
    // gap positions need covering records — dummy values, since this pin is
    // about `extra`, not the key-image values; selected indices are excluded,
    // they derive fresh at sign time.)
    let sel: Vec<u32> = d.selected_transfers.iter().map(|t| *t as u32).collect();
    let span = sel.iter().copied().max().unwrap_or(0) + 1;
    let fp = wallet_fp_of(&LAB_WALLET_ENTROPY);
    let records: Vec<shlosilo::business::sign::WalletKiRecord> = (0..span)
        .filter(|i| !sel.contains(i))
        .map(|i| shlosilo::business::sign::WalletKiRecord {
            transfer_idx: i,
            wallet_fp: fp,
            key_image: [0x5Au8; 32],
            out_pub: [i as u8; 32],
        })
        .collect();
    let out = sign_with_fixed_entropy_records(enc, &LAB_WALLET_ENTROPY, &records);
    let signed_plain = decrypt_signed_txset(&out, &LAB_VIEW_SK).expect("decrypt our signed output");
    let occ = signed_plain
        .windows(extra.len())
        .filter(|w| **w == extra[..])
        .count();
    assert_eq!(
        occ,
        1,
        "the wallet2 construction_data.extra payload must appear verbatim in our signed \
         plaintext (the construction-data field is its only copy — our own tx extra carries \
         different values), hex: {}",
        hex(&extra)
    );
}

/// Minimal signed-plaintext walk: signed_tx_set framing, then the ptx tx
/// prefix (version, unlock_time, vin[]) -> first key image. The key image is
/// a deterministic value (x·Hp(P)), so it is byte-compared below; the
/// signatures around it are not.
fn signed_plain_first_key_image(plain: &[u8]) -> [u8; 32] {
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
    assert_eq!(varint(plain, &mut pos), 1, "single ptx");
    assert_eq!(plain[pos], 1, "ptx version 1");
    pos += 1;
    assert_eq!(varint(plain, &mut pos), 2, "tx version 2");
    let _unlock = varint(plain, &mut pos);
    let n_in = varint(plain, &mut pos);
    assert_eq!(n_in, 1, "single input");
    assert_eq!(plain[pos], 0x02, "txin_to_key tag");
    pos += 1;
    let _amount = varint(plain, &mut pos);
    let n_off = varint(plain, &mut pos);
    for _ in 0..n_off {
        let _rel = varint(plain, &mut pos);
    }
    let mut ki = [0u8; 32];
    ki.copy_from_slice(&plain[pos..pos + 32]);
    ki
}

/// Cross-implementation byte comparison against wallet2's OWN
/// `sign_transfer` output (fixtures/gold_signed_fa.bin, monero-wallet-cli
/// v0.18.5.1 stagenet) over the same unsigned fixture our signer consumed.
///
/// Byte-compared (deterministic on both sides):
///   - the whole vin region (ring offsets + key image): offsets come from the
///     unsigned fixture and the key image is x·Hp(P) — a deterministic value,
///     so byte-equality proves wallet2 and shlosilo derive the SAME one-time
///     input secret. This is the strongest cross-implementation byte pin
///     available for the signing face.
///
/// NOT byte-compared (diverges by construction):
///   - everything past the vin: the first divergence is the vout output key,
///     which embeds the tx secret key r (wallet2 draws r from its RNG, ours is
///     derived from the fixed signer entropy). Also divergent by design:
///     the `key_images` list length (wallet2 carries the wallet-wide spent
///     set, ours the wallet-indexed fill — SIGNED_TX_PARSE_FAIL_REPORT.md
///     §3.1; both wallet2-parse-clean). The construction_data payment-id
///     echo is NO LONGER divergent: it was the pool #39 extra drop, fixed
///     2026-10-20 — our output now echoes the field verbatim (pinned by
///     `golden_sign_path_embeds_construction_data_extra`).
#[test]
fn golden_ours_vs_wallet2_gold_deterministic_region() {
    let gold_container: &[u8] = include_bytes!("fixtures/gold_signed_fa.bin");
    let our_container: &[u8] = include_bytes!("fixtures/ours_signed_fa.bin");
    let gold_plain = decrypt_signed_txset(gold_container, &LAB_VIEW_SK)
        .expect("decrypt wallet2 sign_transfer gold");
    let our_plain = decrypt_signed_txset(our_container, &LAB_VIEW_SK).expect("decrypt ours");
    // The deterministic vin region of this 1-input ring-16 fixture ends at
    // offset 78 (varint framing + offsets + 32B key image).
    assert_eq!(
        &gold_plain[..78],
        &our_plain[..78],
        "vin region (ring offsets + key image) must be byte-identical to \
         wallet2's own signed output"
    );
    assert_eq!(
        signed_plain_first_key_image(&gold_plain),
        signed_plain_first_key_image(&our_plain),
        "key image (deterministic x·Hp(P)) must match wallet2 byte-for-byte"
    );
    // The first divergence must be exactly where the random tx secret key r
    // enters: the first vout output key at offset 78.
    let first_diff = gold_plain
        .iter()
        .zip(our_plain.iter())
        .position(|(a, b)| a != b)
        .expect("gold and ours plaintexts must not be identical (different r)");
    assert_eq!(
        first_diff, 78,
        "the only sanctioned divergence starts at the vout output key \
         (per-implementation tx secret key r)"
    );
    println!(
        "gold={}B ours={}B (Δ{}B): vin[..78] byte-identical vs wallet2 gold; \
         divergent by design past offset 78 (random r / wallet-indexed \
         key_images list; construction_data extra echo now preserved)",
        gold_plain.len(),
        our_plain.len(),
        gold_plain.len().abs_diff(our_plain.len())
    );
}

// ---------------------------------------------------------------------------
// Self-implemented signature verification (verify-not-compare faces).
// Formulas copied from tests/real_fixture.rs (independent re-derivations from
// the spec: Monero crypto.cpp check_signature / check_ring_signature).
// ---------------------------------------------------------------------------

fn hs(data: &[u8]) -> [u8; 32] {
    use curve25519_dalek::scalar::Scalar;
    let h = shlosilo::encoding::keccak256::hash(data).expect("keccak");
    Scalar::from_bytes_mod_order(h).to_bytes()
}

/// Container envelope: Monero Schnorr over keccak256(nonce ‖ cipher-before-sig),
/// pubkey = view_pub.
fn verify_container_sig(container: &[u8], magic: &[u8], view_sk: &[u8; 32]) -> bool {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    if container.len() < magic.len() + 8 + 64 {
        return false;
    }
    let raw = &container[magic.len()..container.len() - 64];
    let sig = &container[container.len() - 64..];
    let msg = shlosilo::encoding::keccak256::hash(raw).expect("keccak");
    let view_pub = (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(*view_sk))
        .compress()
        .to_bytes();
    let c = Scalar::from_bytes_mod_order(sig[..32].try_into().unwrap());
    let r = Scalar::from_bytes_mod_order(sig[32..].try_into().unwrap());
    let p: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(view_pub)
        .decompress()
        .expect("view_pub point")
        .into();
    let r_point = (ED25519_BASEPOINT_TABLE * &r) + (p * c);
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(&msg);
    buf[32..64].copy_from_slice(&view_pub);
    buf[64..].copy_from_slice(&r_point.compress().to_bytes());
    hs(&buf) == c.to_bytes()
}

/// Accompanying key-image signature (ring=1): record = [32B image][64B sig].
fn verify_key_image_sig(record: &[u8], out_pub: &[u8; 32]) -> bool {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    if record.len() != KEY_IMAGE_RECORD_LEN {
        return false;
    }
    let image: [u8; 32] = record[..32].try_into().unwrap();
    let sig = &record[32..96];
    let c = Scalar::from_bytes_mod_order(sig[..32].try_into().unwrap());
    let r = Scalar::from_bytes_mod_order(sig[32..].try_into().unwrap());
    let p: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(*out_pub)
        .decompress()
        .expect("out_pub point")
        .into();
    let i: curve25519_dalek::EdwardsPoint = monero_ed25519::CompressedPoint::from(image)
        .decompress()
        .expect("image point")
        .into();
    let hp_p: curve25519_dalek::EdwardsPoint = monero_ed25519::Point::biased_hash(*out_pub).into();
    let l = (ED25519_BASEPOINT_TABLE * &r) + (p * c);
    let rr = (hp_p * r) + (i * c);
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(&image);
    buf[32..64].copy_from_slice(&l.compress().to_bytes());
    buf[64..].copy_from_slice(&rr.compress().to_bytes());
    hs(&buf) == c.to_bytes()
}

/// Pool #52 ① (2026-10-28): signed-plaintext parse -> re-serialize identity
/// over wallet2's OWN `sign_transfer` output (fixtures/gold_signed_fa.bin,
/// monero-wallet-cli v0.18.5.1 stagenet). The input bytes are wallet2's
/// writer output — byte identity proves our writer is byte-compatible with
/// wallet2 on real data (NOT a self-roundtrip; the tx_key placeholder slot
/// writes Scalar::ONE by design — r is not returned to the host — so this
/// pin also proves wallet2's pending_tx tx_key slot carries the same
/// placeholder bytes in this fixture's production path).
#[test]
fn golden_signed_plain_parse_reserialize_identity() {
    use shlosilo::chain::xmr::signed_txset::{
        decrypt_signed_txset, deserialize_signed_plain, PendingTx, SignedTxSetPools,
        TxKeyImageEntry,
    };
    use shlosilo::chain::xmr::unsigned_txset::{TxDestinationEntry, TxSourceEntry};
    let gold: &[u8] = include_bytes!("fixtures/gold_signed_fa.bin");
    let plain = decrypt_signed_txset(gold, &LAB_VIEW_SK).expect("decrypt wallet2 signed plain");

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
    .expect("parse wallet2 signed plain");

    let mut out = vec![0u8; set.serialized_len().max(plain.len()) + 64];
    let n = set.serialize_into(&mut out).expect("re-serialize");
    // failure-only first-divergence diagnostic (reports the offending offset)
    if out.get(..n) != Some(&plain[..]) {
        let mut i0 = 0usize;
        while i0 < n.min(plain.len()) && out[i0] == plain[i0] {
            i0 += 1;
        }
        let lo = i0.saturating_sub(16);
        std::eprintln!(
            "GSP-DIAG n={} plain_len={} first_mismatch={} ours_tail={:02x?} plain_tail={:02x?}",
            n,
            plain.len(),
            i0,
            &out[lo..(i0 + 16).min(n)],
            &plain[lo..(i0 + 16).min(plain.len())],
        );
    }
    assert_eq!(n, plain.len(), "length identity");
    assert_eq!(
        &out[..n],
        &plain[..],
        "byte identity over wallet2's own signed plain"
    );
}
