//! Key-path -> address pins for the acceptance wallets.
//!
//! ## Why this file exists
//!
//! An operating checklist told the operator to expect a specific address per script
//! type. Two of those expected values turned out to be wrong, and the operator hit
//! the mismatch on real wallets - the device was fine, the checklist was not. A
//! hand-computed address is not evidence; a pinned, cross-derived one is.
//!
//! Everything here runs on the device face (no allocator): the scriptPubKey is built
//! in a fixed-size array and rendered through `address::btc_script`, the same path the
//! review page uses, so these pins also cover the no-alloc build.
//!
//! ## Where the vectors come from (all machine-derived, none hand-typed)
//!
//! Seed: BIP-39 entropy `f284fb6c…b22916`, empty passphrase, master fingerprint
//! `f3b9960b` - the acceptance seed this project has used throughout.
//!
//! Four independent implementations agree on the BIP-49 vector, which is the one the
//! bad checklist value collided with:
//!
//! 1. Bitcoin Core v31.0.0 (isolated regtest instance) produced the same redeem
//!    script hash in the P2SH-P2WPKH fixture:
//!    `tests/fixtures/core_regtest_p2sh_p2wpkh_331b.psbt` carries scriptPubKey
//!    `a9143bd0ce93a9ba0f29e6ceadeceb702cd215e052f287`.
//! 2. Sparrow (Nested Segwit wallet, signet) shows exactly this first address.
//! 3. `@scure/bip32` + RIPEMD-160/base58check derivation from the mnemonic
//!    (recorded in `~/works/shlosilo-acceptance/export-expected/`).
//! 4. This crate.
//!
//! The BIP-86 and BIP-84 vectors were derived the same way; the BIP-86 signet one is
//! also what Sparrow showed for the Taproot wallet of this seed.
//!
//! ## Two traps this file exists to catch
//!
//! 1. **P2SH-P2WPKH is HASH160 of the redeem script**, i.e. RIPEMD-160(SHA-256(redeem)),
//!    not RIPEMD-160(redeem). Hashing the redeem script directly yields a
//!    perfectly valid-looking `2N…` address from a wrong scriptPubKey.
//! 2. **BIP-86 needs the x-only lift, not the derived key's y.** When the derived
//!    internal key has odd y, the tweak must be applied to -P (BIP-341 lifts to even
//!    y). Skipping that produces a valid-looking `bc1p…` that no wallet will ever
//!    show - the signet path happened to have even y, so only the mainnet vector
//!    exposes it.

use shlosilo::address::btc_script;
use shlosilo::chain::btc::taproot::compute_output_key;
use shlosilo::curve_primitive::secp256k1::{base_mul, point_to_compressed};
use shlosilo::derivation::bip32_secp256k1::derive_from_seed;
use shlosilo::derivation::path::DerivationPath;
use shlosilo::encoding::ripemd160::hash as ripemd160;
use shlosilo::encoding::sha256::hash as sha256;
use shlosilo::network::Network;

const ENTROPY: [u8; 16] = [
    0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29, 0x16,
];

fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data).expect("sha256")).expect("ripemd160")
}

fn compressed_pubkey(path: &str) -> [u8; 33] {
    let m = shlosilo::entropy::mnemonic::Mnemonic::from_entropy(&ENTROPY).expect("entropy");
    let seed = m.to_seed(b"");
    let p = DerivationPath::parse(path).expect("path");
    let sk = derive_from_seed(&seed, &p).expect("derive");
    point_to_compressed(&base_mul(&sk))
}

/// P2SH-P2WPKH: scriptPubKey = OP_HASH160 <HASH160(redeemScript)> OP_EQUAL.
fn p2sh_p2wpkh_address(path: &str, network: Network) -> String {
    let pubkey_hash = hash160(&compressed_pubkey(path));
    let mut redeem = [0u8; 22];
    redeem[0] = 0x00; // OP_0 (P2WPKH witness program marker)
    redeem[1] = 0x14; // push 20 bytes
    redeem[2..].copy_from_slice(&pubkey_hash);

    let mut spk = [0u8; 23];
    spk[0] = 0xa9; // OP_HASH160
    spk[1] = 0x14;
    spk[2..22].copy_from_slice(&hash160(&redeem));
    spk[22] = 0x87; // OP_EQUAL
    String::from(btc_script::render(&spk, network).expect("render").as_ref())
}

/// P2WPKH: scriptPubKey = OP_0 <HASH160(pubkey)>.
fn p2wpkh_address(path: &str, network: Network) -> String {
    let h = hash160(&compressed_pubkey(path));
    let mut spk = [0u8; 22];
    spk[0] = 0x00;
    spk[1] = 0x14;
    spk[2..].copy_from_slice(&h);
    String::from(btc_script::render(&spk, network).expect("render").as_ref())
}

/// P2TR (BIP-86 key path): scriptPubKey = OP_1 <32-byte tweaked x-only output key>.
fn p2tr_address(path: &str, network: Network) -> String {
    let compressed = compressed_pubkey(path);
    let mut internal_x = [0u8; 32];
    internal_x.copy_from_slice(&compressed[1..]);
    let output_key = compute_output_key(&internal_x).expect("taptweak");
    let out_compressed = point_to_compressed(&output_key);

    let mut spk = [0u8; 34];
    spk[0] = 0x51; // OP_1
    spk[1] = 0x20; // push 32 bytes
    spk[2..].copy_from_slice(&out_compressed[1..]);
    String::from(btc_script::render(&spk, network).expect("render").as_ref())
}

/// The value the operator's Nested Segwit wallet actually shows.
#[test]
fn bip49_signet_first_address_matches_core_fixture_and_sparrow() {
    assert_eq!(
        p2sh_p2wpkh_address("m/49'/1'/0'/0/0", Network::BitcoinTestnet),
        "2MxhVzmBQFP9qrSEPJ79E7Stobjf3mJtLRb"
    );
}

/// The value the operator's Taproot wallet actually shows.
#[test]
fn bip86_signet_first_address_matches_sparrow() {
    assert_eq!(
        p2tr_address("m/86'/1'/0'/0/0", Network::BitcoinTestnet),
        "tb1p7gles6nwmwuywa8gfak4ps7pvzk8h7nr6yph6a4yptyeclcwtnhs2pya0v"
    );
}

/// Native SegWit on signet - the derivation cross-check the checklist quotes.
#[test]
fn bip84_signet_first_address() {
    assert_eq!(
        p2wpkh_address("m/84'/1'/0'/0/0", Network::BitcoinTestnet),
        "tb1qf5a34hukrsp4uefsr2j5cfuze6gdw6kdmppea2"
    );
}

/// The three paths the account-export leg ships, at their first address. The
/// BIP-84 one is what a wallet must show after importing the `bitcoin:?xpub=` export.
#[test]
fn mainnet_first_addresses_for_the_export_paths() {
    assert_eq!(
        p2wpkh_address("m/84'/0'/0'/0/0", Network::BitcoinMainnet),
        "bc1qeprpf3ufpa4as2e4zk9f3mtnqe0mzak5ymw5hv"
    );
    assert_eq!(
        p2sh_p2wpkh_address("m/49'/0'/0'/0/0", Network::BitcoinMainnet),
        "38ia7N58N2ztBZc7gxk7eVYdB7rXdLvjVx"
    );
    assert_eq!(
        p2tr_address("m/86'/0'/0'/0/0", Network::BitcoinMainnet),
        "bc1pza9xzt70a2td6el08t96pdee2p6hh8wnj8t6xa3gu2f2njuysczsdnsry8"
    );
}
