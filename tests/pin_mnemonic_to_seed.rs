//! Pool §20 MUST-RED pin: `Mnemonic::to_seed` (forms/entropy/mnemonic.rs:180)
//! is a Phase-2 stub that silently returns `[0u8; 64]` — the zero-seed trap:
//! any caller gets an all-zero seed and therefore identical keys for every
//! mnemonic, with no error surfaced. (The key-supply path already routes around
//! it via the production `bip39_passphrase::mnemonic_to_seed`, but the stub
//! itself is still a landmine.)
//!
//! > STATUS 2026-10-21: FLIPPED GREEN (real BIP-39 derivation, `06fece4`) — the red contract below is history.
//!
//! `to_seed_derives_non_degenerate_seed` was INTENTIONALLY RED while the stub
//! returns zeros: a VALID mnemonic must derive a NON-degenerate seed. When the
//! real PBKDF2-HMAC-SHA512(mnemonic_sentence, "mnemonic" + passphrase, 2048)
//! derivation lands (or the stub is deleted/panics on misuse), this pin goes
//! green. No `#[should_panic]`, no `#[ignore]`: the red contract is the panic
//! text below.

/// MUST-RED: `to_seed` on a valid mnemonic must not return the all-zero stub.
#[test]
fn to_seed_derives_non_degenerate_seed() {
    use shlosilo::entropy::mnemonic::Mnemonic;

    // A VALID mnemonic (24 words from 32B entropy, checksum embedded) — this
    // is not a degenerate input; the bug is in to_seed itself.
    let m = Mnemonic::from_entropy(&[0x42u8; 32]).expect("entropy -> mnemonic");
    m.validate().expect("fixture mnemonic must be valid");

    let seed = m.to_seed(b"");
    if seed == [0u8; 64] {
        panic!(
            "PINNED RED: Mnemonic::to_seed returned [0u8; 64] for a valid mnemonic (pool §20 \
             zero-seed trap; forms/entropy/mnemonic.rs:180 Phase-2 stub). Every caller silently \
             derives identical all-zero keys. Fix direction: implement the real BIP-39 derivation \
             PBKDF2-HMAC-SHA512(mnemonic_sentence, \"mnemonic\" + passphrase, 2048 iterations) \
             (the production key path already uses bip39_passphrase::mnemonic_to_seed), or delete \
             the stub / make it panic!(\"unimplemented\") so misuse surfaces immediately."
        );
    }
}
