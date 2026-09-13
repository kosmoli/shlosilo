//! On-device signing smoke: exercises the business layer (create_account /
//! export_readonly / sign) with the same fixed fixtures the host-sim uses
//! (flux/host-sim/sim_l3.c), so the board's output can be diffed against the
//! host oracle.
//!
//! Rust-native: calls the `forms` core directly (no FFI). The whole run is
//! synchronous - the fixtures are pure functions of their inputs (dice rolls
//! go through exact rejection sampling, no RNG; BTC/ETH signing is RFC-6979
//! deterministic) - so it can execute on the embassy executor without
//! borrowing an async context.

use shlosilo::business;
use shlosilo::derivation::path::DerivationPath;
use shlosilo::entropy::mnemonic::{Mnemonic, WordCount};
use shlosilo::error::ShlosiloError;
use shlosilo::network::Network;
use shlosilo::ur::ur_decode;

/// Fixed dice-roll fixture (matches flux/host-sim/sim_l3.c): 64 x d6,
/// [1..6] cycling. 64 rolls exceed the 128-bit floor for a 12-word mnemonic.
fn fixture_rolls() -> [u8; 64] {
    let mut rolls = [0u8; 64];
    for (i, r) in rolls.iter_mut().enumerate() {
        *r = (i % 6 + 1) as u8;
    }
    rolls
}

/// ETH sign-request fixture UR (matches flux/host-sim/sim_l3.c).
const ETH_SIGN_REQUEST_URI: &str = "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmaymwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxadaaadrpceaadt";

/// Render bytes as lowercase hex into `out`; returns the hex &str.
fn to_hex<'a>(bytes: &[u8], out: &'a mut [u8]) -> &'a str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    assert!(out.len() >= bytes.len() * 2, "hex buffer too small");
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    core::str::from_utf8(&out[..bytes.len() * 2]).unwrap_or("<hex>")
}

/// Run the three-step fixture flow, logging every result. Buffer sizes match
/// the host-sim's (mnemonic 24 B, UR export 2048 B).
pub fn run() -> Result<(), ShlosiloError> {
    // ── Step 1: create_account — dice rolls → mnemonic indices ──
    let rolls = fixture_rolls();
    let mut mnemonic_buf = [0u8; 24];
    business::create_account::create_account(
        WordCount::Words12,
        6,
        &rolls,
        b"",
        &mut mnemonic_buf,
    )?;

    let mut indices = [0u16; 12];
    for (i, idx) in indices.iter_mut().enumerate() {
        *idx = u16::from_le_bytes([mnemonic_buf[i * 2], mnemonic_buf[i * 2 + 1]]);
    }
    log::info!(
        "[smoke] create_account ok: idx = {} {} {} {} {} {} {} {} {} {} {} {}",
        indices[0],
        indices[1],
        indices[2],
        indices[3],
        indices[4],
        indices[5],
        indices[6],
        indices[7],
        indices[8],
        indices[9],
        indices[10],
        indices[11]
    );

    // ── Step 2: export_readonly — mnemonic → crypto-hdkey UR ──
    let mnemonic = Mnemonic::from_indices(&indices, WordCount::Words12)?;
    let mut seed = [0u8; 64];
    business::restore_seed::restore_seed(&mnemonic, b"", &mut seed)?;
    let path = DerivationPath::from_flat([44u32 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0])?;
    let mut export_out = [0u8; 2048];
    let export_len = business::export_readonly::export_readonly(
        business::export_readonly::ExportProtocol::CryptoHdKey,
        &seed,
        Network::BitcoinMainnet,
        core::slice::from_ref(&path),
        &mut export_out,
    )?;
    let uri = core::str::from_utf8(&export_out[..export_len]).unwrap_or("<non-utf8>");
    log::info!("[smoke] export_readonly ok: {}", uri);

    // ── Step 3: sign — eth-sign-request UR fixture → signed tx ──
    let decoded = ur_decode::decode(ETH_SIGN_REQUEST_URI)?;
    // Note: the C-side FFI entry additionally runs its network check
    // (check_network) before signing - that check lives at the host boundary
    // (the FFI layer owns the network parameter) and is a no-op for this ETH
    // fixture under the host-sim's network argument; the direct Rust path
    // goes straight to the business layer the same way.
    // The URI is decoded again from the fixture (host-sim parity); the mnemonic
    // is re-built from the same indices as in step 2.
    let signing_mnemonic = Mnemonic::from_indices(&indices, WordCount::Words12)?;
    let input = business::sign::SignInput::Mnemonic {
        mnemonic: signing_mnemonic,
        passphrase: b"",
    };
    let mut sign_out = [0u8; 512];
    // BTC/ETH do not consume injected entropy (RFC-6979); empty slice per the
    // §B.5 contract.
    let sign_len = business::sign::sign_with_entropy(
        input,
        decoded.type_tag(),
        decoded.as_ref(),
        &[],
        &mut sign_out,
    )?;
    let mut hex_buf = [0u8; 1024];
    let hex = to_hex(&sign_out[..sign_len], &mut hex_buf);
    log::info!("[smoke] sign ok: {} bytes", sign_len);
    log::info!("[smoke] signed: {}", hex);

    // Zero the sensitive stack material (parity with the C host's cleanup).
    seed.fill(0);
    mnemonic_buf.fill(0);

    Ok(())
}
