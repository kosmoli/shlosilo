//! ETH EIP-1559 full transaction signing (Phase 5 v7 real implementation)
//!
//! Implements:
//! - EIP-1559 transaction data structures
//! - EIP-1559 signing hash（`keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list]))`）
//! - sign_eip1559 business function (sighash → ECDSA → r/s + y_parity → assemble the signed tx)
//!
//! ## Algorithm summary
//!
//! **EIP-1559 signing hash**:
//! ```text
//! keccak256(0x02 || rlp([
//!   chain_id,
//!   nonce,
//!   max_priority_fee_per_gas,
//!   max_fee_per_gas,
//!   gas_limit,
//!   destination,           // 20-byte address, empty if contract creation
//!   amount,
//!   data,
//!   access_list,           // [] for empty
//! ]))
//! ```text
//!
//! **EIP-1559 signed transaction format**:
//! ```text
//! 0x02 || rlp([
//!   chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
//!   destination, amount, data, access_list,
//!   y_parity, r, s,
//! ])
//! ```text
//!
//! **y_parity**: 0 or 1 (not the legacy 27/28)

#[cfg(feature = "alloc-fallback")]
extern crate alloc;
extern crate digest;
use crate::chain::eth::rlp;
use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
use crate::encoding::keccak256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::signature::ecdsa_secp256k1::{self as ecdsa};
use crate::types::SecretBytes;
// Consumers live behind alloc-fallback / cfg(test).
#[cfg(feature = "alloc-fallback")]
#[allow(unused_imports)]
use alloc::vec::Vec;

// --- Data structures ------------------------------------------------

/// EIP-1559 transaction (unsigned)
#[derive(Clone, Debug)]
pub struct Eip1559Transaction<'a> {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// 20-byte destination address, or None for contract creation
    pub destination: Option<[u8; 20]>,
    pub amount: u128,
    /// Calldata — borrowed from the wire in production (Cow, zero-copy).
    /// (EIP-2930 access_list is unsupported in Phase 5 v7: the model carries
    /// no placeholder field — the wire always writes an empty list.)
    pub data: crate::types::wire_bytes::WireBytes<'a>,
}

/// 20-byte Ethereum address
pub type Address = [u8; 20];

/// Signing input
///
/// P1-03: private keys use `SecretBytes<32>` — no Clone, no Debug, ZeroizeOnDrop, constant-time comparison.
pub struct Eip1559SignInput<'a> {
    pub tx: Eip1559Transaction<'a>,
    pub private_key: SecretBytes<32>,
}

/// Signing output
#[derive(Clone, Debug)]
#[cfg(feature = "alloc-fallback")]
pub struct Eip1559SignedTx {
    /// Full signed transaction bytes (0x02 || rlp([..., y_parity, r, s]))
    pub tx_bytes: Vec<u8>,
    /// signing hash (Keccak256 of preimage)
    pub signing_hash: [u8; 32],
    /// signature r
    pub r: [u8; 32],
    /// signature s
    pub s: [u8; 32],
    /// y_parity: 0 or 1
    pub y_parity: u8,
}

// ─── EIP-1559 signing hash ────────────────────────────────────────

/// Compute the EIP-1559 signing hash
///
/// `keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list]))`
pub fn signing_hash(tx: &Eip1559Transaction) -> Result<[u8; 32]> {
    let mut sink = keccak256::KeccakSink::new();
    write_preimage(&mut sink, tx)?;
    Ok(sink.finalize())
}

// --- Zero-alloc serialization core (production) ----------------------
//
// The signing preimage streams straight into `KeccakSink` (no intermediate
// buffer) and the signed transaction streams into the caller's buffer via
// `SinkCursor`. The `Vec<u8>` conveniences below are test/legacy surface
// behind `alloc-fallback`.

use crate::types::push::{Sink, SinkCursor};

/// The 9 fixed tx fields (+3 tail fields when signing) into a sink.
fn write_tx_fields<S: Sink>(
    s: &mut S,
    tx: &Eip1559Transaction,
    tail: Option<(u8, &[u8; 32], &[u8; 32])>,
) -> Result<()> {
    rlp::write_uint(s, tx.chain_id as u128)?;
    rlp::write_uint(s, tx.nonce as u128)?;
    rlp::write_uint(s, tx.max_priority_fee_per_gas)?;
    rlp::write_uint(s, tx.max_fee_per_gas)?;
    rlp::write_uint(s, tx.gas_limit as u128)?;
    match &tx.destination {
        Some(addr) => rlp::write_bytes(s, addr)?,
        None => rlp::write_bytes(s, b"")?,
    }
    rlp::write_uint(s, tx.amount)?;
    rlp::write_bytes(s, tx.data.as_ref())?;
    rlp::write_list_head(s, 0)?; // empty access_list
    if let Some((yp, r, sc)) = tail {
        rlp::write_uint(s, yp as u128)?;
        rlp::write_uint256(s, r)?;
        rlp::write_uint256(s, sc)?;
    }
    Ok(())
}

/// Exact byte length of `write_tx_fields`' output for this tx.
fn tx_fields_len(tx: &Eip1559Transaction, tail: Option<(u8, &[u8; 32], &[u8; 32])>) -> usize {
    let dest: &[u8] = match &tx.destination {
        Some(addr) => addr.as_slice(),
        None => b"",
    };
    let mut n = rlp::encoded_uint_len(tx.chain_id as u128)
        + rlp::encoded_uint_len(tx.nonce as u128)
        + rlp::encoded_uint_len(tx.max_priority_fee_per_gas)
        + rlp::encoded_uint_len(tx.max_fee_per_gas)
        + rlp::encoded_uint_len(tx.gas_limit as u128)
        + rlp::encoded_bytes_len(dest)
        + rlp::encoded_uint_len(tx.amount)
        + rlp::encoded_bytes_len(tx.data.as_ref())
        + rlp::list_head_len(0);
    if let Some((yp, r, sc)) = tail {
        n += rlp::encoded_uint_len(yp as u128)
            + rlp::encoded_uint256_len(r)
            + rlp::encoded_uint256_len(sc);
    }
    n
}

/// 0x02 || rlp([9 fields]) — the EIP-2718 signing preimage.
fn write_preimage<S: Sink>(s: &mut S, tx: &Eip1559Transaction) -> Result<()> {
    s.put(&[0x02])?;
    rlp::write_list_head(s, tx_fields_len(tx, None))?;
    write_tx_fields(s, tx, None)
}

/// The signing preimage bytes into a caller buffer (debug/inspection form).
pub fn signing_preimage_into(tx: &Eip1559Transaction, out: &mut [u8]) -> Result<usize> {
    let mut w = SinkCursor::new(out);
    write_preimage(&mut w, tx)?;
    Ok(w.pos())
}

/// Debug helper: returns the signing preimage bytes
#[cfg(feature = "alloc-fallback")]
pub fn signing_preimage(tx: &Eip1559Transaction) -> Result<Vec<u8>> {
    let need = 1 + rlp::list_head_len(tx_fields_len(tx, None)) + tx_fields_len(tx, None);
    let mut out = alloc::vec![0u8; need];
    let n = signing_preimage_into(tx, &mut out)?;
    out.truncate(n);
    Ok(out)
}

// --- sign_eip1559 business function -------------------------------

/// Compute y_parity (recovery_id) — derive R.y's parity from (r, s, z, pk)
///
/// Algorithm: R = r⁻¹ · (s · pk − z · G)  ;  y_parity = R.y mod 2
///
/// Using k256 0.14 ProjectivePoint + Scalar arithmetic
/// Compute y_parity (recovery_id) — via k256::ecdsa::VerifyingKey::recover_from_prehash
///
/// In ECDSA, given (z, r, s) + y_parity ∈ {0, 1}, the pubkey can be recovered.
/// Compare the recovered pubkey with the actual pubkey to find the correct y_parity.
///
/// k256 0.14 provides `VerifyingKey::recover_from_prehash(prehash, &sig, recid)`,
/// which accepts a 32-byte prehash (**no** Digest trait needed) — a perfect match for our use case.
fn compute_y_parity(
    sk: &crate::curve_primitive::secp256k1::Secp256k1Scalar,
    signing_hash_bytes: &[u8; 32],
    r_bytes: &[u8; 32],
    s_bytes: &[u8; 32],
) -> Result<u8> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    // Build the signature (r || s, 64 bytes)
    let mut sig_64 = [0u8; 64];
    sig_64[..32].copy_from_slice(r_bytes);
    sig_64[32..].copy_from_slice(s_bytes);
    let sig = Signature::from_slice(&sig_64)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // pubkey (compressed 33 bytes) from sk
    let pk_point = base_mul(sk);
    let pk_compressed = point_to_compressed(&pk_point);

    // Try y_parity = 0 and 1
    for y_parity in 0u8..=1u8 {
        // RecoveryId::new(is_y_odd: bool, is_x_reduced: bool)
        let recid = RecoveryId::new(y_parity == 1, false);
        let recovered = VerifyingKey::recover_from_prehash(signing_hash_bytes, &sig, recid);
        if let Ok(recovered_pk) = recovered {
            // VerifyingKey::to_sec1_point(false) = compressed SEC1 33 bytes
            let sec1_point = recovered_pk.to_sec1_point(true);
            let rec_bytes = sec1_point.as_bytes();
            if rec_bytes == &pk_compressed[..] {
                return Ok(y_parity);
            }
        }
    }

    Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// Sign an EIP-1559 transaction
/// Zero-alloc signed-tx outcome (pure arrays).
pub struct Eip1559SignOutcome {
    pub written: usize,
    pub signing_hash: [u8; 32],
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub y_parity: u8,
}

/// Sign an EIP-1559 transaction, writing `0x02 || rlp([12 fields])` straight
/// into the caller's buffer. Zero-alloc production form.
pub fn sign_eip1559_into(input: &Eip1559SignInput, out: &mut [u8]) -> Result<Eip1559SignOutcome> {
    let sk = scalar_from_bytes(input.private_key.expose())?;

    // 1. signing hash (streams the preimage into Keccak — no buffer)
    let t_hash = crate::device_timing::Mark::start(crate::device_timing::STAGE_KECCAK);
    let sighash = signing_hash(&input.tx)?;
    t_hash.end();

    // 2. ECDSA sign_prehash (returns r||s = 64 bytes)
    let t_ecdsa = crate::device_timing::Mark::start(crate::device_timing::STAGE_Y_PARITY);
    let sig = ecdsa::sign(&sk, &sighash)?;
    t_ecdsa.end();
    // NOTE: STAGE_Y_PARITY slot doubles as the ecdsa::sign measurement; y_parity
    // recovery is measured into STAGE_SERIALIZE below (slot reuse keeps the FFI
    // surface at 8 stages; see device_timing.rs for the stage map).
    let sig_bytes = sig.as_ref();
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[..32]);
    s_bytes.copy_from_slice(&sig_bytes[32..]);

    // 2.5 BIP-146 / EIP-2 low-s enforcement:
    //     compute y_parity with the original s first, then flip s to (n - s) if s > n/2
    //     flipping s is equivalent to R → -R (R.y parity flips)
    let t_yp = crate::device_timing::Mark::start(crate::device_timing::STAGE_SERIALIZE);
    let y_parity_original = compute_y_parity(&sk, &sighash, &r_bytes, &s_bytes)?;
    t_yp.end();

    let half_n_high: [u8; 16] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff,
    ];
    let half_n_low: [u8; 16] = [
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20,
        0xa0,
    ];
    let s_high = &s_bytes[..16];
    let s_low = &s_bytes[16..];
    let is_high_s = if s_high > half_n_high.as_slice() {
        true
    } else if s_high < half_n_high.as_slice() {
        false
    } else {
        s_low > half_n_low.as_slice()
    };
    let y_parity = if is_high_s {
        let n_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut new_s = [0u8; 32];
        let mut borrow: u8 = 0;
        for i in (0..32).rev() {
            let a = n_bytes[i];
            let b = sig_bytes[i];
            let (d, b1) = a.overflowing_sub(b);
            let (d2, b2) = d.overflowing_sub(borrow);
            new_s[i] = d2;
            borrow = (b1 || b2) as u8;
        }
        s_bytes.copy_from_slice(&new_s);
        // flip y_parity (R → -R, parity flips)
        y_parity_original ^ 1
    } else {
        y_parity_original
    };

    // 3. Build signed transaction: 0x02 || rlp([12 fields])
    let t_ser = crate::device_timing::Mark::start(crate::device_timing::STAGE_RLP);
    let tail = (y_parity, &r_bytes, &s_bytes);
    let payload_len = tx_fields_len(&input.tx, Some(tail));
    let need = 1 + rlp::list_head_len(payload_len) + payload_len;
    if out.len() < need {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(need),
        ));
    }
    let mut w = SinkCursor::new(out);
    w.put(&[0x02])?;
    rlp::write_list_head(&mut w, payload_len)?;
    write_tx_fields(&mut w, &input.tx, Some(tail))?;
    t_ser.end();

    Ok(Eip1559SignOutcome {
        written: w.pos(),
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        y_parity,
    })
}

/// Test/legacy convenience (allocates). Production paths use `sign_eip1559_into`.
#[cfg(feature = "alloc-fallback")]
pub fn sign_eip1559(input: &Eip1559SignInput) -> Result<Eip1559SignedTx> {
    let payload_len = tx_fields_len(&input.tx, None);
    let tail_budget = rlp::encoded_uint_len(1) + 33 + 33;
    let need = 1 + rlp::list_head_len(payload_len + tail_budget) + payload_len + tail_budget;
    let mut buf = alloc::vec![0u8; need];
    let out = sign_eip1559_into(input, &mut buf)?;
    buf.truncate(out.written);
    Ok(Eip1559SignedTx {
        tx_bytes: buf,
        signing_hash: out.signing_hash,
        r: out.r,
        s: out.s,
        y_parity: out.y_parity,
    })
}

// --- Helpers: hex decode -------------------------------------------

#[cfg(test)]
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
    }
}

// --- Unit tests ----------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-1559 test vector (reference values computed ourselves with Python)
    /// private_key: 0x4646464646464646464646464646464646464646464646464646464646464646
    /// chain_id: 1, nonce: 0, max_priority_fee: 1 gwei, max_fee: 20 gwei, gas_limit: 21000
    /// destination: 0x3535353535353535353535353535353535353535
    /// amount: 1 ETH
    ///
    /// Expected signing hash: 2cb489a9d0facd97d34bb756c61070935ff0c5fa306bd677acf969b57dbc9e7a
    /// Expected signed tx:    02f87201843b9aca008504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080c001a0d1453c4f511f81fda6e7d582b6f0cfb1d50f0804fc61bf1040aeb09f5fc0958ca0346d4c998fc306a947a1e4ee414d8c9341ae28f4136c89889f686ce4975dd8e8
    #[test]
    fn eip1559_signing_hash_test_vector() {
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };

        let hash = signing_hash(&tx).unwrap();
        let expected_hex = "f63a609bfdfcc60853764d633f8de24fc6bf6f85e19ee6c0f2d089f7ee8d5d86";
        let expected_bytes = hex_decode(expected_hex).unwrap();
        assert_eq!(&hash[..], &expected_bytes[..], "signing hash mismatch");
    }

    /// Full sign_eip1559 + signed tx comparison
    #[test]
    fn sign_eip1559_full_pipeline() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646").unwrap();
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };

        let input = Eip1559SignInput { tx, private_key };
        let signed = sign_eip1559(&input).unwrap();

        // Verify the signing hash
        let expected_hash = "f63a609bfdfcc60853764d633f8de24fc6bf6f85e19ee6c0f2d089f7ee8d5d86";
        let expected_hash_bytes = hex_decode(expected_hash).unwrap();
        assert_eq!(&signed.signing_hash[..], &expected_hash_bytes[..]);

        // Verify r
        let expected_r = "b3d7e5d4775918a0ec38e4f9da6263f69c2072c0e177ff9aa274575bfba17d04";
        let expected_r_bytes = hex_decode(expected_r).unwrap();
        assert_eq!(&signed.r[..], &expected_r_bytes[..]);

        // Verify s
        let expected_s = "62182875ae92e4de08aaf8ea1a43d3ea0d836745788801cdc79ccc473a76dfd9";
        let expected_s_bytes = hex_decode(expected_s).unwrap();
        assert_eq!(&signed.s[..], &expected_s_bytes[..]);

        // Verify y_parity (k256 0.14 defaults to low-s enforcement, y_parity=1)
        assert_eq!(signed.y_parity, 1);

        // Verify the full signed tx
        let expected_tx = "02f8730180843b9aca008504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080c001a0b3d7e5d4775918a0ec38e4f9da6263f69c2072c0e177ff9aa274575bfba17d04a062182875ae92e4de08aaf8ea1a43d3ea0d836745788801cdc79ccc473a76dfd9";
        let expected_tx_bytes = hex_decode(expected_tx).unwrap();
        assert_eq!(
            &signed.tx_bytes[..],
            &expected_tx_bytes[..],
            "signed tx mismatch"
        );
    }

    /// Determinism: same input → same output
    #[test]
    fn deterministic_signing() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646").unwrap();
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };

        let input = Eip1559SignInput { tx, private_key };

        let signed1 = sign_eip1559(&input).unwrap();
        let signed2 = sign_eip1559(&input).unwrap();
        assert_eq!(signed1.signing_hash, signed2.signing_hash);
        assert_eq!(signed1.tx_bytes, signed2.tx_bytes);
    }

    /// Contract creation (destination = None) → different signing hash
    #[test]
    fn contract_creation_differs_from_transfer() {
        let mut tx_transfer = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 0,
            data: Vec::new().into(),
        };
        let hash_transfer = signing_hash(&tx_transfer).unwrap();

        // contract creation: destination = None
        tx_transfer.destination = None;
        let hash_create = signing_hash(&tx_transfer).unwrap();

        assert_ne!(
            hash_transfer, hash_create,
            "contract creation should produce different hash"
        );
    }

    /// Different chain_id → different signing hash
    #[test]
    fn chain_id_changes_signing_hash() {
        let mk_tx = |chain_id: u64| Eip1559Transaction {
            chain_id,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 0,
            data: Vec::new().into(),
        };

        let hash_mainnet = signing_hash(&mk_tx(1)).unwrap();
        let hash_sepolia = signing_hash(&mk_tx(11155111)).unwrap();

        assert_ne!(hash_mainnet, hash_sepolia);
    }
}
