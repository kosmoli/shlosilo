//! ETH EIP-155 Legacy transaction signing (Phase 5 v8)
//!
//! Implements:
//! - EIP-155 transaction data structure
//! - EIP-155 signing hash（`keccak256(rlp([nonce, gas_price, gas_limit, destination, amount, data, chain_id, 0, 0]))`）
//! - sign_eip155 business function (sighash → ECDSA → r/s + y_parity → v = chain_id*2 + 35 + y_parity → assemble the signed tx)
//!
//! ## Algorithm summary
//!
//! **EIP-155 signing hash** (note: no type prefix, unlike EIP-1559):
//! ```text
//! keccak256(rlp([
//!   nonce,
//!   gas_price,
//!   gas_limit,
//!   destination,           // 20-byte address, empty if contract creation
//!   amount,
//!   data,
//!   chain_id,
//!   0,                     // EIP-155 marker
//!   0,                     // EIP-155 marker
//! ]))
//! ```text
//!
//! **EIP-155 signed transaction format** (no type prefix):
//! ```text
//! rlp([
//!   nonce, gas_price, gas_limit, destination, amount, data,
//!   v, r, s,
//! ])
//! ```text
//!
//! **v** = `chain_id * 2 + 35 + y_parity` (y_parity = 0 or 1)
//! - mainnet chain_id = 1 → v = 37 or 38
//! - The old unsigned v is 27/28 (pre-EIP-155)

#[cfg(feature = "alloc-fallback")]
extern crate alloc;
use crate::chain::eth::rlp;
use crate::chain::eth::sign;
use crate::encoding::keccak256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::SecretBytes;
// Consumers live behind alloc-fallback / cfg(test).
#[cfg(feature = "alloc-fallback")]
#[allow(unused_imports)]
use alloc::vec::Vec;

/// EIP-155 Legacy transaction (unsigned)
#[derive(Clone, Debug)]
pub struct Eip155Transaction<'a> {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    /// 20-byte destination address, or None for contract creation
    pub destination: Option<[u8; 20]>,
    pub amount: u128,
    /// Calldata — borrowed from the wire in production (Cow, zero-copy).
    pub data: crate::types::wire_bytes::WireBytes<'a>,
}

/// Signing input
///
/// P1-03: the private key uses `SecretBytes<32>` — no Clone or Debug, ZeroizeOnDrop, constant-time comparison.
pub struct Eip155SignInput<'a> {
    pub tx: Eip155Transaction<'a>,
    pub private_key: SecretBytes<32>,
}

/// Signing output
#[derive(Clone, Debug)]
#[cfg(feature = "alloc-fallback")]
pub struct Eip155SignedTx {
    /// Full signed transaction bytes (rlp([..., v, r, s])) — no type prefix
    pub tx_bytes: Vec<u8>,
    /// signing hash
    pub signing_hash: [u8; 32],
    /// signature r
    pub r: [u8; 32],
    /// signature s
    pub s: [u8; 32],
    /// v = chain_id * 2 + 35 + y_parity
    pub v: u64,
}

// ─── EIP-155 signing hash ────────────────────────────────────────

/// Compute the EIP-155 signing hash
///
/// `keccak256(rlp([nonce, gas_price, gas_limit, destination, amount, data, chain_id, 0, 0]))`
pub fn signing_hash(tx: &Eip155Transaction) -> Result<[u8; 32]> {
    let mut sink = keccak256::KeccakSink::new();
    rlp::write_list_head(&mut sink, preimage_len(tx))?;
    write_preimage(&mut sink, tx)?;
    Ok(sink.finalize())
}

// ─── Zero-alloc serialization core (production) ──────────────────
//
// Same streaming shape as eip1559: the preimage feeds `KeccakSink`
// directly and the signed transaction writes through `SinkCursor`. The
// Vec conveniences below are test/legacy surface behind `alloc-fallback`.

use crate::types::push::{Sink, SinkCursor};

/// The 6 fixed tx fields into a sink.
fn write_tx_base<S: Sink>(s: &mut S, tx: &Eip155Transaction) -> Result<()> {
    rlp::write_uint(s, tx.nonce as u128)?;
    rlp::write_uint(s, tx.gas_price)?;
    rlp::write_uint(s, tx.gas_limit as u128)?;
    match &tx.destination {
        Some(addr) => rlp::write_bytes(s, addr)?,
        None => rlp::write_bytes(s, b"")?,
    }
    rlp::write_uint(s, tx.amount)?;
    rlp::write_bytes(s, tx.data.as_ref())?;
    Ok(())
}

fn tx_base_len(tx: &Eip155Transaction) -> usize {
    let dest: &[u8] = match &tx.destination {
        Some(addr) => addr.as_slice(),
        None => b"",
    };
    rlp::encoded_uint_len(tx.nonce as u128)
        + rlp::encoded_uint_len(tx.gas_price)
        + rlp::encoded_uint_len(tx.gas_limit as u128)
        + rlp::encoded_bytes_len(dest)
        + rlp::encoded_uint_len(tx.amount)
        + rlp::encoded_bytes_len(tx.data.as_ref())
}

/// rlp([base, chain_id, 0, 0]) — the EIP-155 signing preimage payload.
fn write_preimage<S: Sink>(s: &mut S, tx: &Eip155Transaction) -> Result<()> {
    write_tx_base(s, tx)?;
    rlp::write_uint(s, tx.chain_id as u128)?;
    rlp::write_uint(s, 0)?;
    rlp::write_uint(s, 0)
}

fn preimage_len(tx: &Eip155Transaction) -> usize {
    tx_base_len(tx) + rlp::encoded_uint_len(tx.chain_id as u128) + 2
}

/// Compute the signing preimage bytes into a caller buffer.
pub fn signing_preimage_into(tx: &Eip155Transaction, out: &mut [u8]) -> Result<usize> {
    let payload_len = preimage_len(tx);
    let mut w = SinkCursor::new(out);
    rlp::write_list_head(&mut w, payload_len)?;
    write_preimage(&mut w, tx)?;
    Ok(w.pos())
}

/// Compute the signing preimage bytes
#[cfg(feature = "alloc-fallback")]
pub fn signing_preimage(tx: &Eip155Transaction) -> Vec<u8> {
    let need = rlp::list_head_len(preimage_len(tx)) + preimage_len(tx);
    let mut out = alloc::vec![0u8; need];
    let n = signing_preimage_into(tx, &mut out).expect("buffer pre-sized");
    out.truncate(n);
    out
}

// ─── sign_eip155 business function ──────────────────────────────────────────

/// Zero-alloc signed-tx outcome (pure arrays).
pub struct Eip155SignOutcome {
    pub written: usize,
    pub signing_hash: [u8; 32],
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u64,
}

/// Sign an EIP-155 legacy transaction, writing `rlp([9 fields])` straight
/// into the caller's buffer. Zero-alloc production form.
pub fn sign_eip155_into(input: &Eip155SignInput, out: &mut [u8]) -> Result<Eip155SignOutcome> {
    let sk = sign::sk_from_pk(input.private_key.expose())?;

    // 1. signing hash (streams the preimage into Keccak — no buffer)
    let sighash = signing_hash(&input.tx)?;

    // 2. ECDSA sign + low-s enforcement + y_parity
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let y_parity = sign::apply_low_s(&sighash, &sk, &mut r_bytes, &mut s_bytes)?;

    // 3. v = chain_id * 2 + 35 + y_parity
    let v = input.tx.chain_id * 2 + 35 + y_parity as u64;

    // 4. Build signed transaction (no type prefix)
    let payload_len = tx_base_len(&input.tx)
        + rlp::encoded_uint_len(v as u128)
        + rlp::encoded_uint256_len(&r_bytes)
        + rlp::encoded_uint256_len(&s_bytes);
    let need = rlp::list_head_len(payload_len) + payload_len;
    if out.len() < need {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(need),
        ));
    }
    let mut w = SinkCursor::new(out);
    rlp::write_list_head(&mut w, payload_len)?;
    write_tx_base(&mut w, &input.tx)?;
    rlp::write_uint(&mut w, v as u128)?;
    rlp::write_uint256(&mut w, &r_bytes)?;
    rlp::write_uint256(&mut w, &s_bytes)?;

    Ok(Eip155SignOutcome {
        written: w.pos(),
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        v,
    })
}

/// Test/legacy convenience (allocates). Production paths use `sign_eip155_into`.
#[cfg(feature = "alloc-fallback")]
pub fn sign_eip155(input: &Eip155SignInput) -> Result<Eip155SignedTx> {
    let payload_len = tx_base_len(&input.tx) + rlp::encoded_uint_len(u64::MAX as u128) + 33 + 33;
    let need = rlp::list_head_len(payload_len) + payload_len;
    let mut buf = alloc::vec![0u8; need];
    let out = sign_eip155_into(input, &mut buf)?;
    buf.truncate(out.written);
    Ok(Eip155SignedTx {
        tx_bytes: buf,
        signing_hash: out.signing_hash,
        r: out.r,
        s: out.s,
        v: out.v,
    })
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // Consumers live behind alloc-fallback / cfg(test); unused on the no-alloc face.
    #[allow(unused_imports)]
    use alloc::vec::Vec;

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i]).expect("valid hex");
            let lo = hex_nibble(bytes[i + 1]).expect("valid hex");
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    /// EIP-155 test vector (reference values computed with Python + pycryptodome + the ecdsa lib)
    /// private_key: 0x4646464646464646464646464646464646464646464646464646464646464646
    /// chain_id: 1, nonce: 9, gas_price: 20 gwei, gas_limit: 21000
    /// destination: 0x3535353535353535353535353535353535353535
    /// amount: 1 ETH
    ///
    /// Expected signing hash: daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53
    /// Expected signed tx: f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83
    #[test]
    fn eip155_signing_hash_test_vector() {
        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };
        let hash = signing_hash(&tx).unwrap();
        let expected_hex = "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
        let expected_bytes = hex_decode(expected_hex);
        assert_eq!(&hash[..], &expected_bytes[..], "signing hash mismatch");
    }

    /// Full sign_eip155 + compare the signed tx
    #[test]
    fn sign_eip155_full_pipeline() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };

        let input = Eip155SignInput { tx, private_key };
        let signed = sign_eip155(&input).unwrap();

        // Verify the signing hash
        let expected_hash = "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
        let expected_hash_bytes = hex_decode(expected_hash);
        assert_eq!(&signed.signing_hash[..], &expected_hash_bytes[..]);

        // Verify v = chain_id * 2 + 35 + y_parity
        // Python ecdsa lib + k256 0.14 both output low-s + y_parity=0 (s < n/2)
        // → v = 1*2 + 35 + 0 = 37
        assert_eq!(signed.v, 37);

        // Verify the full signed tx
        // v = 0x25 (37), r = 0x28ef..., s = 0x67cb...
        let expected_tx = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
        let expected_tx_bytes = hex_decode(expected_tx);
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
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };

        let input = Eip155SignInput {
            tx: tx.clone(),
            private_key,
        };
        let signed1 = sign_eip155(&input).unwrap();
        let signed2 = sign_eip155(&input).unwrap();
        assert_eq!(signed1.tx_bytes, signed2.tx_bytes, "must be deterministic");
    }

    /// Different chain_id → different signing hash
    #[test]
    fn different_chain_id_different_hash() {
        let tx_mainnet = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };
        let mut tx_sepolia = tx_mainnet.clone();
        tx_sepolia.chain_id = 11155111;
        let hash_mainnet = signing_hash(&tx_mainnet).unwrap();
        let hash_sepolia = signing_hash(&tx_sepolia).unwrap();
        assert_ne!(hash_mainnet, hash_sepolia);
    }
}
