//! ETH EIP-4844 blob transaction signing (Phase 5 v8.1, kept in PoC4)
//!
//! ⚠️ **DEPRECATED (v9.0, 2026-08-22)**:
//! - The user decided to drop EIP-4844 from the formal project (used internally by L2 rollups; a user signer will never receive one)
//! - This file is kept in `src/_experimental/` as a protocol-layer reference
//! - Not part of the `chain::eth` compile path
//!
//! Implements: the EIP-4844 signing hash + the sign_eip4844 business function
//!
//! ## KZG boundary (shlosilo is a signer and is only responsible for the signing step)
//!
//! shlosilo does **not** implement KZG commitment / proof generation (no c-kzg/eth-kzg dependency,
//! avoiding +1.5MB~2MB binary + 50MB trusted setup). Callers must provide:
//! - `blob_versioned_hashes: Vec<[u8; 32]>` — 32-byte SHA256 truncated commitment
//!
//! ## Algorithm summary
//!
//! **EIP-4844 signing hash**:
 //! ```
//! keccak256(0x03 || rlp([
//!   chain_id,
//!   nonce,
//!   max_priority_fee_per_gas,
//!   max_fee_per_gas,
//!   gas_limit,
//!   destination,
//!   amount,
//!   data,
//!   access_list,
//!   max_fee_per_blob_gas,         // NEW vs EIP-1559
//!   blob_versioned_hashes,        // NEW: [versioned_hash, ...]
//! ]))
//! ```
//!
//! **EIP-4844 signed transaction format**:
//! ```
//! 0x03 || rlp([
//!   chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
//!   destination, amount, data, access_list,
//!   max_fee_per_blob_gas, blob_versioned_hashes,
//!   y_parity, r, s,
//! ])
//! ```
//!
//! **blob_versioned_hashes RLP encoding**:
//! - Arrays: `rlp([hash1, hash2, ...])` — each hash is 32 bytes
//! - 0 hashes: `rlp([])` = `0xc0`
//! - 1 hash: `rlp([hash])` = `0xc1 0xa0 hash[0..32]`
//!
//! **Not signed** (per EIP-4844):
//! - `blobs` themselves (128KB each, stored on consensus layer)
//! - `commitments` (KZG polynomial commitments)
//! - `proofs` (KZG proofs)

extern crate alloc;
use crate::chain::eth::rlp;
use crate::chain::eth::sign;
use crate::encoding::keccak256;
use crate::error::Result;
use alloc::vec::Vec;

/// 32-byte Ethereum address
pub type Address = [u8; 20];

/// Versioned hash (EIP-4844 32 bytes, version byte = 0x01 prefix)
pub type VersionedHash = [u8; 32];

// --- access_list RLP encoding (shared with EIP-2930) ---------------

/// EIP-2930 access list item
#[derive(Clone, Debug)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<[u8; 32]>,
}

/// RLP encode single access list item
fn encode_access_list_item(item: &AccessListItem) -> Vec<u8> {
    let addr_rlp = rlp::encode_bytes(&item.address);
    let storage_keys_rlp = if item.storage_keys.is_empty() {
        rlp::encode_list(&[])
    } else {
        let keys: Vec<Vec<u8>> = item
            .storage_keys
            .iter()
            .map(|k| rlp::encode_bytes(k))
            .collect();
        rlp::encode_list(&keys)
    };
    rlp::encode_list(&[addr_rlp, storage_keys_rlp])
}

/// RLP encode access list (list of items)
pub fn encode_access_list(items: &[AccessListItem]) -> Vec<u8> {
    if items.is_empty() {
        return rlp::encode_list(&[]);
    }
    let encoded: Vec<Vec<u8>> = items.iter().map(encode_access_list_item).collect();
    rlp::encode_list(&encoded)
}

/// RLP encode list of versioned hashes (32 bytes each)
fn encode_blob_versioned_hashes(hashes: &[VersionedHash]) -> Vec<u8> {
    if hashes.is_empty() {
        return rlp::encode_list(&[]);
    }
    let encoded: Vec<Vec<u8>> = hashes.iter().map(|h| rlp::encode_bytes(h)).collect();
    rlp::encode_list(&encoded)
}

// --- EIP-4844 data structures --------------------------------------

/// EIP-4844 blob transaction (unsigned)
#[derive(Clone, Debug)]
pub struct Eip4844Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// 20-byte destination address (EIP-4844 requires `to`; it cannot be None)
    pub destination: Address,
    pub amount: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
    /// Wei per blob gas
    pub max_fee_per_blob_gas: u128,
    /// blob_versioned_hashes (32 bytes each)
    /// Must be supplied by the caller (KZG commitment → SHA256[0..31] || 0x01)
    pub blob_versioned_hashes: Vec<VersionedHash>,
}

/// Signing input
#[derive(Clone, Debug)]
pub struct Eip4844SignInput {
    pub tx: Eip4844Transaction,
    pub private_key: [u8; 32],
}

/// Signing output
#[derive(Clone, Debug)]
pub struct Eip4844SignedTx {
    /// Full signed transaction bytes (0x03 || rlp([..., y_parity, r, s]))
    pub tx_bytes: Vec<u8>,
    /// signing hash
    pub signing_hash: [u8; 32],
    /// signature r
    pub r: [u8; 32],
    /// signature s
    pub s: [u8; 32],
    /// y_parity: 0 or 1
    pub y_parity: u8,
}

// ─── EIP-4844 signing hash ────────────────────────────────────────

/// Compute the EIP-4844 signing hash
///
/// `keccak256(0x03 || rlp([chain_id, nonce, max_prio, max_fee, gas_limit, dest, amount, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes]))`
pub fn signing_hash(tx: &Eip4844Transaction) -> Result<[u8; 32]> {
    let preimage = signing_preimage(tx);
    keccak256::hash(&preimage)
}

/// Compute the signing preimage bytes
pub fn signing_preimage(tx: &Eip4844Transaction) -> Vec<u8> {
    let chain_id_rlp = rlp::encode_uint(tx.chain_id as u128);
    let nonce_rlp = rlp::encode_uint(tx.nonce as u128);
    let max_prio_rlp = rlp::encode_uint(tx.max_priority_fee_per_gas);
    let max_fee_rlp = rlp::encode_uint(tx.max_fee_per_gas);
    let gas_limit_rlp = rlp::encode_uint(tx.gas_limit as u128);
    let dest_rlp = rlp::encode_bytes(&tx.destination);
    let amount_rlp = rlp::encode_uint(tx.amount);
    let data_rlp = rlp::encode_bytes(&tx.data);
    let access_list_rlp = encode_access_list(&tx.access_list);
    let max_fee_per_blob_gas_rlp = rlp::encode_uint(tx.max_fee_per_blob_gas);
    let blob_versioned_hashes_rlp = encode_blob_versioned_hashes(&tx.blob_versioned_hashes);

    let unsigned_rlp = rlp::encode_list(&[
        chain_id_rlp,
        nonce_rlp,
        max_prio_rlp,
        max_fee_rlp,
        gas_limit_rlp,
        dest_rlp,
        amount_rlp,
        data_rlp,
        access_list_rlp,
        max_fee_per_blob_gas_rlp,
        blob_versioned_hashes_rlp,
    ]);

    let mut preimage = Vec::with_capacity(1 + unsigned_rlp.len());
    preimage.push(0x03);
    preimage.extend_from_slice(&unsigned_rlp);
    preimage
}

// --- sign_eip4844 business function --------------------------------

/// Sign an EIP-4844 blob transaction
///
/// **Note**: KZG commitment/proof generation is the caller's responsibility; shlosilo does not implement c-kzg/eth-kzg
/// (avoiding +1.5MB binary + 50MB trusted setup). The caller must provide blob_versioned_hashes.
pub fn sign_eip4844(input: &Eip4844SignInput) -> Result<Eip4844SignedTx> {
    let sk = sign::sk_from_pk(&input.private_key)?;

    // 1. signing hash
    let sighash = signing_hash(&input.tx)?;

    // 2. ECDSA sign + low-s + y_parity
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let y_parity = sign::apply_low_s(&sighash, &sk, &mut r_bytes, &mut s_bytes)?;

    // 3. Build signed transaction
    let chain_id_rlp = rlp::encode_uint(input.tx.chain_id as u128);
    let nonce_rlp = rlp::encode_uint(input.tx.nonce as u128);
    let max_prio_rlp = rlp::encode_uint(input.tx.max_priority_fee_per_gas);
    let max_fee_rlp = rlp::encode_uint(input.tx.max_fee_per_gas);
    let gas_limit_rlp = rlp::encode_uint(input.tx.gas_limit as u128);
    let dest_rlp = rlp::encode_bytes(&input.tx.destination);
    let amount_rlp = rlp::encode_uint(input.tx.amount);
    let data_rlp = rlp::encode_bytes(&input.tx.data);
    let access_list_rlp = encode_access_list(&input.tx.access_list);
    let max_fee_per_blob_gas_rlp = rlp::encode_uint(input.tx.max_fee_per_blob_gas);
    let blob_versioned_hashes_rlp = encode_blob_versioned_hashes(&input.tx.blob_versioned_hashes);
    let y_parity_rlp = rlp::encode_uint(y_parity as u128);
    let r_rlp = rlp::encode_uint256(&r_bytes);
    let s_rlp = rlp::encode_uint256(&s_bytes);

    let signed_rlp = rlp::encode_list(&[
        chain_id_rlp,
        nonce_rlp,
        max_prio_rlp,
        max_fee_rlp,
        gas_limit_rlp,
        dest_rlp,
        amount_rlp,
        data_rlp,
        access_list_rlp,
        max_fee_per_blob_gas_rlp,
        blob_versioned_hashes_rlp,
        y_parity_rlp,
        r_rlp,
        s_rlp,
    ]);

    let mut tx_bytes = Vec::with_capacity(1 + signed_rlp.len());
    tx_bytes.push(0x03);
    tx_bytes.extend_from_slice(&signed_rlp);

    Ok(Eip4844SignedTx {
        tx_bytes,
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        y_parity,
    })
}

// --- KZG stubs (left for the upper layer) --------------------------

/// Generate a blob commitment (KZG) — **stub**, the upper layer must implement it
///
/// shlosilo does not implement KZG (avoiding +1.5MB binary + 50MB trusted setup).
/// The caller must pull in c-kzg-ethereum or rust-kzg to implement this function.
#[deprecated(note = "KZG not implemented in shlosilo; caller must provide")]
pub fn kzg_commitment_stub(_blob: &[u8]) -> [u8; 48] {
    unimplemented!("KZG commitment not implemented in shlosilo; caller must provide")
}

/// Generate a blob KZG proof — **stub**, the upper layer must implement it
#[deprecated(note = "KZG not implemented in shlosilo; caller must provide")]
pub fn kzg_proof_stub(_blob: &[u8], _commitment: &[u8; 48]) -> [u8; 48] {
    unimplemented!("KZG proof not implemented in shlosilo; caller must provide")
}

// --- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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

    /// EIP-4844 test vector
    /// private_key: 0x4646464646464646464646464646464646464646464646464646464646464646
    /// chain_id: 1, nonce: 0
    /// max_prio: 1 gwei, max_fee: 20 gwei, gas_limit: 21000
    /// destination: 0x3535353535353535353535353535353535353535
    /// amount: 0, data: empty, access_list: empty
    /// max_fee_per_blob_gas: 1
    /// 1 blob, versioned_hash = 0x01 || 31 bytes of zeros
    ///
    /// Expected signing hash: 67c17f93bd8dc979e38a701df2b37002795a7aa8870fd080205e7b3141f6d1ba
    #[test]
    fn eip4844_signing_hash_test_vector() {
        let mut blob_versioned_hashes = Vec::new();
        let mut h = [0u8; 32];
        h[0] = 0x01;
        blob_versioned_hashes.push(h);

        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes,
        };
        let hash = signing_hash(&tx).unwrap();
        let expected_hex = "67c17f93bd8dc979e38a701df2b37002795a7aa8870fd080205e7b3141f6d1ba";
        let expected_bytes = hex_decode(expected_hex);
        assert_eq!(&hash[..], &expected_bytes[..], "signing hash mismatch");
    }

    /// Full sign_eip4844 + signed tx comparison
    #[test]
    fn sign_eip4844_full_pipeline() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);

        let mut blob_versioned_hashes = Vec::new();
        let mut h = [0u8; 32];
        h[0] = 0x01;
        blob_versioned_hashes.push(h);

        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes,
        };

        let input = Eip4844SignInput { tx, private_key };
        let signed = sign_eip4844(&input).unwrap();

        // Verify the signing hash
        let expected_hash =
            "67c17f93bd8dc979e38a701df2b37002795a7aa8870fd080205e7b3141f6d1ba";
        let expected_hash_bytes = hex_decode(expected_hash);
        assert_eq!(&signed.signing_hash[..], &expected_hash_bytes[..]);

        // Verify r
        let expected_r = "9c74ed2f882f74d48611408cfd3b00abe2492044200ad37afafd56e09731dbc3";
        let expected_r_bytes = hex_decode(expected_r);
        assert_eq!(&signed.r[..], &expected_r_bytes[..], "r mismatch");

        // Verify y_parity
        assert_eq!(signed.y_parity, 0);

        // Verify the full signed tx
        let expected_tx = "03f88e0180843b9aca008504a817c8008252089435353535353535353535353535353535353535358080c001e1a0010000000000000000000000000000000000000000000000000000000000000080a09c74ed2f882f74d48611408cfd3b00abe2492044200ad37afafd56e09731dbc3a014c5178194790a8d75f27eda8dc191d93f164511ff0e5df8307204f127d1dd75";
        let expected_tx_bytes = hex_decode(expected_tx);
        assert_eq!(
            &signed.tx_bytes[..],
            &expected_tx_bytes[..],
            "signed tx mismatch"
        );
    }

    /// Multi-blob test
    #[test]
    fn multiple_blobs() {
        let mut blob_versioned_hashes = Vec::new();
        for i in 1..=3 {
            let mut h = [0u8; 32];
            h[0] = 0x01;
            h[31] = i; // distinguish the hashes
            blob_versioned_hashes.push(h);
        }

        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes,
        };
        // Verify the signing hash doesn't panic
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let input = Eip4844SignInput { tx, private_key };
        let signed = sign_eip4844(&input).unwrap();
        // y_parity depends on R.y's parity; 0 or 1 are both normal
        assert!(signed.y_parity == 0 || signed.y_parity == 1);
    }

    /// Determinism
    #[test]
    fn deterministic_signing() {
        let private_key_bytes =
            hex_decode("4646464646464646464646464646464646464646464646464646464646464646");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);

        let mut blob_versioned_hashes = Vec::new();
        let mut h = [0u8; 32];
        h[0] = 0x01;
        blob_versioned_hashes.push(h);

        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes,
        };

        let input = Eip4844SignInput {
            tx: tx.clone(),
            private_key,
        };
        let signed1 = sign_eip4844(&input).unwrap();
        let signed2 = sign_eip4844(&input).unwrap();
        assert_eq!(signed1.tx_bytes, signed2.tx_bytes);
    }

    /// Different max_fee_per_blob_gas → different signing hash
    #[test]
    fn different_blob_fee_different_hash() {
        let mut blob_versioned_hashes = Vec::new();
        let mut h = [0u8; 32];
        h[0] = 0x01;
        blob_versioned_hashes.push(h);

        let make_tx = |max_fee_per_blob_gas: u128| Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas,
            blob_versioned_hashes: blob_versioned_hashes.clone(),
        };

        let hash1 = signing_hash(&make_tx(1)).unwrap();
        let hash2 = signing_hash(&make_tx(2)).unwrap();
        assert_ne!(hash1, hash2);
    }

    /// Empty blob_versioned_hashes (0 blobs)
    #[test]
    fn zero_blob() {
        let tx = Eip4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 21000,
            destination: [0x35u8; 20],
            amount: 0,
            data: Vec::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes: Vec::new(),
        };
        // 0 blobs can still be signed (the struct allows it), but the actual EIP-4844 protocol requires ≥ 1 blob
        // Here we only verify the signing hash doesn't panic
        let _hash = signing_hash(&tx).unwrap();
    }
}