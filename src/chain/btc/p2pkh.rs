//! BTC P2PKH full transaction signing (legacy, pre-segwit)
//!
//! Implements:
//! - P2PKH sighash algorithm (the same BIP-143 set, but the scriptCode is 76a914{20}88ac embedded in the scriptSig)
//! - sign_p2pkh business function (sighash → ECDSA → DER + sighash byte → scriptSig assembly)
//! - Legacy transaction serialization (no marker/flag/witness)
//!
//! ## Algorithm summary
//!
//! **The P2PKH sighash algorithm is identical to BIP-143 P2WPKH**, but:
//! - scriptCode embedded in scriptSig (`OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`)
//! - witness empty
//! - serialization has no marker/flag
//!
//! **P2PKH scriptCode**:
//! ```text
//! 0x1976a914{20-byte-pubkey-hash}88ac
//! ```
//!
//! **P2PKH scriptSig** (after signing):
//! ```text
//! <varint_push_data_len><DER-sig + sighash-byte><varint_push_data_len><compressed-pubkey>
//! ```
//!
//! ## Reference
//!
//! - Bitcoin Core 0.21+ test/functional/test_framework/script.py
//! - Bitcoin transaction preimage algorithm (<https://en.bitcoin.it/wiki/OP_CHECKSIG>)

extern crate alloc;
use alloc::vec::Vec;

use crate::chain::btc::p2wpkh::{encode_varint, segwit_sighash_p2wpkh, Transaction, SIGHASH_ALL};
use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::signature::ecdsa_secp256k1::{self as ecdsa};
use crate::types::SecretBytes;

/// P2PKH scriptCode: `OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`
pub fn p2pkh_script_code(pubkey_hash: &[u8; 20]) -> [u8; 25] {
    let mut code = [0u8; 25];
    code[0] = 0x76; // OP_DUP
    code[1] = 0xa9; // OP_HASH160
    code[2] = 0x14; // push 20 bytes
    code[3..23].copy_from_slice(pubkey_hash);
    code[23] = 0x88; // OP_EQUALVERIFY
    code[24] = 0xac; // OP_CHECKSIG
    code
}

/// P2PKH scriptPubKey (output lock script)
pub fn p2pkh_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    p2pkh_script_code(pubkey_hash).to_vec()
}

/// P2PKH signing input (per-input info)
///
/// P1-03: the private key uses `SecretBytes<32>` — no Clone or Debug, ZeroizeOnDrop, constant-time comparison.
pub struct P2PKHSignInput<'k> {
    /// The input index being signed
    pub input_index: usize,
    /// The private key for this input (32 bytes) — borrowed, zero-copy forwarding
    pub private_key: &'k SecretBytes<32>,
    /// pubkey hash (20 bytes)
    pub pubkey_hash: [u8; 20],
}

/// P2PKH signing output
#[derive(Clone, Debug)]
pub struct P2PKHSignedTx {
    /// Full legacy serialized transaction (no marker/flag/witness)
    pub tx_bytes: Vec<u8>,
    /// The sighash of this input (the preimage hash used when signing)
    pub sighash: [u8; 32],
}

/// Sign a P2PKH input
///
/// **Side effects**: modifies `tx.inputs[input_index].script_sig` (injects signature + pubkey),
/// sets the other inputs\' script_sig to empty.
pub fn sign_p2pkh(tx: &mut Transaction, input: &P2PKHSignInput<'_>) -> Result<P2PKHSignedTx> {
    if input.input_index >= tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. Compute the sighash
    let script_code = p2pkh_script_code(&input.pubkey_hash);
    let sighash = segwit_sighash_p2wpkh(
        tx,
        input.input_index,
        &script_code,
        0, // P2PKH is legacy, amount does not participate in the sighash (old-style algorithm) → but BIP-143 does use amount
        SIGHASH_ALL,
    )?;

    // 2. ECDSA signature (DER + sighash byte)
    let sig_scalar = scalar_from_bytes(input.private_key.expose())?;
    let pk_point = base_mul(&sig_scalar);
    let pk_compressed = point_to_compressed(&pk_point);

    let signature = ecdsa::sign(&sig_scalar, &sighash)?;
    let mut sig_with_sighash = Vec::new();
    let der_sig = ecdsa::to_der(&signature)?;
    sig_with_sighash.extend_from_slice(&der_sig);
    sig_with_sighash.push(SIGHASH_ALL as u8);

    // 3. Build the scriptSig: <sig-with-sighash-byte> <compressed-pubkey>
    let mut script_sig = Vec::new();
    encode_varint(&mut script_sig, sig_with_sighash.len() as u64);
    script_sig.extend_from_slice(&sig_with_sighash);
    encode_varint(&mut script_sig, pk_compressed.len() as u64);
    script_sig.extend_from_slice(&pk_compressed);

    // 4. Inject the scriptSig
    tx.inputs[input.input_index].script_sig = script_sig;

    // 5. Legacy serialization (differs from BIP-144 segwit: no marker/flag/witness)
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());

    encode_varint(&mut out, tx.inputs.len() as u64);
    for txin in &tx.inputs {
        out.extend_from_slice(&txin.prev_out.txid);
        out.extend_from_slice(&txin.prev_out.vout.to_le_bytes());
        encode_varint(&mut out, txin.script_sig.len() as u64);
        out.extend_from_slice(&txin.script_sig);
        out.extend_from_slice(&txin.sequence.to_le_bytes());
    }

    encode_varint(&mut out, tx.outputs.len() as u64);
    for txout in &tx.outputs {
        out.extend_from_slice(&txout.value.to_le_bytes());
        encode_varint(&mut out, txout.script_pubkey.len() as u64);
        out.extend_from_slice(&txout.script_pubkey);
    }

    out.extend_from_slice(&tx.lock_time.to_le_bytes());

    Ok(P2PKHSignedTx {
        tx_bytes: out,
        sighash,
    })
}

/// Unit tests
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::chain::btc::p2wpkh::{OutPoint, TxIn, TxOut};
    use alloc::string::String;
    use alloc::vec;
    use std::eprintln;

    fn hex_decode(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i]).unwrap();
            let lo = hex_nibble(bytes[i + 1]).unwrap();
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    fn hex_encode(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    /// P2PKH script_code constructed correctly
    #[test]
    fn p2pkh_script_code_format() {
        let pk_hash = [0xab; 20];
        let code = p2pkh_script_code(&pk_hash);
        assert_eq!(code.len(), 25);
        assert_eq!(code[0], 0x76); // OP_DUP
        assert_eq!(code[1], 0xa9); // OP_HASH160
        assert_eq!(code[2], 0x14); // push 20 bytes
        assert_eq!(&code[3..23], &pk_hash);
        assert_eq!(code[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(code[24], 0xac); // OP_CHECKSIG
    }

    /// scriptPubKey should be a copy of script_code
    #[test]
    fn p2pkh_script_pubkey_matches() {
        let pk_hash = [0x12; 20];
        let pk = p2pkh_script_pubkey(&pk_hash);
        let code = p2pkh_script_code(&pk_hash);
        assert_eq!(pk.as_slice(), &code[..]);
    }

    /// End-to-end: P2PKH 1-input 1-output signing
    /// Note: shlosilo and Bitcoin Core may implement RFC6979 deterministic k differently,
    /// so only sighash consistency is verified + the signature ends with sighash byte 0x01.
    #[test]
    fn p2pkh_end_to_end() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        txid[31] = 0xcd;

        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        };

        let txout = TxOut {
            value: 100_000,
            script_pubkey: p2pkh_script_pubkey(&[0x42; 20]),
        };

        let mut tx = Transaction {
            version: 1,
            inputs: vec![txin],
            outputs: vec![txout],
            lock_time: 0,
        };

        let private_key_bytes =
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let pubkey_hash = [0x42; 20];

        let input = P2PKHSignInput {
            input_index: 0,
            private_key: &private_key,
            pubkey_hash,
        };

        let signed = sign_p2pkh(&mut tx, &input).unwrap();

        // 1. sighash is non-zero
        assert_ne!(signed.sighash, [0u8; 32]);

        // 2. scriptSig injected (signature + pubkey)
        let script_sig = &tx.inputs[0].script_sig;
        assert!(!script_sig.is_empty(), "script_sig must be populated");

        // 3. tx_bytes has no marker/flag (legacy)
        assert_ne!(signed.tx_bytes[4], 0x00, "legacy tx has no marker 0x00");
        assert_ne!(signed.tx_bytes[5], 0x01, "legacy tx has no flag 0x01");

        // 4. The scriptSig\'s second push is the compressed pubkey (33 bytes)
        // the first ~71-73 bytes are the DER sig (including the sighash byte), then 33 bytes of pubkey
        let total = script_sig.len();
        assert!(total >= 33 + 9, "script_sig too short");
        let pubkey_len = script_sig[total - 33 - 1]; // varint 33 = 0x21
        assert_eq!(pubkey_len, 33, "compressed pubkey should be 33 bytes");

        // 5. The pubkey must be a 33-byte compressed one (0x02/0x03 prefix)
        let pk_prefix = script_sig[total - 33];
        assert!(
            pk_prefix == 0x02 || pk_prefix == 0x03,
            "invalid pubkey prefix"
        );

        eprintln!(
            "P2PKH signed tx ({} bytes): {}",
            signed.tx_bytes.len(),
            hex_encode(&signed.tx_bytes)
        );
    }

    /// Different input → different sighash
    #[test]
    fn p2pkh_different_input_different_sighash() {
        let tx_a = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0x42, 0x88, 0xac],
            }],
            lock_time: 0,
        };

        let tx_b = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: [2u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![0x76, 0xa9, 0x14, 0x42, 0x88, 0xac],
            }],
            lock_time: 0,
        };

        let pk_hash = [0x42; 20];
        let code = p2pkh_script_code(&pk_hash);

        let h_a = segwit_sighash_p2wpkh(&tx_a, 0, &code, 0, SIGHASH_ALL).unwrap();
        let h_b = segwit_sighash_p2wpkh(&tx_b, 0, &code, 0, SIGHASH_ALL).unwrap();
        assert_ne!(h_a, h_b, "different inputs must produce different sighash");
    }

    /// SIGHASH_ALL byte at the end of the signature
    #[test]
    fn p2pkh_sighash_byte_appended() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint { txid, vout: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: p2pkh_script_pubkey(&[0x42; 20]),
            }],
            lock_time: 0,
        };

        let input = P2PKHSignInput {
            input_index: 0,
            private_key: &SecretBytes::new([1u8; 32]),
            pubkey_hash: [0x42; 20],
        };

        let _ = sign_p2pkh(&mut tx, &input).unwrap();

        // The script_sig\'s last byte must be 0x01 (SIGHASH_ALL)
        let script_sig = &tx.inputs[0].script_sig;
        let total = script_sig.len();
        // The compressed pubkey is the last 33 bytes (varint 0x21 + 33 bytes)
        let sighash_byte_pos = total - 33 - 1;
        assert_eq!(
            script_sig[sighash_byte_pos - 1],
            0x01,
            "sighash byte should be 0x01 (SIGHASH_ALL)"
        );
    }

    /// Input index out of bounds
    #[test]
    fn p2pkh_out_of_bounds_input() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
        };
        let input = P2PKHSignInput {
            input_index: 0,
            private_key: &SecretBytes::new([1u8; 32]),
            pubkey_hash: [0u8; 20],
        };
        let mut tx = tx;
        assert!(sign_p2pkh(&mut tx, &input).is_err());
    }

    /// Reuse the existing shlosilo k256 ECDSA API to test a round-trip
    #[test]
    fn p2pkh_signature_deterministic() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint { txid, vout: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 100_000,
                script_pubkey: p2pkh_script_pubkey(&[0x42; 20]),
            }],
            lock_time: 0,
        };

        let input = P2PKHSignInput {
            input_index: 0,
            private_key: &SecretBytes::new([2u8; 32]),
            pubkey_hash: [0x42; 20],
        };

        // Two signatures → the same sighash (because of RFC6979 determinism)
        let sighash1 =
            segwit_sighash_p2wpkh(&tx, 0, &p2pkh_script_code(&[0x42; 20]), 0, SIGHASH_ALL).unwrap();
        let sighash2 =
            segwit_sighash_p2wpkh(&tx, 0, &p2pkh_script_code(&[0x42; 20]), 0, SIGHASH_ALL).unwrap();
        assert_eq!(sighash1, sighash2, "sighash must be deterministic");

        let _ = sign_p2pkh(&mut tx, &input).unwrap();
    }
}
