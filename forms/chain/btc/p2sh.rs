//! BTC P2SH-P2WPKH full transaction signing (segwit wrapped, BIP-141 + BIP-143)
//!
//! Implements:
//! - P2SH-P2WPKH sighash algorithm (same as P2WPKH, but scriptCode = redeemScript = a P2PKH-style 25 bytes)
//! - sign_p2sh_p2wpkh business function (sighash → ECDSA → DER + sighash byte → scriptSig + witness assembly)
//! - P2SH + BIP-144 segwit serialization (marker + flag + scriptSig containing the redeemScript push + witness)
//!
//! ## Algorithm summary
//!
//! **P2SH-P2WPKH sighash** is identical to P2WPKH (BIP-143), but:
//! - scriptCode = redeemScript = `0x1976a914{20-byte-pubkey-hash}88ac` (25 bytes)
//! - scriptSig = `varint_push_len_0x23 {0x16 0x0014} redeemScript` (22-byte push)
//! - witness = `[signature, compressed-pubkey]` (2 items, same as P2WPKH)
//!
//! ## Key constraints
//!
//! The P2SH scriptPubKey is `OP_HASH160 <redeemScriptHash> OP_EQUAL`:
//! - `0xa914{20-byte-redeemScriptHash}87` (23 bytes)
//!
//! but signing only needs the redeemScript (the actually executed script), not the redeemScript hash.
//! The caller must provide the redeemScript, not its hash.
//!
//! ## Reference
//!
//! - BIP-141 (Segwit): <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki>
//! - BIP-143 (Segwit sighash): <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
//! - BIP-16 (P2SH): <https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki>

#[cfg(any(feature = "alloc-fallback", test))]
extern crate alloc;
// The whole-transaction signer below builds a serialized transaction in a Vec,
// so it stays on the alloc face; the fixed-size redeem-script helper and the
// PSBT finalization records that the device path needs do not (`sign_psbt_p2sh_p2wpkh`
// in chain/btc/psbt.rs assembles the same bytes into caller/stack buffers).
#[cfg(any(feature = "alloc-fallback", test))]
use alloc::vec;
#[cfg(any(feature = "alloc-fallback", test))]
use alloc::vec::Vec;

#[cfg(any(feature = "alloc-fallback", test))]
use crate::chain::btc::p2pkh::p2pkh_script_code;
#[cfg(test)]
use crate::chain::btc::p2wpkh::bt_vec;
#[cfg(any(feature = "alloc-fallback", test))]
use crate::chain::btc::p2wpkh::{segwit_sighash_p2wpkh, Transaction, SIGHASH_ALL};
#[cfg(any(feature = "alloc-fallback", test))]
use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
#[cfg(any(feature = "alloc-fallback", test))]
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
#[cfg(any(feature = "alloc-fallback", test))]
use crate::signature::ecdsa_secp256k1::{self as ecdsa};
use crate::types::SecretBytes;

/// P2SH scriptPubKey: `OP_HASH160 <20-byte-hash> OP_EQUAL`
///
/// `0xa914{20-byte-hash}87`
#[cfg(any(feature = "alloc-fallback", test))]
pub fn p2sh_script_pubkey(redeem_script_hash: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(23);
    out.push(0xa9); // OP_HASH160
    out.push(0x14); // push 20 bytes
    out.extend_from_slice(redeem_script_hash);
    out.push(0x87); // OP_EQUAL
    out
}

/// P2SH-P2WPKH scriptSig: `varint_22 0x16 0x0014 {redeemScript}`
///
/// Actual push: `push 22 bytes, where the first 2 bytes are 0x160014 (P2PKH-style prefix) and the last 20 bytes are the pubkey_hash`
///
/// redeemScript full 22 bytes: `0x16 0x00 0x14 {20-byte-pubkey-hash}`
/// Note: 0x16 = OP_PUSH_22, 0x00 = OP_PUSHDATA1... wait, actually it is:
///
/// **The actual redeemScript = P2WPKH witness program = `0x0014{20-byte-pubkey-hash}` (22 bytes)**
///
/// The whole scriptSig:
///
/// ```text
/// <0x16> = push 22 bytes (redeemScript length)
/// <22 bytes> = 0x00 0x14 {20-byte-pubkey-hash}
/// ```
#[cfg(any(feature = "alloc-fallback", test))]
pub fn p2sh_p2wpkh_script_sig(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 22);
    out.push(0x16); // push 22 bytes
    out.push(0x00); // OP_0
    out.push(0x14); // push 20 bytes
    out.extend_from_slice(pubkey_hash);
    out
}

/// P2SH-P2WPKH redeemScript (22 bytes)
///
/// `0x0014{20-byte-pubkey-hash}` — fixed size, so it needs no heap and stays on
/// the device face.
pub fn p2wpkh_redeem_script(pubkey_hash: &[u8; 20]) -> [u8; 22] {
    p2sh_p2wpkh_redeem_script(pubkey_hash)
}

/// Historical name of [`p2wpkh_redeem_script`] (kept for existing callers).
pub fn p2sh_p2wpkh_redeem_script(pubkey_hash: &[u8; 20]) -> [u8; 22] {
    let mut out = [0u8; 22];
    out[0] = 0x00; // OP_0 (P2WPKH marker)
    out[1] = 0x14; // push 20 bytes
    out[2..22].copy_from_slice(pubkey_hash);
    out
}

/// P2SH-P2WPKH signing input (per-input info)
///
/// P1-03: the private key uses `SecretBytes<32>` — no Clone or Debug, ZeroizeOnDrop, constant-time comparison.
pub struct P2SHP2WPKHSignInput<'k> {
    /// The input index being signed
    pub input_index: usize,
    /// The private key for this input (32 bytes) — borrowed, zero-copy forwarding
    pub private_key: &'k SecretBytes<32>,
    /// pubkey hash (20 bytes) — the pubkey hash inside the P2WPKH witness program
    pub pubkey_hash: [u8; 20],
    /// The value of this input (satoshis) — used for the BIP-143 sighash
    pub amount: u64,
}

/// P2SH-P2WPKH signing output
#[cfg(any(feature = "alloc-fallback", test))]
#[derive(Clone, Debug)]
pub struct P2SHP2WPKHSignedTx {
    /// Full BIP-144 segwit serialized transaction (marker + flag + witness)
    pub tx_bytes: Vec<u8>,
    /// The sighash of this input
    pub sighash: [u8; 32],
}

#[cfg(any(feature = "alloc-fallback", test))]
/// Sign a P2SH-P2WPKH input
///
/// **Side effects**:
/// - Modifies `tx.inputs[input_index].script_sig` (injects the redeemScript push)
/// - Modifies `tx.inputs[input_index].witness` (injects signature + pubkey)
pub fn sign_p2sh_p2wpkh(
    tx: &mut Transaction,
    input: &P2SHP2WPKHSignInput<'_>,
) -> Result<P2SHP2WPKHSignedTx> {
    if input.input_index >= tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // 1. sighash: P2SH-P2WPKH uses a P2PKH-style scriptCode (redeemScript)
    let redeem_script = p2pkh_script_code(&input.pubkey_hash);
    let sighash = segwit_sighash_p2wpkh(
        tx,
        input.input_index,
        &redeem_script,
        input.amount,
        SIGHASH_ALL,
    )?;

    // 2. ECDSA signature
    let sig_scalar = scalar_from_bytes(input.private_key.expose())?;
    let pk_point = base_mul(&sig_scalar);
    let pk_compressed = point_to_compressed(&pk_point);

    let signature = ecdsa::sign(&sig_scalar, &sighash)?;
    let mut sig_with_sighash = Vec::new();
    let der_sig = ecdsa::to_der(&signature)?;
    sig_with_sighash.extend_from_slice(&der_sig);
    sig_with_sighash.push(SIGHASH_ALL as u8);

    // 3. scriptSig = push(22) {0x00 0x14 pubkey_hash}
    let script_sig = p2sh_p2wpkh_script_sig(&input.pubkey_hash);

    // 4. witness = [signature, compressed-pubkey]
    let witness = vec![sig_with_sighash, pk_compressed.to_vec()];

    // 5. Injection
    tx.inputs[input.input_index].script_sig = script_sig.into();
    tx.inputs[input.input_index].witness = witness;

    // 6. BIP-144 segwit serialization (via p2wpkh::Transaction::serialize_segwit)
    let tx_bytes = tx.serialize_segwit();

    Ok(P2SHP2WPKHSignedTx { tx_bytes, sighash })
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

    /// P2SH scriptPubKey construction
    #[test]
    fn p2sh_script_pubkey_format() {
        let hash = [0xab; 20];
        let pk = p2sh_script_pubkey(&hash);
        assert_eq!(pk.len(), 23);
        assert_eq!(pk[0], 0xa9); // OP_HASH160
        assert_eq!(pk[1], 0x14); // push 20
        assert_eq!(&pk[2..22], &hash);
        assert_eq!(pk[22], 0x87); // OP_EQUAL
    }

    /// P2SH-P2WPKH redeemScript construction
    #[test]
    fn p2sh_p2wpkh_redeem_script_format() {
        let pk_hash = [0x42; 20];
        let rs = p2sh_p2wpkh_redeem_script(&pk_hash);
        assert_eq!(rs.len(), 22);
        assert_eq!(rs[0], 0x00);
        assert_eq!(rs[1], 0x14);
        assert_eq!(&rs[2..], &pk_hash);
    }

    /// The P2SH-P2WPKH scriptSig is push(22) {0x00 0x14 hash}
    #[test]
    fn p2sh_p2wpkh_script_sig_format() {
        let pk_hash = [0x42; 20];
        let sig = p2sh_p2wpkh_script_sig(&pk_hash);
        assert_eq!(sig.len(), 23);
        assert_eq!(sig[0], 0x16); // push 22 bytes
        assert_eq!(sig[1], 0x00);
        assert_eq!(sig[2], 0x14);
        assert_eq!(&sig[3..], &pk_hash);
    }

    /// End-to-end: P2SH-P2WPKH signing
    #[test]
    fn p2sh_p2wpkh_end_to_end() {
        let mut txid = [0u8; 32];
        txid[0] = 0xab;
        let txin = TxIn {
            prev_out: OutPoint { txid, vout: 0 },
            script_sig: vec![].into(),
            sequence: 0xffffffff,
            witness: vec![],
        };
        let txout = TxOut {
            value: 200_000,
            script_pubkey: p2sh_script_pubkey(&[0x33; 20]).into(), // simulates a P2SH output
        };
        let mut tx = Transaction {
            version: 1,
            inputs: bt_vec![txin],
            outputs: bt_vec![txout],
            lock_time: 0,
        };

        let private_key_bytes =
            hex_decode("0101010101010101010101010101010101010101010101010101010101010101");
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);
        let private_key = SecretBytes::take(&mut private_key);

        let input = P2SHP2WPKHSignInput {
            input_index: 0,
            private_key: &private_key,
            pubkey_hash: [0x42; 20],
            amount: 300_000,
        };

        let signed = sign_p2sh_p2wpkh(&mut tx, &input).unwrap();

        // 1. sighash is non-zero
        assert_ne!(signed.sighash, [0u8; 32]);

        // 2. scriptSig injected (23 bytes: 0x16 + 0x00 + 0x14 + 20-byte hash)
        let script_sig = &tx.inputs[0].script_sig;
        assert_eq!(script_sig.len(), 23);
        assert_eq!(script_sig[0], 0x16);

        // 3. witness injected (2 items)
        let witness = &tx.inputs[0].witness;
        assert_eq!(witness.len(), 2);

        // 4. Item 1 = signature + sighash byte (last byte = 0x01)
        let sig_witness = &witness[0];
        assert!(sig_witness.len() >= 9);
        assert_eq!(sig_witness[sig_witness.len() - 1], 0x01);

        // 5. Item 2 = compressed pubkey (33 bytes)
        let pk_witness = &witness[1];
        assert_eq!(pk_witness.len(), 33);
        assert!(pk_witness[0] == 0x02 || pk_witness[0] == 0x03);

        // 6. tx_bytes is BIP-144 segwit format (marker 0x00, flag 0x01)
        assert_eq!(signed.tx_bytes[4], 0x00);
        assert_eq!(signed.tx_bytes[5], 0x01);

        eprintln!(
            "P2SH-P2WPKH signed tx ({} bytes): {}",
            signed.tx_bytes.len(),
            hex_encode(&signed.tx_bytes)
        );
    }

    /// Input index out of bounds
    #[test]
    fn p2sh_p2wpkh_out_of_bounds() {
        let tx = Transaction {
            version: 1,
            inputs: bt_vec![],
            outputs: bt_vec![],
            lock_time: 0,
        };
        let secret = SecretBytes::new([1u8; 32]);
        let input = P2SHP2WPKHSignInput {
            input_index: 0,
            private_key: &secret,
            pubkey_hash: [0u8; 20],
            amount: 0,
        };
        let mut tx = tx;
        assert!(sign_p2sh_p2wpkh(&mut tx, &input).is_err());
    }

    /// F-20 (external audit 2026-11-19): this test used to call `segwit_sighash_p2wpkh` twice with
    /// identical arguments and assert the two results were equal — a tautology that would pass
    /// even if the nested signer passed the wrong scriptCode. It now checks the **BIP-143
    /// P2SH-P2WPKH example** (the BIP's own vector) through the same sighash path the nested
    /// signer uses.
    ///
    /// BIP-143 vector:
    ///   tx           0100000001db6b1b20…54770100000000feffffff02b8b4eb0b…92040000
    ///   spent value  10 BTC (0x00ca9a3b00000000)
    ///   redeemScript 001479091972186c449eb1ded22b78e40d009bdf0089
    ///   scriptCode   1976a91479091972186c449eb1ded22b78e40d009bdf008988ac
    ///   sighash      64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6
    #[test]
    fn p2sh_p2wpkh_sighash_matches_the_bip143_vector() {
        use crate::chain::btc::p2wpkh::{segwit_sighash_p2wpkh, SIGHASH_ALL};

        // hash160 of the key, i.e. the P2PKH scriptCode BIP-143 prescribes for P2SH-P2WPKH.
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&hex_decode("79091972186c449eb1ded22b78e40d009bdf0089"));
        let script_code = p2pkh_script_code(&pubkey_hash);

        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(&hex_decode(
            "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477",
        ));
        let tx = Transaction {
            version: 1,
            inputs: bt_vec![TxIn {
                prev_out: OutPoint {
                    txid: prev_txid,
                    vout: 1,
                },
                script_sig: Vec::new().into(),
                // wire bytes `feffffff` are LE → the sequence VALUE is 0xffff_fffe
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            outputs: bt_vec![
                TxOut {
                    // b8b4eb0b00000000 LE = 199,996,600 (verified against the BIP's own preimage)
                    value: 199_996_600,
                    script_pubkey:
                        hex_decode("76a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac",).into(),
                },
                TxOut {
                    value: 0x2faf_0800,
                    script_pubkey:
                        hex_decode("76a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac",).into(),
                },
            ],
            lock_time: 0x0492,
        };

        let digest =
            segwit_sighash_p2wpkh(&tx, 0, &script_code, 1_000_000_000, SIGHASH_ALL).unwrap();
        assert_eq!(
            hex_encode(&digest),
            "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
            "nested signer's digest must equal the BIP-143 P2SH-P2WPKH vector"
        );

        // ... and the scriptCode choice is load-bearing: feeding the redeem script instead of the
        // P2PKH scriptCode gives a different digest (the old test could not tell the difference).
        let wrong = segwit_sighash_p2wpkh(
            &tx,
            0,
            &p2wpkh_redeem_script(&pubkey_hash),
            1_000_000_000,
            SIGHASH_ALL,
        )
        .unwrap();
        assert_ne!(
            wrong, digest,
            "scriptCode must be the P2PKH script, not the redeemScript"
        );
    }
}
