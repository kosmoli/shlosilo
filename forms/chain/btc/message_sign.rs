//! BTC message signing: BIP-137 (legacy compact) + BIP-322 (simple P2WPKH)
//!
//! Phase 5 v9.16
//!
//! BIP-137: `SHA256d("\x18Bitcoin Signed Message:\n" || compact_size(len) || msg)`
//! then recoverable ECDSA, 65 bytes `[header || r || s]`.
//! header = 27 + rec_id + {0 uncompressed | 4 compressed | 8 P2SH-P2WPKH | 12 P2WPKH}
//!
//! BIP-322 simple P2WPKH / P2TR: tagged hash `BIP0322-signed-message`, virtual to_spend/to_sign.
//! P2WPKH uses BIP-143; P2TR keypath uses BIP-341 + BIP-86 tweak.
//! Returns the consensus-encoded witness stack (the caller adds the `smp` prefix).

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::chain::btc::p2wpkh::{
    encode_varint, segwit_sighash_p2wpkh, OutPoint, Transaction, TxIn, TxOut, SIGHASH_ALL,
};
use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, Secp256k1Scalar};
use crate::encoding::{ripemd160, sha256};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::signature::ecdsa_secp256k1::{self as ecdsa};

const BIP137_MAGIC: &[u8] = b"Bitcoin Signed Message:\n";
const BIP322_TAG: &[u8] = b"BIP0322-signed-message";

/// BIP-137 address type → header constant (plus rec_id 0..=3)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bip137AddrKind {
    P2pkhUncompressed, // 27
    P2pkhCompressed,   // 31
    P2shP2wpkh,        // 35
    P2wpkh,            // 39
}

impl Bip137AddrKind {
    fn header_base(self) -> u8 {
        match self {
            Self::P2pkhUncompressed => 27,
            Self::P2pkhCompressed => 31,
            Self::P2shP2wpkh => 35,
            Self::P2wpkh => 39,
        }
    }
}

fn compact_size_push(buf: &mut Vec<u8>, n: u64) {
    encode_varint(buf, n);
}

/// BIP-137 message hash
pub fn bip137_message_hash(msg: &[u8]) -> Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(1 + BIP137_MAGIC.len() + 9 + msg.len());
    compact_size_push(&mut buf, BIP137_MAGIC.len() as u64);
    buf.extend_from_slice(BIP137_MAGIC);
    compact_size_push(&mut buf, msg.len() as u64);
    buf.extend_from_slice(msg);
    sha256::hash_twice(&buf)
}

fn y_parity(sk: &Secp256k1Scalar, sighash: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> Result<u8> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let mut sig_64 = [0u8; 64];
    sig_64[..32].copy_from_slice(r);
    sig_64[32..].copy_from_slice(s);
    let sig = Signature::from_slice(&sig_64)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let pk_compressed = point_to_compressed(&base_mul(sk));

    for y_odd in [false, true] {
        let recid = RecoveryId::new(y_odd, false);
        if let Ok(recovered) = VerifyingKey::recover_from_prehash(sighash, &sig, recid) {
            let sec1 = recovered.to_sec1_point(true);
            if sec1.as_bytes() == &pk_compressed[..] {
                return Ok(u8::from(y_odd));
            }
        }
    }
    Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// BIP-137 signature: 65 bytes header||r||s. The sk is already derived.
pub fn sign_bip137(sk: &Secp256k1Scalar, msg: &[u8], kind: Bip137AddrKind) -> Result<[u8; 65]> {
    let hash = bip137_message_hash(msg)?;
    let sig = ecdsa::sign(sk, &hash)?;
    let bytes = sig.as_ref();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    let rec_id = y_parity(sk, &hash, &r, &s)?;
    let mut out = [0u8; 65];
    out[0] = kind.header_base() + rec_id;
    out[1..33].copy_from_slice(&r);
    out[33..65].copy_from_slice(&s);
    Ok(out)
}

fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::hash(tag).unwrap_or([0u8; 32]);
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(&tag_hash);
    buf.extend_from_slice(&tag_hash);
    buf.extend_from_slice(msg);
    sha256::hash(&buf).unwrap_or([0u8; 32])
}

/// BIP-322 tagged hash: tag = BIP0322-signed-message
pub fn bip322_message_hash(msg: &[u8]) -> [u8; 32] {
    tagged_hash(BIP322_TAG, msg)
}

fn hash160(data: &[u8]) -> Result<[u8; 20]> {
    let h = sha256::hash(data)?;
    ripemd160::hash(&h)
}

fn dsha256(data: &[u8]) -> Result<[u8; 32]> {
    sha256::hash_twice(data)
}

fn serialize_legacy_tx(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    encode_varint(&mut out, tx.inputs.len() as u64);
    for txin in &tx.inputs {
        out.extend_from_slice(&txin.serialize_legacy());
    }
    encode_varint(&mut out, tx.outputs.len() as u64);
    for txout in &tx.outputs {
        out.extend_from_slice(&txout.serialize());
    }
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    out
}

fn encode_witness_stack(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_varint(&mut out, items.len() as u64);
    for item in items {
        encode_varint(&mut out, item.len() as u64);
        out.extend_from_slice(item);
    }
    out
}

/// BIP-322 simple P2WPKH: consensus-encoded witness stack (smp prefix not included)
pub fn sign_bip322_simple_p2wpkh(sk: &Secp256k1Scalar, msg: &[u8]) -> Result<Vec<u8>> {
    let pk = point_to_compressed(&base_mul(sk));
    let pkh = hash160(&pk)?;
    let mut challenge = Vec::with_capacity(22);
    challenge.push(0x00);
    challenge.push(0x14);
    challenge.extend_from_slice(&pkh);

    let message_hash = bip322_message_hash(msg);
    let mut script_sig = Vec::with_capacity(34);
    script_sig.push(0x00); // OP_0
    script_sig.push(0x20); // PUSH32
    script_sig.extend_from_slice(&message_hash);

    let to_spend = Transaction {
        version: 0,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: [0u8; 32],
                vout: 0xffff_ffff,
            },
            script_sig,
            sequence: 0,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 0,
            script_pubkey: challenge,
        }],
        lock_time: 0,
    };
    let to_spend_txid = dsha256(&serialize_legacy_tx(&to_spend))?;

    let to_sign = Transaction {
        version: 0,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: to_spend_txid,
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 0,
            script_pubkey: vec![0x6a], // OP_RETURN
        }],
        lock_time: 0,
    };

    let mut script_code = Vec::with_capacity(25);
    script_code.push(0x76);
    script_code.push(0xa9);
    script_code.push(0x14);
    script_code.extend_from_slice(&pkh);
    script_code.push(0x88);
    script_code.push(0xac);

    let sighash = segwit_sighash_p2wpkh(&to_sign, 0, &script_code, 0, SIGHASH_ALL)?;
    let sig = ecdsa::sign(sk, &sighash)?;
    let der = ecdsa::to_der(&sig)?;
    let mut sig_with_ht = Vec::with_capacity(der.len() + 1);
    sig_with_ht.extend_from_slice(der.as_slice());
    sig_with_ht.push(SIGHASH_ALL as u8);

    Ok(encode_witness_stack(&[sig_with_ht, pk.to_vec()]))
}

/// BIP-322 simple P2TR keypath: consensus-encoded witness stack (smp prefix not included)
///
/// `internal_sk` is the untweaked private key; Schnorr after tweaking per BIP-86 (merkle_root = None).
fn bip322_p2tr_sighash(internal_sk: &[u8; 32], msg: &[u8]) -> Result<[u8; 32]> {
    use crate::chain::btc::taproot::{
        bip341_keypath_sighash, compute_output_key, SpentOutput, TaprootSighashInput,
        SIGHASH_DEFAULT,
    };
    use crate::curve_primitive::secp256k1::scalar_from_bytes;

    let sk = scalar_from_bytes(internal_sk)?;
    let pk = point_to_compressed(&base_mul(&sk));
    let mut internal_x = [0u8; 32];
    internal_x.copy_from_slice(&pk[1..]);
    let output = compute_output_key(&internal_x)?;
    let out_c = point_to_compressed(&output);
    let mut output_x = [0u8; 32];
    output_x.copy_from_slice(&out_c[1..]);

    let mut challenge = Vec::with_capacity(34);
    challenge.push(0x51);
    challenge.push(0x20);
    challenge.extend_from_slice(&output_x);

    let message_hash = bip322_message_hash(msg);
    let mut script_sig = Vec::with_capacity(34);
    script_sig.push(0x00);
    script_sig.push(0x20);
    script_sig.extend_from_slice(&message_hash);

    let to_spend = Transaction {
        version: 0,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: [0u8; 32],
                vout: 0xffff_ffff,
            },
            script_sig,
            sequence: 0,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value: 0,
            script_pubkey: challenge.clone(),
        }],
        lock_time: 0,
    };
    let to_spend_txid = dsha256(&serialize_legacy_tx(&to_spend))?;

    let spent = SpentOutput {
        value: 0,
        script_pubkey: challenge,
    };
    let tx_out = SpentOutput {
        value: 0,
        script_pubkey: vec![0x6a],
    };
    let prevouts = [(to_spend_txid, 0u32)];
    let sequences = [0u32];
    let spent_outputs = [spent];
    let tx_outputs = [tx_out];
    bip341_keypath_sighash(&TaprootSighashInput {
        tx_version: 0,
        locktime: 0,
        prevouts: &prevouts,
        sequences: &sequences,
        spent_outputs: &spent_outputs,
        tx_outputs: &tx_outputs,
        input_index: 0,
        hash_type: SIGHASH_DEFAULT,
        annex_present: false,
        tapleaf_hash: None,
    })
}

/// BIP-322 simple P2TR keypath: consensus-encoded witness stack (smp prefix not included)
///
/// `internal_sk` is the untweaked private key; Schnorr after tweaking per BIP-86 (merkle_root = None).
pub fn sign_bip322_simple_p2tr(internal_sk: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>> {
    use crate::chain::btc::taproot::{sign_p2tr_keypath, P2TRKeypathSignInput, SIGHASH_DEFAULT};

    let sighash = bip322_p2tr_sighash(internal_sk, msg)?;
    let sig = sign_p2tr_keypath(
        &P2TRKeypathSignInput {
            internal_sk: *internal_sk,
            merkle_root: None,
        },
        &sighash,
        &[0u8; 32],
        SIGHASH_DEFAULT,
    )?;
    Ok(encode_witness_stack(&[sig]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_primitive::secp256k1::scalar_from_bytes;
    use crate::derivation::bip32_secp256k1::derive_from_seed;
    use crate::derivation::path::DerivationPath;
    use crate::encoding::base64;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn verify_p2tr_witness(internal_sk: &[u8; 32], msg: &[u8], wit: &[u8]) -> bool {
        use crate::chain::btc::taproot::{compute_output_key, lift_x_pubkey};
        use crate::signature::schnorr_secp256k1;
        if wit.len() != 66 || wit[0] != 1 || wit[1] != 64 {
            return false;
        }
        let sig = schnorr_secp256k1::from_bytes(&wit[2..]).unwrap();
        let sk = scalar_from_bytes(internal_sk).unwrap();
        let pk = point_to_compressed(&base_mul(&sk));
        let mut x = [0u8; 32];
        x.copy_from_slice(&pk[1..]);
        let output = compute_output_key(&x).unwrap();
        let oc = point_to_compressed(&output);
        let mut ox = [0u8; 32];
        ox.copy_from_slice(&oc[1..]);
        let even = lift_x_pubkey(&ox).unwrap();
        let sighash = bip322_p2tr_sighash(internal_sk, msg).unwrap();
        schnorr_secp256k1::verify(&even, &sighash, &sig)
    }

    #[test]
    fn bip137_hash_known_message() {
        let h = bip137_message_hash(b"123").unwrap();
        assert_eq!(
            crate::encoding::hex::encode(&h),
            "01ad6dbae3160521b6dc8bb905031d42a4c77e9e31e1ebf21c66430e2cfaf42c"
        );
    }

    #[test]
    fn bip137_keystone_sign_msg_oracle() {
        let seed = hex_decode(
            "7bf300876c3927d133c7535cbcb19d22e4ac1aff29998355d2fa7ed749212c7106620e74daf0f3d5e13a48dfb8b17641c711b513d92c7a5023ca5b1ad7b202e5",
        );
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        let sk = derive_from_seed(&seed, &path).unwrap();
        let sig = sign_bip137(&sk, b"123", Bip137AddrKind::P2pkhCompressed).unwrap();
        let encoded = base64::encode_std(&sig).unwrap();
        assert_eq!(
            encoded.as_ref(),
            "H8CDgK7sBj7o+OFZ+IVZyrKmcZuJn2/KFNHHv+kAxi+FWCUEYpZCyAGz0fj1OYwFM0E+q/TyQ2uZziqWI8k0eYE="
        );
    }

    #[test]
    fn bip322_hash_official_empty() {
        let h = bip322_message_hash(b"");
        assert_eq!(
            crate::encoding::hex::encode(&h),
            "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"
        );
    }

    #[test]
    fn bip322_hash_official_hello_world() {
        let h = bip322_message_hash(b"Hello World");
        assert_eq!(
            crate::encoding::hex::encode(&h),
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"
        );
    }

    #[test]
    fn bip322_simple_p2wpkh_official_empty() {
        let mut key = [0u8; 32];
        key.copy_from_slice(&hex_decode(
            "bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004",
        ));
        let sk = scalar_from_bytes(&key).unwrap();
        let wit = sign_bip322_simple_p2wpkh(&sk, b"").unwrap();
        let a = base64::decode_std(
            "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
        )
        .unwrap();
        let b = base64::decode_std(
            "AkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy",
        )
        .unwrap();
        assert!(
            wit.as_slice() == a.as_slice() || wit.as_slice() == b.as_slice(),
            "witness {} not in official pair",
            crate::encoding::hex::encode(&wit)
        );
    }

    #[test]
    fn bip322_simple_p2wpkh_official_hello_world() {
        let mut key = [0u8; 32];
        key.copy_from_slice(&hex_decode(
            "bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004",
        ));
        let sk = scalar_from_bytes(&key).unwrap();
        let wit = sign_bip322_simple_p2wpkh(&sk, b"Hello World").unwrap();
        let a = base64::decode_std(
            "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
        )
        .unwrap();
        let b = base64::decode_std(
            "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy",
        )
        .unwrap();
        assert!(
            wit.as_slice() == a.as_slice() || wit.as_slice() == b.as_slice(),
            "hello-world witness {} not in official pair",
            crate::encoding::hex::encode(&wit)
        );
    }

    #[test]
    fn bip322_to_spend_txid_official_empty() {
        let h = bip322_message_hash(b"");
        let mut script_sig = Vec::with_capacity(34);
        script_sig.push(0x00);
        script_sig.push(0x20);
        script_sig.extend_from_slice(&h);
        // address bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l → witness program
        // we'll reconstruct from the WIF key's pkh
        let mut key = [0u8; 32];
        key.copy_from_slice(&hex_decode(
            "bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004",
        ));
        let sk = scalar_from_bytes(&key).unwrap();
        let pk = point_to_compressed(&base_mul(&sk));
        let pkh = hash160(&pk).unwrap();
        let mut challenge = Vec::with_capacity(22);
        challenge.push(0x00);
        challenge.push(0x14);
        challenge.extend_from_slice(&pkh);
        let to_spend = Transaction {
            version: 0,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: [0u8; 32],
                    vout: 0xffff_ffff,
                },
                script_sig,
                sequence: 0,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 0,
                script_pubkey: challenge,
            }],
            lock_time: 0,
        };
        let txid = dsha256(&serialize_legacy_tx(&to_spend)).unwrap();
        // official to_spend_tx_hash is display (reversed) hex
        let mut display = txid;
        display.reverse();
        assert_eq!(
            crate::encoding::hex::encode(&display),
            "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7"
        );
    }

    #[test]
    fn bip322_p2tr_bip86_address_matches_official() {
        use crate::chain::btc::taproot::{p2tr_address_from_x_only, MAINNET_HRP};
        let mut key = [0u8; 32];
        key.copy_from_slice(&hex_decode(
            "4e9159a8a0f5f20606364cd9b23c1e6df363367c29a658ef4a881444afb0164e",
        ));
        let sk = scalar_from_bytes(&key).unwrap();
        let pk = point_to_compressed(&base_mul(&sk));
        let mut x = [0u8; 32];
        x.copy_from_slice(&pk[1..]);
        let addr = p2tr_address_from_x_only(&x, MAINNET_HRP).unwrap();
        assert_eq!(
            addr, "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler",
            "bip-86 addr mismatch: {addr}"
        );
    }

    #[test]
    fn bip322_simple_p2tr_official_no_prefix() {
        // BIP-322 basic-test-vectors.json, type p2tr, message "No prefix fallback"
        let mut key = [0u8; 32];
        key.copy_from_slice(&hex_decode(
            "4e9159a8a0f5f20606364cd9b23c1e6df363367c29a658ef4a881444afb0164e",
        ));
        let wit = sign_bip322_simple_p2tr(&key, b"No prefix fallback").unwrap();
        let official = base64::decode_std(
            "AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R",
        )
        .unwrap();
        // Different Schnorr aux → different bytes; official vectors must still verify against the same BIP-341 sighash
        assert!(
            verify_p2tr_witness(&key, b"No prefix fallback", official.as_slice()),
            "official p2tr sig must verify"
        );
        assert!(
            verify_p2tr_witness(&key, b"No prefix fallback", &wit),
            "our p2tr sig must verify"
        );
        assert_eq!(wit.len(), 66);
        assert_eq!(wit[0], 1);
        assert_eq!(wit[1], 64);
    }

    #[test]
    fn bip322_simple_p2tr_generated_vector() {
        // generated-test-vectors.json simple p2tr (smp prefix already stripped)
        let mut key = [0u8; 32];
        key.copy_from_slice(&hex_decode(
            "f805d22c9379f60b87770c8358c8fc2310b3e65d1c4555a51f58c912862b385b",
        ));
        let wit = sign_bip322_simple_p2tr(&key, b"PURVOQ544B6HUATVBJZN5EZJUU").unwrap();
        let official = base64::decode_std(
            "AUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8",
        )
        .unwrap();
        assert!(verify_p2tr_witness(
            &key,
            b"PURVOQ544B6HUATVBJZN5EZJUU",
            official.as_slice()
        ));
        assert!(verify_p2tr_witness(
            &key,
            b"PURVOQ544B6HUATVBJZN5EZJUU",
            &wit
        ));
        assert_eq!(wit.len(), 66);
    }
}
