//! BTC P2PKH input signing (legacy, pre-segwit).
//!
//! # Why this is not BIP-143
//!
//! Legacy inputs sign with the **original** Bitcoin signature hash
//! (`SigVersion::BASE`): the transaction is re-serialized with every input's
//! scriptSig blanked out, except the input being signed, whose scriptCode takes
//! its place; `OP_CODESEPARATOR` opcodes are deleted from that scriptCode; and
//! the four-byte hash type is appended. There is no `hashPrevouts` /
//! `hashSequence` / `hashOutputs` and no spent amount in the preimage — those
//! belong to BIP-143 (segwit v0) only.
//!
//! The pre-B-9 version of this module fed the BIP-143 preimage with
//! `amount = 0`. That produces a well-formed ECDSA signature over a digest no
//! node computes, which is why it was never wired into the dispatch and nothing
//! ever failed: every product path avoided it.
//!
//! # Preimage layout (`SigVersion::BASE`)
//!
//! ```text
//! version (i32 LE)
//! varint(n_inputs)          // 1 under SIGHASH_ANYONECANPAY
//!   per input:
//!     prevout txid (32) + vout (u32 LE)
//!     varint(len) + script    // our scriptCode (separators deleted) at nIn,
//!                             // empty for every other input
//!     sequence (u32 LE)       // 0 for the other inputs under SINGLE/NONE
//! varint(n_outputs)         // 0 under NONE; nIn+1 under SINGLE; else all
//!   per output:
//!     value (u64 LE) + varint(len) + scriptPubKey
//!                         // under SINGLE everything but nIn is
//!                         // value = -1 (0xffff…), empty script
//! locktime (u32 LE)
//! hash type (u32 LE)        // all 32 bits, not just the low byte
//! ```
//!
//! Everything streams into SHA-256 and is double-hashed: no buffer, no heap.
//! The spent amount deliberately does not take part (unlike BIP-143), so this
//! function needs no prevout values at all.
//!
//! # The 0xab trap
//!
//! Deleting `OP_CODESEPARATOR` is an **opcode-level** operation (consensus:
//! `CTransactionSignatureSerializer::SerializeScriptCode` walks the script with
//! `GetOp`). Byte-wise deletion looks equivalent — until a pubkey hash contains
//! `0xab`, which is true for roughly 7.5% of keys: that byte lives inside a push
//! and must survive. A byte-wise implementation signs a different digest for
//! those keys only, so "it works" and "it works for most keys" both look green.
//! [`walk_script_keeping`] is the opcode-wise walker; the regtest fixture
//! `core_regtest_p2pkh_abhash_1in1out.psbt` pins it against Bitcoin Core.

use crate::chain::btc::p2wpkh::{Transaction, SIGHASH_ALL};
use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::signature::ecdsa_secp256k1 as ecdsa;
use crate::types::SecretBytes;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// P2PKH scriptCode / scriptPubKey: `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`
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

/// Does this scriptPubKey lock to `pubkey_hash` under the P2PKH template?
pub fn is_p2pkh_spk(spk: &[u8], pubkey_hash: &[u8; 20]) -> bool {
    spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
        && spk[3..23] == *pubkey_hash
}

/// Walk `script` opcode-wise, handing out the byte ranges that survive the
/// deletion of `OP_CODESEPARATOR` opcodes.
///
/// Push payloads are skipped as data, so an `0xab` inside a push is kept. A
/// truncated push ends the walk and the remaining bytes are handed out verbatim
/// (Core's `GetOp` fails there and `SerializeScriptCode` writes the tail
/// unmodified); no signing path of ours can produce such a script.
fn walk_script_keeping(script: &[u8], mut keep: impl FnMut(&[u8])) {
    let n = script.len();
    let mut run_start = 0usize;
    let mut i = 0usize;
    while i < n {
        let op = script[i];
        if op == 0xab {
            if run_start < i {
                keep(&script[run_start..i]);
            }
            i += 1;
            run_start = i;
            continue;
        }
        let step = match op {
            0x01..=0x4b => op as usize + 1,
            0x4c => {
                if i + 1 >= n {
                    break;
                }
                2 + script[i + 1] as usize
            }
            0x4d => {
                if i + 2 >= n {
                    break;
                }
                3 + u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize
            }
            0x4e => {
                if i + 4 >= n {
                    break;
                }
                5 + u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]])
                    as usize
            }
            _ => 1,
        };
        if i + step > n {
            break;
        }
        i += step;
    }
    if run_start < n {
        keep(&script[run_start..n]);
    }
}

/// Bitcoin compact size into a SHA-256 stream.
fn put_varint(h: &mut sha2::Sha256, n: u64) {
    use sha2::Digest as _;
    let mut buf = [0u8; 9];
    let len = if n < 0xfd {
        buf[0] = n as u8;
        1
    } else if n <= 0xffff {
        buf[0] = 0xfd;
        buf[1..3].copy_from_slice(&(n as u16).to_le_bytes());
        3
    } else if n <= 0xffff_ffff {
        buf[0] = 0xfe;
        buf[1..5].copy_from_slice(&(n as u32).to_le_bytes());
        5
    } else {
        buf[0] = 0xff;
        buf[1..9].copy_from_slice(&n.to_le_bytes());
        9
    };
    h.update(&buf[..len]);
}

/// The legacy (pre-BIP-143) signature hash — `SigVersion::BASE`.
///
/// `script_code` is the script being satisfied (for P2PKH: the 25-byte
/// scriptPubKey). `hash_type` is the raw four-byte value: the low five bits pick
/// ALL/NONE/SINGLE semantics, bit 0x80 is ANYONECANPAY, and all 32 bits are
/// appended to the preimage as given.
pub fn legacy_sighash(
    tx: &Transaction<'_>,
    input_index: usize,
    script_code: &[u8],
    hash_type: u32,
) -> Result<[u8; 32]> {
    use sha2::Digest as _;

    if input_index >= tx.inputs.len() {
        return Err(err());
    }
    let base = hash_type & 0x1f;
    let anyonecanpay = hash_type & 0x80 != 0;

    // SIGHASH_SINGLE without a matching output: the historical "1" digest — the
    // 32-byte little-endian integer one, not a hash of anything.
    if base == 3 && input_index >= tx.outputs.len() {
        let mut one = [0u8; 32];
        one[0] = 1;
        return Ok(one);
    }

    let mut h = sha2::Sha256::new();
    h.update(tx.version.to_le_bytes());

    let n_inputs = if anyonecanpay { 1 } else { tx.inputs.len() };
    put_varint(&mut h, n_inputs as u64);
    for slot in 0..n_inputs {
        let idx = if anyonecanpay { input_index } else { slot };
        let txin = &tx.inputs[idx];
        h.update(txin.prev_out.txid);
        h.update(txin.prev_out.vout.to_le_bytes());
        if idx == input_index {
            let mut len = 0usize;
            walk_script_keeping(script_code, |seg| len += seg.len());
            put_varint(&mut h, len as u64);
            walk_script_keeping(script_code, |seg| h.update(seg));
        } else {
            put_varint(&mut h, 0);
        }
        if idx != input_index && (base == 2 || base == 3) {
            h.update(0u32.to_le_bytes());
        } else {
            h.update(txin.sequence.to_le_bytes());
        }
    }

    let n_outputs = if base == 2 {
        0
    } else if base == 3 {
        input_index + 1
    } else {
        tx.outputs.len()
    };
    put_varint(&mut h, n_outputs as u64);
    for i in 0..n_outputs {
        if base == 3 && i != input_index {
            // CTxOut() — the "null" output: value -1, empty script.
            h.update(u64::MAX.to_le_bytes());
            put_varint(&mut h, 0);
        } else {
            let out = &tx.outputs[i];
            h.update(out.value.to_le_bytes());
            let spk = crate::types::wire_bytes::wire_slice(&out.script_pubkey);
            put_varint(&mut h, spk.len() as u64);
            h.update(spk);
        }
    }

    h.update(tx.lock_time.to_le_bytes());
    h.update(hash_type.to_le_bytes());

    let once = h.finalize();
    Ok(sha2::Sha256::digest(once).into())
}

/// P2PKH signing input (per-input info).
///
/// P1-03: the private key uses `SecretBytes<32>` — no Clone or Debug,
/// ZeroizeOnDrop, constant-time comparison.
pub struct P2PKHSignInput<'k> {
    /// The input index being signed
    pub input_index: usize,
    /// The private key for this input — borrowed, zero-copy forwarding
    pub private_key: &'k SecretBytes<32>,
    /// pubkey hash (20 bytes) of the spent scriptPubKey
    pub pubkey_hash: [u8; 20],
}

/// Sign one P2PKH input.
///
/// Returns the first push payload (`<DER signature ‖ hash type>`) and the
/// compressed public key; the caller assembles the two pushes. Nothing is
/// allocated: the DER signature lives in a fixed 72-byte heapless vector and the
/// pubkey in a stack array.
pub fn sign_p2pkh_core(
    tx: &Transaction<'_>,
    sign_input: &P2PKHSignInput<'_>,
) -> Result<(heapless::Vec<u8, 72>, [u8; 33])> {
    let script_code = p2pkh_script_code(&sign_input.pubkey_hash);
    let sighash = legacy_sighash(tx, sign_input.input_index, &script_code, SIGHASH_ALL)?;

    let sk = scalar_from_bytes(sign_input.private_key.expose())?;
    let sig = ecdsa::sign(&sk, &sighash)?;

    let mut sig_with_sighash = ecdsa::to_der(&sig)?;
    sig_with_sighash
        .push(SIGHASH_ALL as u8)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;

    let pubkey = point_to_compressed(&base_mul(&sk));
    Ok((sig_with_sighash, pubkey))
}

/// Largest scriptSig this module produces: two pushes of at most 72 and 33 bytes.
///
/// `pub(crate)`: an internal size bound, not part of the C ABI — a `pub` const
/// would be exported into `shlosilo.h` and freeze an implementation detail.
pub(crate) const P2PKH_SCRIPTSIG_MAX: usize = 1 + 72 + 1 + 33;

/// Assemble `<push sig><push pubkey>` into `out`; returns the used length.
pub fn write_p2pkh_script_sig(sig: &[u8], pubkey: &[u8; 33], out: &mut [u8]) -> Result<usize> {
    if sig.len() > 72 {
        return Err(ShlosiloError::new(
            ShlosiloErrorKind::EncodingBufferOverflow,
        ));
    }
    let need = 1 + sig.len() + 1 + pubkey.len();
    if out.len() < need {
        return Err(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall));
    }
    out[0] = sig.len() as u8; // single-byte push prefix (both pushes are < 0x4c)
    out[1..1 + sig.len()].copy_from_slice(sig);
    let pk_at = 1 + sig.len();
    out[pk_at] = pubkey.len() as u8;
    out[pk_at + 1..pk_at + 1 + pubkey.len()].copy_from_slice(pubkey);
    Ok(need)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::btc::p2wpkh::{OutPoint, TxIn, TxOut};
    use crate::types::wire_bytes::{wire_from, witness_empty};

    const EMPTY: &[u8] = &[];
    const WPKH_OUT: &[u8] = &[
        0x00, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    ];

    fn tx_one_in_one_out(prev_txid: [u8; 32], sequence: u32) -> Transaction<'static> {
        let mut inputs = heapless::Vec::new();
        inputs
            .push(TxIn {
                prev_out: OutPoint {
                    txid: prev_txid,
                    vout: 1,
                },
                script_sig: wire_from(EMPTY),
                sequence,
                witness: witness_empty(),
            })
            .unwrap();
        let mut outputs = heapless::Vec::new();
        outputs
            .push(TxOut {
                value: 50_000,
                script_pubkey: wire_from(WPKH_OUT),
            })
            .unwrap();
        Transaction {
            version: 2,
            inputs,
            outputs,
            lock_time: 0,
        }
    }

    fn keep_bytes(script: &[u8]) -> heapless::Vec<u8, 64> {
        let mut kept: heapless::Vec<u8, 64> = heapless::Vec::new();
        walk_script_keeping(script, |seg| {
            kept.extend_from_slice(seg).unwrap();
        });
        kept
    }

    #[test]
    fn p2pkh_script_code_format() {
        let code = p2pkh_script_code(&[0x42; 20]);
        assert_eq!(code.len(), 25);
        assert_eq!(code[0], 0x76);
        assert_eq!(code[1], 0xa9);
        assert_eq!(code[2], 0x14);
        assert_eq!(&code[3..23], &[0x42; 20]);
        assert_eq!(code[23], 0x88);
        assert_eq!(code[24], 0xac);
        assert!(is_p2pkh_spk(&code, &[0x42; 20]));
        assert!(!is_p2pkh_spk(&code, &[0x43; 20]));
        // A P2WPKH prevout is not a P2PKH prevout.
        let mut wpkh = [0u8; 22];
        wpkh[0] = 0x00;
        wpkh[1] = 0x14;
        assert!(!is_p2pkh_spk(&wpkh, &[0x42; 20]));
        // …and neither is a P2SH-wrapped one.
        let mut p2sh = [0u8; 23];
        p2sh[0] = 0xa9;
        p2sh[1] = 0x14;
        p2sh[22] = 0x87;
        assert!(!is_p2pkh_spk(&p2sh, &[0x00; 20]));
    }

    #[test]
    fn p2pkh_sighash_deterministic_and_script_sensitive() {
        let tx = tx_one_in_one_out([0x11; 32], 0xffff_fffd);
        let code = p2pkh_script_code(&[0x42; 20]);
        let a = legacy_sighash(&tx, 0, &code, SIGHASH_ALL).unwrap();
        assert_eq!(a, legacy_sighash(&tx, 0, &code, SIGHASH_ALL).unwrap());
        assert_ne!(
            a,
            legacy_sighash(&tx, 0, &p2pkh_script_code(&[0x43; 20]), SIGHASH_ALL).unwrap()
        );
        assert!(legacy_sighash(&tx, 1, &code, SIGHASH_ALL).is_err());
    }

    /// The push-aware rule: an `0xab` inside the pushed pubkey hash is data and
    /// must survive. Byte-wise deletion would shorten the scriptCode, so the kept
    /// length is asserted directly (a digest-only assertion would also "pass" if
    /// both sides were wrong in the same way).
    #[test]
    fn p2pkh_sighash_keeps_pushed_ab_bytes() {
        let code = p2pkh_script_code(&[0xab; 20]);
        let kept = keep_bytes(&code);
        assert_eq!(kept.len(), 25, "pushed 0xab bytes must not be deleted");
        assert_eq!(&kept[..], &code[..]);

        // Same script with the pushed hash's 0xab bytes replaced by 0x00 must
        // hash differently — a byte-wise implementation would have collapsed the
        // first script to a 5-byte stub and could not tell them apart.
        let tx = tx_one_in_one_out([0x11; 32], 0xffff_ffff);
        assert_ne!(
            legacy_sighash(&tx, 0, &code, SIGHASH_ALL).unwrap(),
            legacy_sighash(&tx, 0, &p2pkh_script_code(&[0x00; 20]), SIGHASH_ALL).unwrap(),
        );
    }

    /// A standalone OP_CODESEPARATOR opcode *is* deleted (that is the rule).
    #[test]
    fn p2pkh_sighash_deletes_code_separator_opcodes() {
        let script = [0x76u8, 0xab, 0xa9, 0xab];
        assert_eq!(&keep_bytes(&script)[..], &[0x76, 0xa9]);
        // PUSHDATA1 payloads are data: an 0xab inside one survives.
        let with_pushdata = [0x4c, 0x02, 0xab, 0xab, 0xab, 0x76];
        assert_eq!(
            &keep_bytes(&with_pushdata)[..],
            &[0x4c, 0x02, 0xab, 0xab, 0x76]
        );
    }

    /// SIGHASH_SINGLE with no matching output is the historical "1" digest.
    #[test]
    fn p2pkh_sighash_single_without_output_is_one() {
        let code = p2pkh_script_code(&[0x42; 20]);
        let mut tx = tx_one_in_one_out([0x11; 32], 0xffff_ffff);
        tx.inputs
            .push(TxIn {
                prev_out: OutPoint {
                    txid: [0x22; 32],
                    vout: 0,
                },
                script_sig: wire_from(EMPTY),
                sequence: 0xffff_ffff,
                witness: witness_empty(),
            })
            .unwrap();
        let digest = legacy_sighash(&tx, 1, &code, 3).unwrap();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(digest, expected);
    }

    /// ANYONECANPAY signs only the input being spent: adding an unrelated input
    /// must not change the digest.
    #[test]
    fn p2pkh_sighash_anyonecanpay_ignores_other_inputs() {
        let code = p2pkh_script_code(&[0x42; 20]);
        let one = tx_one_in_one_out([0x11; 32], 0xffff_fffd);
        let mut two = tx_one_in_one_out([0x11; 32], 0xffff_fffd);
        two.inputs
            .push(TxIn {
                prev_out: OutPoint {
                    txid: [0x22; 32],
                    vout: 3,
                },
                script_sig: wire_from(EMPTY),
                sequence: 0xffff_ffff,
                witness: witness_empty(),
            })
            .unwrap();
        let acp = 0x81; // SIGHASH_ALL | ANYONECANPAY
        assert_eq!(
            legacy_sighash(&one, 0, &code, acp).unwrap(),
            legacy_sighash(&two, 0, &code, acp).unwrap(),
        );
        assert_ne!(
            legacy_sighash(&one, 0, &code, SIGHASH_ALL).unwrap(),
            legacy_sighash(&two, 0, &code, SIGHASH_ALL).unwrap(),
        );
    }

    #[test]
    fn p2pkh_script_sig_layout() {
        let sig = [0x30u8; 71];
        let pk = [0x02u8; 33];
        let mut out = [0u8; P2PKH_SCRIPTSIG_MAX];
        let n = write_p2pkh_script_sig(&sig, &pk, &mut out).unwrap();
        assert_eq!(n, 1 + 71 + 1 + 33);
        assert_eq!(out[0], 71);
        assert_eq!(out[72], 33);
        assert_eq!(&out[73..n], &pk[..]);
        // A short caller buffer is an explicit error, never a truncation.
        let mut small = [0u8; 40];
        assert!(write_p2pkh_script_sig(&sig, &pk, &mut small).is_err());
        // An over-long signature is refused rather than written as a bad push.
        let long = [0x30u8; 73];
        assert!(write_p2pkh_script_sig(&long, &pk, &mut out).is_err());
    }
}
