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

#[cfg(any(feature = "alloc-fallback", test))]
extern crate alloc;
use crate::chain::eth::rlp;
use crate::chain::eth::sign;
use crate::encoding::keccak256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::types::SecretBytes;
// Consumers live behind alloc-fallback / cfg(test).
#[cfg(any(feature = "alloc-fallback", test))]
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
    /// A2-08 (2026-11-19 audit): the signer BORROWS the key, mirroring `Eip1559SignInput`. Taking it
    /// by value forced every caller to mint an extra owner of a secret it already held.
    pub private_key: &'a SecretBytes<32>,
}

/// Signing output
#[derive(Clone, Debug)]
#[cfg(any(feature = "alloc-fallback", test))]
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
    rlp::write_bytes(s, crate::types::wire_bytes::wire_slice(&tx.data))?;
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
        + rlp::encoded_bytes_len(crate::types::wire_bytes::wire_slice(&tx.data))
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
#[cfg(any(feature = "alloc-fallback", test))]
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

/// Signature parts (E-1, 2026-11-25) — no transaction serialization, pure arrays.
///
/// The `ur:eth-signature` exit carries `r ‖ s ‖ v`, so the signer needs exactly
/// these values: `sign_eip155_into` adds the RLP serialization on top, and the
/// product exit path stops here (same split as `eip1559::sign_eip1559_parts`).
#[derive(Clone, Debug)]
pub struct Eip155Signature {
    /// signing hash (Keccak256 of the EIP-155 preimage)
    pub signing_hash: [u8; 32],
    /// signature r
    pub r: [u8; 32],
    /// signature s (always the low-s form)
    pub s: [u8; 32],
    /// `chain_id * 2 + 35 + y_parity` — the EIP-155 `v` (`37`/`38` on chain 1)
    pub v: u64,
}

/// `v = chain_id * 2 + 35 + y_parity`, in **checked** arithmetic.
///
/// F-8 (P1, 2026-11-25): this used to be a bare `chain_id * 2 + 35 + parity`. u64
/// multiplication does not trap in a release build — it wraps — so a chain id above
/// 2^63 emitted a `v` from a different chain, and a wallet recovering the sender
/// from it lands on the wrong address while the device reports success. (In a debug
/// build the same expression panics, which `forms/` may not do at all.)
///
/// A chain id whose `v` does not fit in u64 is a request this signer cannot express:
/// `EncodingInvalidFormat`, not an internal error.
///
/// Mutation check for the pin in `sign_eip155_parts_...`: replace the checked chain
/// with `chain_id * 2 + 35 + y_parity as u64` and
/// `eip155_sign_parts_rejects_unrepresentable_chain_id` must go red (it would see a
/// wrapped `v` instead of an error).
fn eip155_v(chain_id: u64, y_parity: u8) -> Result<u64> {
    chain_id
        .checked_mul(2)
        .and_then(|x| x.checked_add(35))
        .and_then(|x| x.checked_add(y_parity as u64))
        .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))
}

/// Write the EIP-155 `v` as **minimal big-endian** bytes: the leading zero bytes are
/// dropped, and `v == 0` is the single byte `0x00`.
///
/// Byte-for-byte the rule keystone's reference implementation applies in
/// `rust/apps/ethereum/src/structs.rs::EthereumSignature::serialize` (it takes
/// `u64::to_be_bytes()`, strips leading zeros, and pushes one `0` when nothing is
/// left), so a `v` of 309 reaches a wallet as `01 35` no matter which implementation
/// produced it. `ur:eth-signature` accepts 1..=8 bytes and refuses the padded form
/// (`ur::codec::eth_signature::check_signature_shape`), so this function is the only
/// producer of that segment.
///
/// Returns the number of bytes written (`1..=8`).
pub fn write_v_be(v: u64, out: &mut [u8]) -> Result<usize> {
    let be = v.to_be_bytes();
    // Keep at least one byte: `first` never reaches `be.len()`.
    let mut first = 0usize;
    while first + 1 < be.len() && be[first] == 0 {
        first += 1;
    }
    let n = be.len() - first;
    let slot = match out.get_mut(..n) {
        Some(s) => s,
        None => {
            return Err(ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(n),
            ))
        }
    };
    slot.copy_from_slice(&be[first..]);
    Ok(n)
}

/// Steps 1–3 of the signing flow: signing hash → ECDSA → low-s → EIP-155 `v`.
///
/// Returns the signature parts only; `sign_eip155_into` adds the RLP serialization
/// on top, and the `ur:eth-signature` exit path stops here.
pub fn sign_eip155_parts(input: &Eip155SignInput) -> Result<Eip155Signature> {
    let sk = sign::sk_from_pk(input.private_key.expose())?;

    // 1. signing hash (streams the preimage into Keccak — no buffer)
    let sighash = signing_hash(&input.tx)?;

    // 2. ECDSA sign + low-s enforcement + y_parity
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let y_parity = sign::apply_low_s(&sighash, &sk, &mut r_bytes, &mut s_bytes)?;

    // 3. v = chain_id * 2 + 35 + y_parity (F-8: checked, never a wrapping multiply)
    let v = eip155_v(input.tx.chain_id, y_parity)?;

    Ok(Eip155Signature {
        signing_hash: sighash,
        r: r_bytes,
        s: s_bytes,
        v,
    })
}

/// Sign an EIP-155 legacy transaction, writing `rlp([9 fields])` straight
/// into the caller's buffer. Zero-alloc production form.
///
/// E-1: parts first, then serialize — the signing steps (and the checked `v`) live in
/// [`sign_eip155_parts`], so this convenience face cannot drift from the product exit.
pub fn sign_eip155_into(input: &Eip155SignInput, out: &mut [u8]) -> Result<Eip155SignOutcome> {
    let parts = sign_eip155_parts(input)?;
    let r_bytes = parts.r;
    let s_bytes = parts.s;
    let v = parts.v;
    let sighash = parts.signing_hash;

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
#[cfg(any(feature = "alloc-fallback", test))]
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

        let input = Eip155SignInput {
            tx,
            private_key: &private_key,
        };
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
            private_key: &private_key,
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

    // ─── E-1 (2026-11-25): the product exit's signature parts ───────────────

    /// The EIP-155 spec's own example — the gold vector for the product exit
    /// (pool #68's hex, the same transaction as `sign_eip155_full_pipeline`):
    ///
    /// ```text
    /// preimage  rlp([9, 20 gwei, 21000, 0x3535…35, 1 ETH, 0x, 1, 0, 0])
    ///         = ec098504a817c800825208943535…35880de0b6b3a764000080018080
    /// sighash   daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53
    /// signed    f86c09…6d83   (v = 0x25 = 37, r = 28ef…, s = 67cb…)
    /// ```
    ///
    /// The exit path hands a wallet `r ‖ s ‖ v`, not a signed transaction, so the
    /// parts are what has to match the published bytes: same key (0x4646…46), same
    /// preimage, same three values.
    #[test]
    fn eip155_gold_parts_match_the_spec_example() {
        let private_key = SecretBytes::new([
            0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46,
            0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46,
            0x46, 0x46, 0x46, 0x46,
        ]);
        let tx = Eip155Transaction {
            chain_id: 1,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1_000_000_000_000_000_000,
            data: Vec::new().into(),
        };

        // the preimage our struct model produces IS the bytes the wallet signed
        let mut preimage = [0u8; 256];
        let n = signing_preimage_into(&tx, &mut preimage).expect("preimage");
        assert_eq!(
            &preimage[..n],
            &hex_decode(
                "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
            )[..],
            "the EIP-155 preimage must be byte-exact (this is the gold wire shape)"
        );

        let parts = sign_eip155_parts(&Eip155SignInput {
            tx,
            private_key: &private_key,
        })
        .expect("sign parts");

        // sighash
        assert_eq!(
            &parts.signing_hash[..],
            &hex_decode("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")[..],
            "sighash must match the published example"
        );
        // r and s, byte for byte, out of the published signed transaction
        assert_eq!(
            &parts.r[..],
            &hex_decode("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276")[..],
            "r must match the published signed tx"
        );
        assert_eq!(
            &parts.s[..],
            &hex_decode("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")[..],
            "s must match the published signed tx"
        );
        // v = 0x25 = chain_id*2 + 35 + parity (0 here — the published v is 37, so
        // this also pins that we do not add a 27/28 offset on top of EIP-155)
        assert_eq!(parts.v, 37, "v = 37 for chain 1, low-s parity 0");
        // and the exit's v segment is the single byte the container carries
        let mut v_bytes = [0u8; 8];
        let vn = write_v_be(parts.v, &mut v_bytes).expect("write v");
        assert_eq!(&v_bytes[..vn], &[0x25], "v = 0x25 is one byte");
    }

    /// `v` is written minimal big-endian — keystone
    /// `EthereumSignature::serialize`'s rule, byte for byte, so the same `v`
    /// becomes the same bytes whichever implementation produced it.
    #[test]
    fn write_v_be_matches_keystone_serialize() {
        let cases: [(u64, &[u8], &str); 6] = [
            (0, &[0x00], "v = 0 is one byte 0x00, never zero bytes"),
            (27, &[0x1b], "EIP-191 v"),
            (37, &[0x25], "mainnet legacy EIP-155 v"),
            (
                309,
                &[0x01, 0x35],
                "Polygon (137) needs 2 bytes → 66 B container",
            ),
            (
                22310257,
                &[0x01, 0x54, 0x6d, 0x71],
                "Sepolia (11155111) needs 4 bytes → 68 B container",
            ),
            (
                u64::MAX,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                "widest v",
            ),
        ];
        for (v, want, why) in cases {
            let mut out = [0u8; 8];
            let n = write_v_be(v, &mut out).expect("write v");
            assert_eq!(&out[..n], want, "{why}");
        }
        // different v, different bytes: no aliasing through padding
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        let na = write_v_be(309, &mut a).expect("write a");
        let nb = write_v_be(310, &mut b).expect("write b");
        assert_ne!(&a[..na], &b[..nb], "309 and 310 must not collide");
        // an undersized buffer is reported, never silently truncated
        let mut small = [0u8; 3];
        let e = write_v_be(22310257, &mut small).expect_err("4 bytes do not fit in 3");
        assert_eq!(e.kind, ShlosiloErrorKind::BufferTooSmall);
        assert_eq!(e.context, crate::error::ErrorContext::RequiredLength(4));
    }

    /// F-8 (P1, 2026-11-25): a chain id whose `v` cannot be represented is a
    /// refused request, never a wrapped value.
    ///
    /// `chain_id = u64::MAX` needs `v = 2^65 + 35`. The old bare
    /// `chain_id * 2 + 35 + parity` wrapped in release (u64::MAX*2 + 35 = 33, +1 →
    /// 34: a "v" that is neither 27/28 nor EIP-155 — a wallet recovering from it
    /// lands on some other address while the device reports success) and panicked in
    /// debug, which `forms/` may not do at all.
    ///
    /// Mutation check: swap the `checked_mul(2).and_then(checked_add(35))…
    /// .ok_or_else(…)` chain in `eip155_v` for `chain_id * 2 + 35 + y_parity as u64`
    /// and this pin goes red (debug: panic; release: a wrapped v instead of Err).
    #[test]
    fn eip155_sign_parts_rejects_unrepresentable_chain_id() {
        let private_key = SecretBytes::new([0x46u8; 32]);
        // Every one of these needs v = 2*chain_id + 35 + parity above u64::MAX.
        for chain_id in [u64::MAX, u64::MAX / 2 + 1, 1u64 << 63] {
            let tx = Eip155Transaction {
                chain_id,
                nonce: 9,
                gas_price: 20_000_000_000,
                gas_limit: 21000,
                destination: Some([0x35u8; 20]),
                amount: 1,
                data: Vec::new().into(),
            };
            let e = sign_eip155_parts(&Eip155SignInput {
                tx,
                private_key: &private_key,
            })
            .expect_err("an unrepresentable v must be refused, not wrapped");
            assert_eq!(
                e.kind,
                ShlosiloErrorKind::EncodingInvalidFormat,
                "chain_id {chain_id}: an unrepresentable v is a request we cannot sign"
            );
        }
        // control: the largest chain id whose v still fits signs fine
        let highest_ok = (u64::MAX - 36) / 2;
        let tx = Eip155Transaction {
            chain_id: highest_ok,
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            destination: Some([0x35u8; 20]),
            amount: 1,
            data: Vec::new().into(),
        };
        let parts = sign_eip155_parts(&Eip155SignInput {
            tx,
            private_key: &private_key,
        })
        .expect("the largest representable chain id signs");
        assert!(parts.v >= 35 + highest_ok * 2, "v is EIP-155, not wrapped");
    }

    /// E-1 v table on the core that produces it: every supported chain yields
    /// `chain_id * 2 + 35 + parity` and never the pre-EIP-155 `27/28`.
    #[test]
    fn eip155_v_is_always_the_protected_form() {
        let private_key = SecretBytes::new([0x11u8; 32]);
        let cases: [(u64, &str); 4] = [
            (1, "ethereum mainnet"),
            (5, "goerli"),
            (137, "polygon"),
            (11155111, "sepolia"),
        ];
        for (chain_id, name) in cases {
            let tx = Eip155Transaction {
                chain_id,
                nonce: 0,
                gas_price: 1_000_000_000,
                gas_limit: 21_000,
                destination: Some([0x22u8; 20]),
                amount: 1,
                data: Vec::new().into(),
            };
            let parts = sign_eip155_parts(&Eip155SignInput {
                tx,
                private_key: &private_key,
            })
            .expect("sign parts");
            let parity = parts.v - (chain_id * 2 + 35);
            assert!(
                parity == 0 || parity == 1,
                "{name}: v must be chain_id*2+35+parity, got {}",
                parts.v
            );
            assert!(
                parts.v >= 37,
                "{name}: 27/28 is the unprotected form and is never emitted here"
            );
        }
    }
}
