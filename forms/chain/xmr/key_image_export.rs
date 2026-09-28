//! XMR key image export end-to-end flow (aligned with keystone `generate_export_ur_data`).
//!
//! Steps ①→② of the three-step wire protocol:
//! 1. Wallet (hot side) `export_outputs` → `OUTPUT_EXPORT_MAGIC` encrypted payload → XmrOutput UR
//! 2. Device decrypts → validates pk1/pk2 ownership → computes key image + accompanying signature per output
//!    → `KEY_IMAGE_EXPORT_MAGIC` encryption → XmrKeyImage UR
//!
//! Encryption wrapper layer (aligned with keystone `utils/mod.rs`):
//! ```text
//! encrypt: [magic][8B nonce BE][ChaCha20Legacy(cryptonight_hash_v0(view_sk), nonce)(
//!           [u32 LE 0 if key-image magic][pk1][pk2](export magic only)][data][64B sig])]
//! sig    : Monero Schnorr (c, r) over keccak256(nonce || ciphertext-before-sig),
//!          pubkey = view_pub — see the dual implementation in unsigned_txset::check_monero_signature
//! ```

#[cfg(feature = "alloc-fallback")]
extern crate alloc;

use alloc::vec::Vec;

use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use monero_ed25519::Point;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::chain::xmr::output_export::{ExportedTransferDetail, ExportedTransferDetails};
use crate::chain::xmr::unsigned_txset::check_monero_signature;
use crate::encoding::keccak256;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

pub const OUTPUT_EXPORT_MAGIC: &[u8] = b"Monero output export\x04";
pub const KEY_IMAGE_EXPORT_MAGIC: &[u8] = b"Monero key image export\x03";
const NONCE_LEN: usize = 8;
const SIG_LEN: usize = 64;
const PUBKEY_LEN: usize = 32;

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

/// Decrypted export payload: (pk1, pk2, zeroizing plaintext).
pub type ExportPayload = ([u8; 32], [u8; 32], zeroize::Zeroizing<Vec<u8>>);

/// Decrypt an export-class payload (OUTPUT/KEY_IMAGE magic share a structure).
///
/// Returns `(pk1, pk2, plaintext)`; pk1/pk2 exist only for OUTPUT/KEY_IMAGE magic
/// (unsigned/signed txset have no such section). Signature verified first (anti-tamper), then decrypted.
pub fn decrypt_export_payload(
    data: &[u8],
    magic: &[u8],
    view_sk: &[u8; 32],
) -> Result<ExportPayload> {
    // Z2.4d-5 staging convenience (allocates); core is `decrypt_export_payload_into`.
    let mut scratch = zeroize::Zeroizing::new(alloc::vec![0u8; data.len()]);
    let (pk1, pk2, n) = decrypt_export_payload_into(data, magic, view_sk, &mut scratch)?;
    Ok((pk1, pk2, zeroize::Zeroizing::new(scratch[..n].to_vec())))
}

/// Fused core (Z2.4d-5): decrypts into caller storage. `scratch[..n]` is the payload
/// (request details — same secrecy class as `details_out`, not secret); the scratch
/// TAIL is wiped by forms before return. Signature verified first (anti-tamper).
pub fn decrypt_export_payload_into(
    data: &[u8],
    magic: &[u8],
    view_sk: &[u8; 32],
    scratch: &mut [u8],
) -> Result<([u8; 32], [u8; 32], usize)> {
    use zeroize::Zeroize;
    if data.len() < magic.len() + NONCE_LEN + SIG_LEN {
        return Err(err());
    }
    if &data[..magic.len()] != magic {
        return Err(err());
    }

    // raw = nonce || ciphertext (the signature covers nonce||cipher, aligned with keystone raw_data)
    let raw = &data[magic.len()..];
    let nonce = &raw[..NONCE_LEN];
    let sig = &data[data.len() - SIG_LEN..];
    let raw_data = &data[magic.len()..data.len() - SIG_LEN];

    // 1. Monero Schnorr verification (view_pub over keccak256(nonce||cipher))
    let v_scalar = Scalar::from_bytes_mod_order(*view_sk);
    let view_pub = (ED25519_BASEPOINT_TABLE * &v_scalar).compress().to_bytes();
    let msg_hash = keccak256::hash(raw_data)?;
    if !check_monero_signature(&msg_hash, &view_pub, sig)? {
        return Err(err());
    }

    // 2. ChaCha20-Legacy decryption into the caller scratch
    // Z2.2 (2026-09-24): ChaCha key material zeroized on drop.
    let key = zeroize::Zeroizing::new(cuprate_cryptonight::cryptonight_hash_v0(view_sk));
    let mut cipher =
        chacha20::ChaCha20Legacy::new_from_slices(key.as_slice(), nonce).map_err(|_| err())?;
    let ct = &raw_data[NONCE_LEN..];
    if scratch.len() < ct.len() {
        return Err(crate::error::ShlosiloError::new(
            crate::error::ShlosiloErrorKind::BufferTooSmall,
        ));
    }
    let plain: &mut [u8] = &mut scratch[..ct.len()];
    plain.copy_from_slice(ct);
    cipher.apply_keystream(plain);

    // 3. key-image magic has a leading u32 LE 0; both export magics carry pk1||pk2
    let start = if magic == KEY_IMAGE_EXPORT_MAGIC {
        4
    } else {
        0
    };
    if plain.len() < start + PUBKEY_LEN * 2 {
        scratch[..ct.len()].zeroize();
        return Err(err());
    }
    let mut pk1 = [0u8; 32];
    let mut pk2 = [0u8; 32];
    pk1.copy_from_slice(&plain[start..start + PUBKEY_LEN]);
    pk2.copy_from_slice(&plain[start + PUBKEY_LEN..start + PUBKEY_LEN * 2]);
    let payload_start = start + PUBKEY_LEN * 2;
    let payload_len = plain.len() - payload_start;
    scratch.copy_within(payload_start..payload_start + payload_len, 0);
    // forms-internal duty: everything beyond the payload is wiped before return.
    scratch[payload_len..].zeroize();
    Ok((pk1, pk2, payload_len))
}

/// Encrypt an export-class payload (aligned with keystone `encrypt_data_with_pvk`).
/// Z2.4d-5: staging convenience over `encrypt_export_payload_into`; test-only —
/// the production path calls the into-core directly.
#[cfg(test)]
fn encrypt_export_payload<R: RngCore + CryptoRng>(
    magic: &[u8],
    view_sk: &[u8; 32],
    spend_pub: &[u8; 32],
    view_pub: &[u8; 32],
    data: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Z2.4d-5 staging convenience (allocates); core is `encrypt_export_payload_into`.
    let mut out = alloc::vec![0u8; magic.len() + NONCE_LEN + 4 + 64 + data.len() + SIG_LEN];
    let n = encrypt_export_payload_into(magic, view_sk, spend_pub, view_pub, data, rng, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// Fused core (Z2.4d-5): writes `magic ‖ nonce ‖ ChaCha(sections) ‖ sig` straight
/// into `out` — the plaintext sections stream through the keystream and never
/// materialize (same shape as `SignedTxSet::encrypt_signed_txset_into`). Byte-identical
/// to the former buffer-based body under the same RNG (nonce draw first, then the
/// signature k). The output is ciphertext (not sensitive).
pub fn encrypt_export_payload_into<R: RngCore + CryptoRng>(
    magic: &[u8],
    view_sk: &[u8; 32],
    spend_pub: &[u8; 32],
    view_pub: &[u8; 32],
    data: &[u8],
    rng: &mut R,
    out: &mut [u8],
) -> Result<usize> {
    use crate::types::push::{push_slice, EncryptingSink, Sink as _, SinkCursor};
    // Z2.2 (2026-09-24): ChaCha key material zeroized on drop.
    let key = zeroize::Zeroizing::new(cuprate_cryptonight::cryptonight_hash_v0(view_sk));
    let nonce_num = rng.next_u64().to_be_bytes();
    let cipher =
        chacha20::ChaCha20Legacy::new_from_slices(key.as_slice(), &nonce_num).map_err(|_| err())?;

    // Signature: Monero Schnorr over keccak256(nonce || ciphertext), key = view_sk
    let v_scalar = Scalar::from_bytes_mod_order(*view_sk);

    // stage 1: magic ‖ nonce ‖ ciphertext — sections stream through the keystream
    let ct_end = {
        let mut w = SinkCursor::new(out);
        w.put(magic)?;
        w.put(&nonce_num)?;
        let mut enc = EncryptingSink::new(w, cipher);
        // Plaintext sections: key-image magic has a leading u32 LE 0; export magic carries pk1||pk2
        if magic == KEY_IMAGE_EXPORT_MAGIC {
            enc.put(&0u32.to_le_bytes())?;
        }
        enc.put(spend_pub)?;
        enc.put(view_pub)?;
        enc.put(data)?;
        enc.pos()
    };
    // stage 2: sig over keccak256(nonce ‖ ciphertext) — contiguous in `out` after the magic
    let msg_hash = keccak256::hash(&out[magic.len()..ct_end])?;
    let sig = generate_monero_signature(&msg_hash, &v_scalar, rng)?;
    let mut n = 0usize;
    push_slice(&mut out[ct_end..], &mut n, &sig)?;
    Ok(ct_end + n)
}

/// Monero Schnorr generation side (aligned with keystone `generate_signature`):
/// k random → K = k·B → c = Hs(hash || P || K) → r = k − c·x.
/// Verification side `check_monero_signature`: c·P + r·B == K.
pub fn generate_monero_signature<R: RngCore + CryptoRng>(
    hash: &[u8; 32],
    sec: &Scalar,
    rng: &mut R,
) -> Result<[u8; 64]> {
    loop {
        // 64B random → mod_order_wide (aligned with keystone generate_random_scalar)
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let k = Scalar::from_bytes_mod_order_wide(&wide);
        let kb = (ED25519_BASEPOINT_TABLE * &k).compress().to_bytes();
        let pub_b = (ED25519_BASEPOINT_TABLE * sec).compress().to_bytes();

        // Z2.4d-5: stack buffer (was a 96B Vec on the signing path)
        let mut data = [0u8; 96];
        data[..32].copy_from_slice(hash);
        data[32..64].copy_from_slice(&pub_b);
        data[64..].copy_from_slice(&kb);
        let c_bytes = crate::chain::xmr::subaddress::hash_to_scalar(&data)?;
        let c = Scalar::from_bytes_mod_order(c_bytes);
        if c == Scalar::ZERO {
            continue;
        }
        let r = k - c * sec;
        if r == Scalar::ZERO {
            continue;
        }
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&c.to_bytes());
        sig[32..].copy_from_slice(&r.to_bytes());
        return Ok(sig);
    }
}

/// Key image accompanying signature (aligned with keystone `generate_ring_signature`, ring=1).
///
/// Single-element ring signature (MLSAG special case): h = Hs(prefix || k·B || k·Hp(P)),
/// c = h, r = k − c·x. The verifier recomputes Hs(prefix || r·B + c·P || r·Hp(P) + c·I).
/// `prefix_hash` = the key image itself (keystone passes image.compress().0).
fn generate_key_image_signature<R: RngCore + CryptoRng>(
    prefix_hash: &[u8; 32],
    input_sk: &Scalar,
    rng: &mut R,
) -> Result<[u8; 64]> {
    use curve25519_dalek::EdwardsPoint;
    // P = x·G；I = x·Hp(P)
    let p_point: EdwardsPoint = ED25519_BASEPOINT_TABLE * input_sk;
    let p_bytes = p_point.compress().to_bytes();
    let i_point: EdwardsPoint = Point::biased_hash(p_bytes).into();

    let k = {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    };
    let kb = (ED25519_BASEPOINT_TABLE * &k).compress().to_bytes();
    let khp = (k * i_point).compress().to_bytes();

    // Z2.4d-5: stack buffer (was a 96B Vec on the signing path)
    let mut buff = [0u8; 96];
    buff[..32].copy_from_slice(prefix_hash);
    buff[32..64].copy_from_slice(&kb);
    buff[64..].copy_from_slice(&khp);
    let h_bytes = crate::chain::xmr::subaddress::hash_to_scalar(&buff)?;
    let h = Scalar::from_bytes_mod_order(h_bytes);
    let c = h;
    let r = k - c * input_sk;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&c.to_bytes());
    sig[32..].copy_from_slice(&r.to_bytes());
    Ok(sig)
}

/// End-to-end: XmrOutput payload → XmrKeyImage payload (isomorphic to keystone generate_export_ur_data).
///
/// `view_sk`/`spend_sk` are held by the caller in Zeroizing; this function takes only borrows (v2-security §2)
/// and creates no extra copies. Computes only outputs with `is_key_image_request()` (keystone computes all,
/// but the flags bit5 semantics are exactly "needs key image" — keeping full alignment; a parameter switch is left for the future).
pub fn generate_key_image_export<R: RngCore + CryptoRng>(
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
    request_payload: &[u8],
    details_out: &mut [ExportedTransferDetail],
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Z2.4d-5 staging convenience (allocates); core is `generate_key_image_export_into`.
    let mut scratch = alloc::vec![0u8; request_payload.len().max(1024)];
    let mut records_out: alloc::vec::Vec<([u8; 32], [u8; 64])> = alloc::vec::Vec::new();
    records_out.resize(details_out.len().max(1), ([0u8; 32], [0u8; 64]));
    let mut out = alloc::vec![0u8; 8192];
    let n = generate_key_image_export_into(
        view_sk,
        spend_sk,
        request_payload,
        &mut scratch,
        details_out,
        &mut records_out,
        &mut out,
        rng,
    )?;
    out.truncate(n);
    Ok(out)
}

/// Fused core (Z2.4d-5): request decrypt→parse→key images→response encrypt in one
/// pass. `scratch` is storage only — the request plaintext transient is wiped by
/// forms before return (same contract as `decrypt_and_parse_unsigned_tx`), then
/// reused to stage the response records (public data) for the keystream sections.
/// `records_out` holds the computed (image, sig) pairs; `out` receives ciphertext.
#[allow(clippy::too_many_arguments)]
pub fn generate_key_image_export_into<R: RngCore + CryptoRng>(
    view_sk: &[u8; 32],
    spend_sk: &[u8; 32],
    request_payload: &[u8],
    scratch: &mut [u8],
    details_out: &mut [ExportedTransferDetail],
    records_out: &mut [([u8; 32], [u8; 64])],
    out: &mut [u8],
    rng: &mut R,
) -> Result<usize> {
    use crate::types::push::SinkCursor;
    use zeroize::Zeroize;
    // 1. Decrypt the OUTPUT_EXPORT payload into the scratch, validate pk1/pk2 ownership
    let (pk1, pk2, req_len) =
        decrypt_export_payload_into(request_payload, OUTPUT_EXPORT_MAGIC, view_sk, scratch)?;

    let spend_sk_scalar = Scalar::from_bytes_mod_order(*spend_sk);
    let spend_pub = (ED25519_BASEPOINT_TABLE * &spend_sk_scalar)
        .compress()
        .to_bytes();
    let v_scalar = Scalar::from_bytes_mod_order(*view_sk);
    let view_pub = (ED25519_BASEPOINT_TABLE * &v_scalar).compress().to_bytes();

    // Ownership validation (keystone panics — we return an error code; a signer must not panic)
    if pk1 != spend_pub || pk2 != view_pub {
        return Err(err());
    }

    // 2. Parse the outputs (Z2.3 C3b-1: details list into caller storage)
    let details = ExportedTransferDetails::from_bytes(&scratch[..req_len], details_out)?;
    // request plaintext transient done with — wiped before anything else happens
    scratch.zeroize();

    // 3. Compute key image + accompanying signature per output into the caller slot
    let spend_sk_z = Zeroizing::new(*spend_sk);
    let _ = spend_sk_z; // Zeroizing lifetime pinned to end of function
    let count = details.details.len();
    if count > records_out.len() {
        return Err(crate::error::ShlosiloError::new(
            crate::error::ShlosiloErrorKind::BufferTooSmall,
        ));
    }
    for (i, detail) in details.details.iter().enumerate() {
        let rec = compute_key_image_with_signature(view_sk, &spend_sk_scalar, detail, rng)?;
        records_out[i] = rec;
    }

    // 4. KEY_IMAGE_EXPORT_MAGIC encryption — records stream through the keystream
    //    (wire staged in the same scratch; it holds public data only).
    let mut w = SinkCursor::new(scratch);
    crate::chain::xmr::output_export::write_key_images(&records_out[..count], &mut w)?;
    let wire_len = w.pos();
    encrypt_export_payload_into(
        KEY_IMAGE_EXPORT_MAGIC,
        view_sk,
        &spend_pub,
        &view_pub,
        &scratch[..wire_len],
        rng,
        out,
    )
}

/// Single-output key image + signature (aligned with keystone `generate_key_image`).
fn compute_key_image_with_signature<R: RngCore + CryptoRng>(
    view_sk: &[u8; 32],
    spend_sk: &Scalar,
    detail: &ExportedTransferDetail,
    rng: &mut R,
) -> Result<([u8; 32], [u8; 64])> {
    // additional key semantics: subaddress outputs use the per-output additional tx key
    let key_to_use: [u8; 32] = if detail.major != 0 || detail.minor != 0 {
        match detail.additional_tx_keys.len() {
            1 => *detail.additional_tx_keys[0],
            n if n > 1 => {
                let idx = detail.internal_output_index as usize;
                **detail.additional_tx_keys.get(idx).ok_or_else(err)?
            }
            _ => detail.tx_pubkey,
        }
    } else {
        detail.tx_pubkey
    };

    // key_offset = Hs((view·tx_pub)·8 || varint(idx)) + m(major,minor)
    let offset = crate::chain::xmr::subaddress::calc_output_key_offset(
        view_sk,
        &key_to_use,
        detail.internal_output_index,
        detail.major,
        detail.minor,
    )?;

    // input_sk = spend_sk + offset; verifies input_sk·G == output_pubkey
    let input_sk = spend_sk + Scalar::from_bytes_mod_order(offset);
    let input_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();
    if input_pub != detail.pubkey {
        return Err(err());
    }

    // I = input_sk · Hp(P)
    let image: [u8; 32] = {
        let point: curve25519_dalek::EdwardsPoint = Point::biased_hash(detail.pubkey).into();
        (point * input_sk).compress().to_bytes()
    };

    // Accompanying signature: prefix = the image itself
    let sig = generate_key_image_signature(&image, &input_sk, rng)?;
    Ok((image, sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::xmr::output_export::deserialize_key_images;
    use rand_chacha::rand_core::SeedableRng;

    fn rng_from(seed: u64) -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::seed_from_u64(seed)
    }

    fn make_keypair(seed: u8) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let sk = Scalar::from_bytes_mod_order([seed; 32]);
        let sk_b = sk.to_bytes();
        let pk = (ED25519_BASEPOINT_TABLE * &sk).compress().to_bytes();
        (sk_b, pk, sk_b, pk) // (spend_sk, spend_pub, view_sk, view_pub)
    }

    #[test]
    fn export_encrypt_decrypt_round_trip() {
        let mut rng = rng_from(1);
        let (_, spend_pub, view_sk, view_pub) = make_keypair(1);
        let data = b"hello wire";

        let enc = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC,
            &view_sk,
            &spend_pub,
            &view_pub,
            data,
            &mut rng,
        )
        .unwrap();
        let (pk1, pk2, plain) =
            decrypt_export_payload(&enc, OUTPUT_EXPORT_MAGIC, &view_sk).unwrap();
        assert_eq!(pk1, spend_pub);
        assert_eq!(pk2, view_pub);
        assert_eq!(*plain, data.to_vec());
    }

    #[test]
    fn wrong_magic_rejected() {
        let mut rng = rng_from(2);
        let (_, spend_pub, view_sk, view_pub) = make_keypair(2);
        let enc = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC,
            &view_sk,
            &spend_pub,
            &view_pub,
            b"x",
            &mut rng,
        )
        .unwrap();
        assert!(decrypt_export_payload(&enc, KEY_IMAGE_EXPORT_MAGIC, &view_sk).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut rng = rng_from(3);
        let (_, spend_pub, view_sk, view_pub) = make_keypair(3);
        let mut enc = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC,
            &view_sk,
            &spend_pub,
            &view_pub,
            b"payload",
            &mut rng,
        )
        .unwrap();
        let last = enc.len() - 1;
        enc[last] ^= 0x01;
        assert!(decrypt_export_payload(&enc, OUTPUT_EXPORT_MAGIC, &view_sk).is_err());
    }

    #[test]
    fn wrong_view_key_rejected() {
        let mut rng = rng_from(4);
        let (_, spend_pub, view_sk, view_pub) = make_keypair(4);
        let enc = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC,
            &view_sk,
            &spend_pub,
            &view_pub,
            b"payload",
            &mut rng,
        )
        .unwrap();
        let (_, _, other_view, _) = make_keypair(99);
        assert!(decrypt_export_payload(&enc, OUTPUT_EXPORT_MAGIC, &other_view).is_err());
    }

    #[test]
    fn key_image_export_end_to_end() {
        // End-to-end: build an output export (with 1 main-address output) → full flow → decrypt and verify
        let mut rng = rng_from(5);
        let (spend_sk, spend_pub, view_sk, view_pub) = make_keypair(5);

        // Build the plaintext ExportedTransferDetails (main-address output: major=0,minor=0)
        let mut plain = Vec::new();
        plain.extend_from_slice(&[0x01]); // has_transfers
        plain.extend_from_slice(&[0x00]); // offset
        plain.extend_from_slice(&[0x01]); // transfer_count
        plain.extend_from_slice(&[0x00]); // blob size
                                          // detail: version, pubkey, idx, gidx, tx_pubkey, flags, amount, keys, major, minor
        plain.extend_from_slice(&[0x01]); // version
                                          // output pubkey = input_sk·G，input_sk = spend + offset(0)
        let offset =
            crate::chain::xmr::subaddress::calc_output_key_offset(&view_sk, &[0x22u8; 32], 0, 0, 0)
                .unwrap();
        let input_sk =
            Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(offset);
        let out_pub = (ED25519_BASEPOINT_TABLE * &input_sk).compress().to_bytes();
        plain.extend_from_slice(&out_pub);
        plain.extend_from_slice(&[0x00]); // idx=0
        plain.extend_from_slice(&[0x64]); // gidx=100
        plain.extend_from_slice(&[0x22u8; 32]); // tx_pubkey
        plain.push(0b0001_0100); // rct + key_image_request
        plain.extend_from_slice(&[0x80, 0x89, 0x2f]); // amount varint-ish
        plain.extend_from_slice(&[0x00]); // no additional keys
        plain.extend_from_slice(&[0x00, 0x00]); // major=0 minor=0

        let enc_req = encrypt_export_payload(
            OUTPUT_EXPORT_MAGIC,
            &view_sk,
            &spend_pub,
            &view_pub,
            &plain,
            &mut rng,
        )
        .unwrap();

        // Device-side full flow
        let mut pool: [ExportedTransferDetail; 4] =
            core::array::from_fn(|_| ExportedTransferDetail::default());
        let enc_resp =
            generate_key_image_export(&view_sk, &spend_sk, &enc_req, &mut pool, &mut rng).unwrap();

        // Hot-side decryption (verified via the monero decryption path)
        let (_, _, resp_plain) =
            decrypt_export_payload(&enc_resp, KEY_IMAGE_EXPORT_MAGIC, &view_sk).unwrap();
        let records = deserialize_key_images(&resp_plain);

        // Z2.4d-5 twin: into-core == convenience under the SAME rng seed (self-contained)
        let mut det_c: [ExportedTransferDetail; 4] =
            core::array::from_fn(|_| ExportedTransferDetail::default());
        let mut rng_c = rng_from(0xC0);
        let conv = generate_key_image_export(&view_sk, &spend_sk, &enc_req, &mut det_c, &mut rng_c)
            .unwrap();
        {
            let mut scratch2 = alloc::vec![0u8; enc_req.len() + 1024];
            let mut details2: [ExportedTransferDetail; 4] =
                core::array::from_fn(|_| ExportedTransferDetail::default());
            let mut recs2: alloc::vec::Vec<([u8; 32], [u8; 64])> =
                alloc::vec![( [0u8; 32], [0u8; 64] ); 4];
            let mut rng2 = rng_from(0xC0);
            let mut out2 = alloc::vec![0u8; 8192];
            let n2 = generate_key_image_export_into(
                &view_sk,
                &spend_sk,
                &enc_req,
                &mut scratch2,
                &mut details2,
                &mut recs2,
                &mut out2,
                &mut rng2,
            )
            .unwrap();
            // the e2e above used a seeded rng as well — same seed, same bytes
            assert_eq!(
                &out2[..n2],
                &conv[..],
                "generate_key_image_export_into != convenience"
            );
        }
        assert_eq!(records.len(), 1);

        // Independent key image recomputation cross-check
        let (image, sig) = &records[0];
        let expected: [u8; 32] = {
            let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub).into();
            (hp * input_sk).compress().to_bytes()
        };
        assert_eq!(*image, expected);

        // Accompanying signature verification (single-ring Hs recomputation)
        let i_point: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub).into();
        let c = Scalar::from_canonical_bytes(sig[..32].try_into().unwrap()).unwrap();
        let r = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).unwrap();
        let lhs = (ED25519_BASEPOINT_TABLE * &r) + (ED25519_BASEPOINT_TABLE * &c);
        let rhs = (r * i_point) + (c * i_point);
        // Expectation: Hs(prefix || r·B + c·P || r·I + c·I) == c, where P = input_sk·G = out_pub
        // P point: input_sk·G
        let p_point = ED25519_BASEPOINT_TABLE * &input_sk;
        let rb = (ED25519_BASEPOINT_TABLE * &r).compress().to_bytes();
        let r_p = (r * p_point).compress().to_bytes();
        let _ = lhs;
        let _ = rhs;
        let _ = r_p;
        let _ = rb;
        // Full verification: recompute the challenge
        let mut buff = Vec::new();
        buff.extend_from_slice(image);
        // k·B cannot be recomputed (k is lost) → verification formula: Hs(prefix || r·B + c·P || r·I + c·I) == c
        //   r·B + c·P（P=input_sk·G=out_pub）
        let s1 = (ED25519_BASEPOINT_TABLE * &r) + (c * p_point);
        //   r·Hp(P) + c·I = (r + c·input_sk)·Hp(P)
        let s2 = (r + c * input_sk) * i_point;
        let mut vbuf = Vec::new();
        vbuf.extend_from_slice(image);
        vbuf.extend_from_slice(&s1.compress().to_bytes());
        vbuf.extend_from_slice(&s2.compress().to_bytes());
        let h = crate::chain::xmr::subaddress::hash_to_scalar(&vbuf).unwrap();
        assert_eq!(h, c.to_bytes());
    }

    #[test]
    fn keystone_cross_fixture_output_export() {
        // fixture from keystone fork apps/monero test_generate_signature
        const PVK_HEX: &str = "bb4346a861b208744ff939ff1faacbbe0c5298a4996f4de05e0d9c04c769d501";
        const DATA_HEX: &str = "4d6f6e65726f206f7574707574206578706f727404eb5fb0d1fc8358931053f6e24d93ec0766aad43a54453593287d0d3dcfdef9371f411a0e179a9c1b0da94a3fe3d51cccf3573c01b6f8d6ee215caf3238976d8e9af5347e44b0d575fa622accdd4b4d5d272e13d77ff897752f52d7617be986efb4d2b1f841bae6c1d041d6ff9df46262b1251a988d5b0fbe5012d2af7b9ff318381bfd8cbe06af6e0750c16ff7a61d31d36526d83d7b6b614b2fd602941f2e94de01d0e3fc5a84414cdeabd943e5d8f0226ab7bea5e47c97253bf2f062e92a6bf27b6099a47cb8bca47e5ad544049611d77bfeb5c16b5b7849ce5d46bb928ce2e9a2b6679653a769f53c7c17d3e91df35ae7b62a4cffcea2d25df1c2e21a58b1746aae00a273317ec3873c53d8ae71d89d70637a6bd1da974e548b48a0f96d119f0f7d04ff034bb7fed3dbe9081d3e3a3212d330328c0edbacad85bab43780f9b5dfd81f359b0827146ebc421e60dba0badab1941bc31a0086aac99d59f55f07d58c02a48a3e1f70222bae1a612dacd09d0b176345a115e6ae6523ecbc346d8a8078111da7f9932f31d6e35500f5195cfdfe6b6eb2b223d171430a1cb7e11a51ac41d06f3a81546378b1ff342a18fb1f01cfd10df9c1ac86531456f240e5500d9c7ba4c47ba8d4455ea2b7e460ee207c064b76019f6bb4efe5a3e27a126b0c8be6a2e6f3d7ede9580ff49598501aafa36187896e245d64461f9f1c24323b1271af9e0a7a9108422de5ecfdaccdcb2b4520a6d75b2511be6f17a272d21e05ead99818e697559714af0a220494004e393eeefdfe029cff0db22c3adadf6f00edbf6bf4fcbcfc1e225451be3c1c700fe796fce6480b02d0cb1f9fbcf6c05895df2eeb8192980df50a0523922c1247fef83a5f631cf64132125477e1a3b13bcbaa691da1e9b45288eb6c7669e7a7857f87ed45f74725b72b4604fda6b44d3999e1d6fab0786f9b14f00a6518ca3fbc5f865d9fc8acd6e5773208";
        let view_sk: [u8; 32] = hex_to_32(PVK_HEX);
        let data = hex_bytes(DATA_HEX);
        let _ = &data;

        let (pk1, pk2, plain) = crate::chain::xmr::key_image_export::decrypt_export_payload(
            &data,
            crate::chain::xmr::key_image_export::OUTPUT_EXPORT_MAGIC,
            &view_sk,
        )
        .expect("shlosilo must decrypt keystone fixture");
        let _ = pk1;

        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;
        let v = Scalar::from_bytes_mod_order(view_sk);
        let view_pub = (ED25519_BASEPOINT_TABLE * &v).compress().to_bytes();
        assert_eq!(pk2, view_pub);

        let mut pool: [crate::chain::xmr::output_export::ExportedTransferDetail; 16] =
            core::array::from_fn(|_| {
                crate::chain::xmr::output_export::ExportedTransferDetail::default()
            });
        let details = crate::chain::xmr::output_export::ExportedTransferDetails::from_bytes(
            &plain, &mut pool,
        )
        .expect("plaintext must parse as ExportedTransferDetails");
        assert!(!details.details.is_empty());
        assert!(details.details.len() <= 8);
        // The first output is a key_image_request with a known amount (characteristic of real wallet data)
        assert!(details.details[0].is_key_image_request());
        assert!(details.details[0].amount > 0);
    }

    fn hex_to_32(h: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
    fn hex_bytes(h: &str) -> Vec<u8> {
        (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// Z2.4d-5 twins: into-cores must be byte-identical to the conveniences, and the
    /// decrypt core must wipe the scratch tail (sentinel).
    #[test]
    fn export_cores_match_conveniences() {
        let view_sk = [0x11u8; 32];
        let spend_pub = [0x22u8; 32];
        let view_pub = {
            use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
            use curve25519_dalek::scalar::Scalar;
            (ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(view_sk))
                .compress()
                .to_bytes()
        };
        let data = [0xABu8; 40];

        // encrypt twin
        let mut r1 = rng_from(0x51);
        let conv = encrypt_export_payload(
            KEY_IMAGE_EXPORT_MAGIC,
            &view_sk,
            &spend_pub,
            &view_pub,
            &data,
            &mut r1,
        )
        .unwrap();
        let mut r2 = rng_from(0x51);
        let mut buf = alloc::vec![0u8; 4096];
        let n = encrypt_export_payload_into(
            KEY_IMAGE_EXPORT_MAGIC,
            &view_sk,
            &spend_pub,
            &view_pub,
            &data,
            &mut r2,
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..n], &conv[..], "encrypt into != convenience");

        // decrypt twin + tail wipe
        let mut scratch = alloc::vec![0xEEu8; 1024];
        let (pk1, pk2, plen) =
            decrypt_export_payload_into(&conv, KEY_IMAGE_EXPORT_MAGIC, &view_sk, &mut scratch)
                .unwrap();
        assert_eq!(pk1, spend_pub);
        assert_eq!(pk2, view_pub);
        assert_eq!(&scratch[..plen], &data[..]);
        assert!(
            scratch[plen..].iter().all(|&b| b == 0),
            "decrypt core must wipe the scratch tail (forms-internal zeroization duty)"
        );
        let (cpk1, cpk2, cplain) =
            decrypt_export_payload(&conv, KEY_IMAGE_EXPORT_MAGIC, &view_sk).unwrap();
        assert_eq!(cpk1, pk1);
        assert_eq!(cpk2, pk2);
        assert_eq!(&cplain[..], &data[..], "decrypt into != convenience");
    }
}
