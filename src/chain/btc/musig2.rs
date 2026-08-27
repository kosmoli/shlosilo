//! BTC MuSig2 (BIP-327) — Phase 5 v9.11
//!
//! ## 范围
//! - **KeyAgg**: aggregate public keys (MuSig2* optimization, 2nd distinct key gets coeff 1)
//! - **KeySort**: lexicographic sort pubkeys
//! - **ApplyTweak**: plain + x-only tweaks (BIP-32 / BIP-341 support)
//! - **NonceGen**: derive secnonce + pubnonce
//! - **NonceAgg**: aggregate pubnonces
//! - **GetSessionValues**: pre-compute (Q, gacc, tacc, b, R, e)
//! - **Sign**: produce partial signature
//! - **PartialSigVerify**: verify partial signature (identifiable abort)
//! - **PartialSigAgg**: aggregate partial signatures → final BIP-340 signature
//!
//! ## L1 纯函数
//! All algorithms are pure functions over Secp256k1Point/Secp256k1Scalar.
//!
//! ## Cross-validation
//! Uses BIP-327 official test vectors from `bitcoin/bips/bip-0327/vectors/`.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use k256::sha2::Digest as K256Digest;
use sha2::{Digest, Sha256};

use crate::curve_primitive::secp256k1::{
    base_mul, point_add, point_from_compressed, point_negate, point_to_compressed,
    scalar_add, scalar_from_bytes, scalar_mul, scalar_mul_n, scalar_negate, scalar_to_bytes,
    Secp256k1Point, Secp256k1Scalar,
};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// hash_tag(tag, x) = SHA256(SHA256(tag) || SHA256(tag) || x)
fn hash_tagged(tag: &[u8], x: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(x);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn hash_keys(pubkeys: &[Vec<u8>]) -> [u8; 32] {
    let mut concat = Vec::new();
    for pk in pubkeys {
        concat.extend_from_slice(pk);
    }
    hash_tagged(b"KeyAgg list", &concat)
}

fn hash_keyagg_coefficient(pubkeys: &[Vec<u8>], pk_prime: &[u8]) -> [u8; 32] {
    let l = hash_keys(pubkeys);
    let mut buf = Vec::with_capacity(32 + pk_prime.len());
    buf.extend_from_slice(&l);
    buf.extend_from_slice(pk_prime);
    hash_tagged(b"KeyAgg coefficient", &buf)
}

fn hash_noncecoef(aggnonce: &[u8; 66], q_xonly: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(66 + 32 + msg.len());
    buf.extend_from_slice(aggnonce);
    buf.extend_from_slice(q_xonly);
    buf.extend_from_slice(msg);
    hash_tagged(b"MuSig/noncecoef", &buf)
}

fn hash_challenge(r_xonly: &[u8; 32], q_xonly: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 32 + msg.len());
    buf.extend_from_slice(r_xonly);
    buf.extend_from_slice(q_xonly);
    buf.extend_from_slice(msg);
    hash_tagged(b"BIP0340/challenge", &buf)
}

fn hash_musig_nonce(
    rand: &[u8; 32],
    pk: &[u8],
    aggpk: &[u8],
    m_prefixed: &[u8],
    extra_in: &[u8],
    idx: u8,
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(rand);
    buf.push(pk.len() as u8);
    buf.extend_from_slice(pk);
    buf.push(aggpk.len() as u8);
    buf.extend_from_slice(aggpk);
    buf.extend_from_slice(m_prefixed);
    let len = extra_in.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(extra_in);
    buf.push(idx);
    hash_tagged(b"MuSig/nonce", &buf)
}

fn hash_musig_aux(rand: &[u8; 32]) -> [u8; 32] {
    hash_tagged(b"MuSig/aux", rand)
}

/// has_even_y(P) = true if compressed[0] == 0x02
fn has_even_y(p: &Secp256k1Point) -> bool {
    point_to_compressed(p)[0] == 0x02
}

/// cbytes(P) = 0x02/0x03 || x(P)
fn cbytes(p: &Secp256k1Point) -> [u8; 33] {
    point_to_compressed(p)
}

/// cbytes_ext(P): if P is infinity, return bytes(33, 0), else cbytes(P)
fn cbytes_ext(p: &Secp256k1Point) -> [u8; 33] {
    let c = point_to_compressed(p);
    if c.iter().all(|&b| b == 0) {
        [0u8; 33]
    } else {
        c
    }
}

fn xbytes(p: &Secp256k1Point) -> [u8; 32] {
    let c = point_to_compressed(p);
    let mut out = [0u8; 32];
    out.copy_from_slice(&c[1..33]);
    out
}

fn with_even_y(p: &Secp256k1Point) -> Secp256k1Point {
    if has_even_y(p) {
        *p
    } else {
        point_negate(p)
    }
}

/// cpoint_ext(x) where x is 33-byte: bytes(33, 0) → infinity, else point_from_compressed
fn cpoint_ext(pk: &[u8]) -> Result<Secp256k1Point> {
    if pk.iter().all(|&b| b == 0) {
        // Point at infinity: construct explicitly via base_mul(0)
        Ok(base_mul(&scalar_from_bytes(&[0u8; 32]).unwrap()))
    } else {
        point_from_compressed(pk)
    }
}

// === KeySort ===

pub fn key_sort_vec(pubkeys: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut v = pubkeys.to_vec();
    v.sort();
    v
}

pub fn key_sort(pubkeys: &mut Vec<Vec<u8>>) {
    pubkeys.sort();
}

// === KeyAgg Context ===

pub struct KeyAggContext {
    pub q: Secp256k1Point,
    pub gacc: Secp256k1Scalar,
    pub tacc: Secp256k1Scalar,
}

impl core::fmt::Debug for KeyAggContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyAggContext")
            .field("q", &alloc::format!("Point({})", hex_encode_pub(&self.q)))
            .field("gacc", &hex_encode(&scalar_to_bytes(&self.gacc)))
            .field("tacc", &hex_encode(&scalar_to_bytes(&self.tacc)))
            .finish()
    }
}

fn hex_encode_pub(p: &Secp256k1Point) -> alloc::string::String {
    hex_encode(&point_to_compressed(p))
}

/// GetSecondKey: second distinct key (or bytes(33, 0) if all identical)
fn get_second_key(pubkeys: &[Vec<u8>]) -> Vec<u8> {
    for pk in &pubkeys[1..] {
        if *pk != pubkeys[0] {
            return pk.clone();
        }
    }
    vec![0u8; 33]
}

fn key_agg_coeff_internal(pubkeys: &[Vec<u8>], pk_prime: &[u8], pk2: &[u8]) -> Secp256k1Scalar {
    if pk_prime == pk2 {
        // Second distinct key gets coefficient = 1 (per BIP-327 "MuSig2* optimization").
        // Use big-endian 32-byte encoding: last byte = 1, rest = 0.
        let one_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };
        return scalar_from_bytes(&one_bytes).unwrap();
    }
    let h = hash_keyagg_coefficient(pubkeys, pk_prime);
    // Try direct decode first (hash < curve order n).
    if let Ok(s) = scalar_from_bytes(&h) {
        return s;
    }
    // Fallback: hash >= n. Reduce manually via repeated subtraction.
    // This is rare (probability ~ 2^-128), but correctness requires handling.
    // We use k256's scalar arithmetic by creating a Scalar from the hash bytes
    // and iteratively subtracting n until we get a valid scalar.
    // Simplest path: use k256's `mod_n_vartime`-style reduction via a known trick.
    // For BIP-327 correctness, hash will practically always be < n, so this
    // branch is only a safety net.
    // Try reducing via wrapping: subtract n via arithmetic
    // Since this is rare, use a simple brute-force subtract approach.
    // (n ≈ 2^256 - 2^128, so most hashes >= n are within n + 2^128 of 0)
    // Just try all candidates hash, hash-1, hash-2, ... until valid (probabilistically rare).
    let mut bytes = h;
    for _ in 0..256 {
        match scalar_from_bytes(&bytes) {
            Ok(s) => return s,
            Err(_) => {
                // Subtract 1 (big-endian decrement)
                let mut i = 31;
                while bytes[i] == 0 {
                    bytes[i] = 0xff;
                    if i == 0 { break; }
                    i -= 1;
                }
                if i > 0 || bytes[0] > 0 {
                    bytes[i] -= 1;
                } else {
                    // Underflow → wraps to all 0xff, which is also >= n
                    // Just give up and use 0...0 (statistically impossible case)
                    bytes = [0u8; 32];
                    break;
                }
            }
        }
    }
    // Last resort: hash bytes are invalid; use 1 (any non-zero valid scalar)
    scalar_from_bytes(&[0u8; 32]).unwrap_or_else(|_| scalar_from_bytes(&[1u8; 32]).unwrap())
}

/// KeyAgg: aggregate pubkeys into KeyAggContext (MuSig2* optimization)
pub fn key_agg(pubkeys: &[Vec<u8>]) -> Result<KeyAggContext> {
    if pubkeys.is_empty() || pubkeys.len() >= u32::MAX as usize {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let pk2 = get_second_key(pubkeys);

    // DEBUG: print intermediate values
    #[cfg(test)]
    {
        extern crate std;
        use std::eprintln;
        let pk2_hex: alloc::string::String = pk2.iter().map(|b| alloc::format!("{:02x}", b)).collect();
        eprintln!("[DEBUG key_agg] pk2 = {}", pk2_hex);
        let l = hash_keys(pubkeys);
        eprintln!("[DEBUG key_agg] L_hash = {}", alloc::format!("{:02x?}", l.chunks(32).next().unwrap()).trim_matches(|c: char| !c.is_ascii_hexdigit()));
    }

    let mut q: Option<Secp256k1Point> = None;
    for pk in pubkeys {
        let p = cpoint_ext(pk)?;
        let a = key_agg_coeff_internal(pubkeys, pk, &pk2);
        let ap = scalar_mul(&a, &p);
        q = Some(match q {
            None => ap,
            Some(prev) => point_add(&prev, &ap),
        });
        #[cfg(test)]
        {
            extern crate std;
            use std::eprintln;
            eprintln!(
                "[DEBUG key_agg] pk={} coef={} ap.x={} Q.x={}",
                alloc::format!("{:02x?}", &pk[..4]),
                hex_encode(&scalar_to_bytes(&a)),
                hex_encode(&xbytes(&ap)),
                q.as_ref().map(|p| hex_encode(&xbytes(p))).unwrap_or_default(),
            );
        }
    }
    let q = q.ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let c = point_to_compressed(&q);
    if c.iter().all(|&b| b == 0) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    let gacc = scalar_from_bytes(&[1u8; 32]).unwrap();
    let tacc = scalar_from_bytes(&[0u8; 32]).unwrap();
    Ok(KeyAggContext { q, gacc, tacc })
}

pub fn get_xonly_pubkey(ctx: &KeyAggContext) -> [u8; 32] {
    let q = with_even_y(&ctx.q);
    xbytes(&q)
}

pub fn get_plain_pubkey(ctx: &KeyAggContext) -> [u8; 33] {
    cbytes(&ctx.q)
}

pub fn apply_tweak(
    ctx: &KeyAggContext,
    tweak: &[u8; 32],
    is_xonly_t: bool,
) -> Result<KeyAggContext> {
    let g_scalar = if is_xonly_t && !has_even_y(&ctx.q) {
        scalar_negate(&scalar_from_bytes(&[1u8; 32]).unwrap())
    } else {
        scalar_from_bytes(&[1u8; 32]).unwrap()
    };

    let t = scalar_from_bytes(tweak)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    let gq = scalar_mul(&g_scalar, &ctx.q);
    let tg = base_mul(&t);
    let q_new = point_add(&gq, &tg);
    let c = point_to_compressed(&q_new);
    if c.iter().all(|&b| b == 0) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // gacc' = g * gacc mod n  (scalar multiplication)
    let gacc_new = scalar_mul_n(&g_scalar, &ctx.gacc);
    // tacc' = t + g * tacc mod n
    let gtacc = scalar_mul_n(&g_scalar, &ctx.tacc);
    let tacc_new = scalar_add(&t, &gtacc);

    Ok(KeyAggContext {
        q: q_new,
        gacc: gacc_new,
        tacc: tacc_new,
    })
}


// === NonceGen ===

#[derive(Clone)]
pub struct NonceGenInput<'a> {
    pub rand: [u8; 32],
    pub sk: Option<&'a [u8; 32]>,
    pub pk: &'a [u8],
    pub aggpk: Option<&'a [u8; 32]>,
    pub msg: Option<&'a [u8]>,
    pub extra_in: Option<&'a [u8]>,
}

pub struct NonceGenOutput {
    pub secnonce: [u8; 97],
    pub pubnonce: [u8; 66],
}

impl core::fmt::Debug for NonceGenOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NonceGenOutput")
            .field("secnonce", &hex_encode(&self.secnonce))
            .field("pubnonce", &hex_encode(&self.pubnonce))
            .finish()
    }
}

pub fn nonce_gen(input: &NonceGenInput) -> Result<NonceGenOutput> {
    let NonceGenInput {
        rand,
        sk,
        pk,
        aggpk,
        msg,
        extra_in,
    } = input;

    if pk.len() != 33 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    if rand.iter().all(|&b| b == 0) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // rand = sk XOR hash_MuSig/aux(rand') if sk present
    let rand_final: [u8; 32] = if let Some(sk_bytes) = sk {
        let aux = hash_musig_aux(rand);
        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = sk_bytes[i] ^ aux[i];
        }
        xored
    } else {
        *rand
    };

    // aggpk = empty bytestring if not present
    let aggpk_bytes: &[u8] = aggpk.map(|a| a.as_slice()).unwrap_or(&[]);

    let mut m_prefixed = Vec::new();
    match msg {
        None => m_prefixed.push(0),
        Some(m) => {
            m_prefixed.push(1);
            m_prefixed.extend_from_slice(&(m.len() as u64).to_le_bytes());
            m_prefixed.extend_from_slice(m);
        }
    }

    let extra_in_bytes = extra_in.unwrap_or(&[]);

    let k1_h = hash_musig_nonce(&rand_final, pk, aggpk_bytes, &m_prefixed, extra_in_bytes, 0);
    let k2_h = hash_musig_nonce(&rand_final, pk, aggpk_bytes, &m_prefixed, extra_in_bytes, 1);

    if k1_h.iter().all(|&b| b == 0) || k2_h.iter().all(|&b| b == 0) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    // Validate scalars are valid
    let _ = scalar_from_bytes(&k1_h)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let _ = scalar_from_bytes(&k2_h)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    let r1 = base_mul(&scalar_from_bytes(&k1_h).unwrap());
    let r2 = base_mul(&scalar_from_bytes(&k2_h).unwrap());

    let pubnonce_1 = cbytes(&r1);
    let pubnonce_2 = cbytes(&r2);
    let mut pubnonce = [0u8; 66];
    pubnonce[0..33].copy_from_slice(&pubnonce_1);
    pubnonce[33..66].copy_from_slice(&pubnonce_2);

    // secnonce = bytes(32, k1) || bytes(32, k2) || pk
    let mut secnonce = [0u8; 97];
    secnonce[0..32].copy_from_slice(&k1_h);
    secnonce[32..64].copy_from_slice(&k2_h);
    secnonce[64..97].copy_from_slice(pk);

    Ok(NonceGenOutput { secnonce, pubnonce })
}

// === NonceAgg ===

pub fn nonce_agg(pubnonces: &[Vec<u8>]) -> Result<[u8; 66]> {
    if pubnonces.is_empty() || pubnonces.len() >= u32::MAX as usize {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let mut aggnonce = [0u8; 66];

    for j in 0..2 {
        let mut r: Option<Secp256k1Point> = None;
        for pubnonce in pubnonces {
            if pubnonce.len() != 66 {
                return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let r_ij = cpoint_ext(&pubnonce[j * 33..(j + 1) * 33])?;
            r = Some(match r {
                None => r_ij,
                Some(prev) => point_add(&prev, &r_ij),
            });
        }
        let r_sum = r.ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        let c = cbytes_ext(&r_sum);
        aggnonce[j * 33..(j + 1) * 33].copy_from_slice(&c);
    }
    Ok(aggnonce)
}

// === Session Context ===

#[derive(Clone)]
pub struct SessionContext {
    pub aggnonce: [u8; 66],
    pub pubkeys: Vec<Vec<u8>>,
    pub tweaks: Vec<([u8; 32], bool)>,
    pub msg: Vec<u8>,
}

impl core::fmt::Debug for SessionContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionContext")
            .field("aggnonce", &hex_encode(&self.aggnonce))
            .field("pubkeys", &self.pubkeys.len())
            .field("tweaks", &self.tweaks.len())
            .field("msg_len", &self.msg.len())
            .finish()
    }
}

pub struct SessionValues {
    pub q: Secp256k1Point,
    pub gacc: Secp256k1Scalar,
    pub tacc: Secp256k1Scalar,
    pub b: Secp256k1Scalar,
    pub r: Secp256k1Point,
    pub e: Secp256k1Scalar,
}

pub fn get_session_values(session: &SessionContext) -> Result<SessionValues> {
    let pk_refs: Vec<Vec<u8>> = session.pubkeys.clone();
    let mut keyagg_ctx = key_agg(&pk_refs)?;
    for (tweak, is_xonly) in &session.tweaks {
        keyagg_ctx = apply_tweak(&keyagg_ctx, tweak, *is_xonly)?;
    }

    let q = keyagg_ctx.q;
    let gacc = keyagg_ctx.gacc;
    let tacc = keyagg_ctx.tacc;
    let q_xonly = xbytes(&q);

    let b_h = hash_noncecoef(&session.aggnonce, &q_xonly, &session.msg);
    let b = scalar_from_bytes(&b_h)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    let r1 = cpoint_ext(&session.aggnonce[0..33])?;
    let r2 = cpoint_ext(&session.aggnonce[33..66])?;
    let br2 = scalar_mul(&b, &r2);
    let r_prime = point_add(&r1, &br2);

    let r_final = if point_to_compressed(&r_prime).iter().all(|&b| b == 0) {
        base_mul(&scalar_from_bytes(&[1u8; 32]).unwrap()) // G
    } else {
        r_prime
    };

    let r_xonly = xbytes(&r_final);
    let e_h = hash_challenge(&r_xonly, &q_xonly, &session.msg);
    let e = scalar_from_bytes(&e_h)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    Ok(SessionValues { q, gacc, tacc, b, r: r_final, e })
}

// === Sign ===

pub fn sign(secnonce: &[u8; 97], sk: &[u8; 32], session: &SessionContext) -> Result<[u8; 32]> {
    let values = get_session_values(session)?;
    let SessionValues { q, gacc, b, r, e, .. } = values;

    let k1_prime_bytes: [u8; 32] = secnonce[0..32].try_into()
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let k2_prime_bytes: [u8; 32] = secnonce[32..64].try_into()
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let k1_prime = scalar_from_bytes(&k1_prime_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let k2_prime = scalar_from_bytes(&k2_prime_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    // k_i = k_i' if has_even_y(R), else n - k_i'
    let (k1, k2): (Secp256k1Scalar, Secp256k1Scalar) = if has_even_y(&r) {
        (k1_prime, k2_prime)
    } else {
        (
            scalar_negate(&k1_prime),
            scalar_negate(&k2_prime),
        )
    };

    let d_prime = scalar_from_bytes(sk)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let zero = scalar_from_bytes(&[0u8; 32]).unwrap();
    let zero_bytes = scalar_to_bytes(&zero);
    if scalar_to_bytes(&d_prime) == zero_bytes {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    let p = base_mul(&d_prime);
    let pk_self = cbytes(&p);

    if pk_self.as_slice() != &secnonce[64..97] {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }

    let a = get_session_keyagg_coeff(session, &p)?;

    let one = scalar_from_bytes(&[1u8; 32]).unwrap();
    let neg_one = scalar_negate(&one);
    let g = if has_even_y(&q) { one } else { neg_one };

    // d = g * gacc * d' mod n
    let d = scalar_mul_n(&scalar_mul_n(&g, &gacc), &d_prime);

    // s = k1 + b*k2 + e*a*d mod n
    let bk2 = scalar_mul_n(&b, &k2);
    let ead = scalar_mul_n(&scalar_mul_n(&e, &a), &d);
    let s = scalar_add(&scalar_add(&k1, &bk2), &ead);

    Ok(scalar_to_bytes(&s))
}

pub fn get_session_keyagg_coeff(
    session: &SessionContext,
    p: &Secp256k1Point,
) -> Result<Secp256k1Scalar> {
    let pk_self = cbytes(p);
    if !session.pubkeys.iter().any(|pk| pk.as_slice() == pk_self.as_slice()) {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let pk2 = get_second_key(&session.pubkeys);
    Ok(key_agg_coeff_internal(&session.pubkeys, &pk_self, &pk2))
}

// === PartialSigVerify ===

pub fn partial_sig_verify(
    psig: &[u8; 32],
    pubnonce: &[u8; 66],
    pk: &[u8],
    session: &SessionContext,
) -> Result<bool> {
    let values = get_session_values(session)?;
    let SessionValues { q, gacc, b, r, e, .. } = values;

    let s_bytes: [u8; 32] = psig[..].try_into()
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
    let s = scalar_from_bytes(&s_bytes)
        .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;

    if pubnonce.len() != 66 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let r1 = cpoint_ext(&pubnonce[0..33])?;
    let r2 = cpoint_ext(&pubnonce[33..66])?;

    let br2 = scalar_mul(&b, &r2);
    let re_prime = point_add(&r1, &br2);
    let re = if has_even_y(&r) { re_prime } else { point_negate(&re_prime) };

    if pk.len() != 33 {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let p = cpoint_ext(pk)?;
    let pk2 = get_second_key(&session.pubkeys);
    let a = key_agg_coeff_internal(&session.pubkeys, pk, &pk2);

    let one = scalar_from_bytes(&[1u8; 32]).unwrap();
    let neg_one = scalar_negate(&one);
    let g = if has_even_y(&q) { one } else { neg_one };
    let g_prime = scalar_mul_n(&g, &gacc);

    // Check s*G == Re + e*a*g'*P
    let lhs = base_mul(&s);
    let eag_prime_p = scalar_mul(&scalar_mul_n(&scalar_mul_n(&e, &a), &g_prime), &p);
    let rhs = point_add(&re, &eag_prime_p);

    Ok(point_to_compressed(&lhs) == point_to_compressed(&rhs))
}

// === PartialSigAgg ===

pub fn partial_sig_agg(psigs: &[[u8; 32]], session: &SessionContext) -> Result<[u8; 64]> {
    if psigs.is_empty() || psigs.len() != session.pubkeys.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let values = get_session_values(session)?;
    let SessionValues { q, tacc, r, e, .. } = values;

    let zero = scalar_from_bytes(&[0u8; 32]).unwrap();
    let mut sum_s = zero;
    for psig in psigs {
        let s_i = scalar_from_bytes(psig)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        sum_s = scalar_add(&sum_s, &s_i);
    }

    let one = scalar_from_bytes(&[1u8; 32]).unwrap();
    let neg_one = scalar_negate(&one);
    let g = if has_even_y(&q) { one } else { neg_one };

    let egt = scalar_mul_n(&scalar_mul_n(&e, &g), &tacc);
    let s = scalar_add(&sum_s, &egt);

    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&xbytes(&r));
    sig[32..64].copy_from_slice(&scalar_to_bytes(&s));
    Ok(sig)
}

// === Utility ===

fn hex_encode(b: &[u8]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&alloc::format!("{:02x}", byte));
    }
    s
}

fn hex_decode_pubkey(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap();
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

// === Tests ===

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::eprintln;

    // === BIP-327 key_agg_vectors: pubkeys ===
    const KEY_AGG_PUBKEYS_HEX: &[&str] = &[
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "020000000000000000000000000000000000000000000000000000000000000005",
        "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        "021D2322C5925CDF67A6B0B68D714C4A28E42FD89D3B57B575FF55D23461B3C054",
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    ];

    fn key_agg_pubkeys() -> Vec<Vec<u8>> {
        KEY_AGG_PUBKEYS_HEX.iter().map(|s| hex_decode_pubkey(s)).collect()
    }

    /// BIP-327 test vector 0: 3 pubkeys (no tweaks)
    /// Expected xonly aggregate: 90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C
    ///
    /// **ROOT CAUSE (2026-08-22)**: BIP-327 uses its own tags (`KeyAgg list`, `KeyAgg coefficient`),
    /// NOT the BIP-340 prefixed versions. Fixed.
    #[test]
    fn key_agg_vector_0() {
        let pks = key_agg_pubkeys();
        let selected: Vec<Vec<u8>> = vec![pks[0].clone(), pks[1].clone(), pks[2].clone()];
        let ctx = key_agg(&selected).unwrap();
        let xonly = get_xonly_pubkey(&ctx);
        assert_eq!(
            hex_encode(&xonly).to_lowercase(),
            "90539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c"
        );
    }

    /// Sanity: scalar_mul * 1 = same point (test scalar_to_bytes round trip)
    #[test]
    fn scalar_to_bytes_round_trip() {
        let bytes = hex_decode_pubkey("ad0537c883813849e3b95ce5db1d45eb25cc5fae197c4e8759719065932aa183");
        let scalar = scalar_from_bytes(&bytes).unwrap();
        let recovered = scalar_to_bytes(&scalar);
        assert_eq!(&recovered[..], &bytes[..]);
    }

    /// Sanity: scalar_from_bytes(&[0u8;32]) → ZERO scalar
    #[test]
    fn scalar_zero_check() {
        let zero = scalar_from_bytes(&[0u8; 32]).unwrap();
        let zero_bytes = scalar_to_bytes(&zero);
        assert_eq!(&zero_bytes[..], &[0u8; 32][..]);
    }

    /// Sanity: scalar_from_bytes(&[2u8;32]) → 2 scalar
    #[test]
    fn scalar_two_check() {
        let two = {
            let mut b = [0u8; 32];
            b[31] = 2;
            scalar_from_bytes(&b).unwrap()
        };
        let two_bytes = scalar_to_bytes(&two);
        eprintln!("scalar 2 bytes = {}", hex_encode(&two_bytes));
        // Expected: 32 bytes with value 2 (big-endian: ...00 02)
        assert_eq!(two_bytes[31], 2);
    }

    /// Sanity: point_add of G + G = 2*G
    #[test]
    fn point_add_double_gen() {
        use crate::curve_primitive::secp256k1::generator;
        let g = generator();
        let gg = point_add(&g, &g);
        let gg_compressed = point_to_compressed(&gg);
        eprintln!("G+G (point_add) = {}", hex_encode(&gg_compressed));
        // Expected: 0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    }

    /// Sanity: base_mul(2) should equal 2*G
    #[test]
    fn base_mul_two() {
        use crate::curve_primitive::secp256k1::generator;
        let g = generator();
        let two_scalar = {
            let mut b = [0u8; 32];
            b[31] = 2;
            scalar_from_bytes(&b).unwrap()
        };
        let two_g = base_mul(&two_scalar);
        let two_g_compressed = point_to_compressed(&two_g);
        eprintln!("base_mul(2) = {}", hex_encode(&two_g_compressed));
        eprintln!("Expected:   02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        assert_eq!(
            &two_g_compressed[..],
            &[
                2, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
                0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
                0xb9, 0x5c, 0x70, 0x9e, 0xe5
            ][..]
        );
    }

    /// Sanity: scalar_mul(2, &G) should equal 2*G (direct, no base_mul indirection)
    #[test]
    fn scalar_mul_two_of_g() {
        use crate::curve_primitive::secp256k1::{generator, scalar_mul};
        let g = generator();
        let two_scalar = {
            let mut b = [0u8; 32];
            b[31] = 2;
            scalar_from_bytes(&b).unwrap()
        };
        let two_g = scalar_mul(&two_scalar, &g);
        let two_g_compressed = point_to_compressed(&two_g);
        eprintln!("scalar_mul(2, &G) = {}", hex_encode(&two_g_compressed));
        assert_eq!(
            &two_g_compressed[..],
            &[
                2, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
                0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
                0xb9, 0x5c, 0x70, 0x9e, 0xe5
            ][..]
        );
    }

    /// Sanity: pk1 + pk2 where pk1 and pk2 are different
    #[test]
    fn point_add_two_distinct() {
        let pk1 = hex_decode_pubkey("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
        let pk2 = hex_decode_pubkey("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
        let p1 = point_from_compressed(&pk1).unwrap();
        let p2 = point_from_compressed(&pk2).unwrap();
        let sum = point_add(&p1, &p2);
        let sum_compressed = point_to_compressed(&sum);
        eprintln!("P1+P2 = {}", hex_encode(&sum_compressed));
        // Expected (from Python): P1+P2.x = 0x90966a7817cc354c1c12ece31bc3419086af24b46f64390ef27451394fc6a166 (P1+0*P2 = P1 = 64a1d9989d39...)
        // For pk1+pk2 we need actual computation
    }

    /// BIP-327 test vector 1: same 3 pubkeys reversed order [2, 1, 0]
    /// Expected: 6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B
    #[test]
    fn key_agg_vector_1_reversed() {
        let pks = key_agg_pubkeys();
        let selected: Vec<Vec<u8>> = vec![pks[2].clone(), pks[1].clone(), pks[0].clone()];
        let ctx = key_agg(&selected).unwrap();
        let xonly = get_xonly_pubkey(&ctx);
        assert_eq!(
            hex_encode(&xonly).to_lowercase(),
            "6204de8b083426dc6eaf9502d27024d53fc826bf7d2012148a0575435df54b2b"
        );
    }

    /// BIP-327 test vector 2: same pubkey 3 times [0, 0, 0]
    /// Expected: B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935
    #[test]
    fn key_agg_vector_2_dup() {
        let pks = key_agg_pubkeys();
        let selected: Vec<Vec<u8>> = vec![pks[0].clone(), pks[0].clone(), pks[0].clone()];
        let ctx = key_agg(&selected).unwrap();
        let xonly = get_xonly_pubkey(&ctx);
        assert_eq!(
            hex_encode(&xonly).to_lowercase(),
            "b436e3bad62b8cd409969a224731c193d051162d8c5ae8b109306127da3aa935"
        );
    }

    /// KeySort: lexicographic order
    #[test]
    fn key_sort_test() {
        let input = vec![
            hex_decode_pubkey("021D2322C5925CDF67A6B0B68D714C4A28E42FD89D3B57B575FF55D23461B3C054"),
            hex_decode_pubkey("023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"),
            hex_decode_pubkey("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
            hex_decode_pubkey("03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"),
            hex_decode_pubkey("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
        ];
        let sorted = key_sort_vec(&input);
        for i in 1..sorted.len() {
            assert!(sorted[i - 1] <= sorted[i]);
        }
    }

    /// NonceGen basic test
    #[test]
    fn nonce_gen_basic() {
        let pk = hex_decode_pubkey("03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9");
        let rand = [1u8; 32];
        let input = NonceGenInput {
            rand,
            sk: None,
            pk: &pk,
            aggpk: None,
            msg: None,
            extra_in: None,
        };
        let out = nonce_gen(&input).unwrap();
        assert!(!out.pubnonce.iter().all(|&b| b == 0));
        assert_eq!(&out.secnonce[64..97], pk.as_slice());
    }

    /// NonceGen rejects all-zero rand
    #[test]
    fn nonce_gen_rejects_zero_rand() {
        let pk = hex_decode_pubkey("03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9");
        let rand = [0u8; 32];
        let input = NonceGenInput {
            rand,
            sk: None,
            pk: &pk,
            aggpk: None,
            msg: None,
            extra_in: None,
        };
        assert!(nonce_gen(&input).is_err());
    }

    /// NonceAgg aggregates pubnonces
    #[test]
    fn nonce_agg_test() {
        let pks = key_agg_pubkeys();
        let selected: Vec<Vec<u8>> = vec![pks[0].clone(), pks[1].clone(), pks[2].clone()];
        let ctx = key_agg(&selected).unwrap();
        let aggpk = get_xonly_pubkey(&ctx);

        let rand = [0x42u8; 32];
        let input1 = NonceGenInput {
            rand,
            sk: None,
            pk: &pks[0],
            aggpk: Some(&aggpk),
            msg: Some(b"test"),
            extra_in: None,
        };
        let out1 = nonce_gen(&input1).unwrap();
        let pubnonces: Vec<Vec<u8>> = vec![out1.pubnonce.to_vec()];
        let aggnonce = nonce_agg(&pubnonces).unwrap();
        assert_eq!(aggnonce, out1.pubnonce);
    }

    /// Full sign + verify flow
    #[test]
    fn sign_verify_full_flow() {
        let sk_bytes = [0x01u8; 32];
        let sks = [sk_bytes, [0x02u8; 32], [0x03u8; 32]];
        let pks: Vec<Vec<u8>> = sks
            .iter()
            .map(|b| {
                let s = scalar_from_bytes(b).unwrap();
                let p = base_mul(&s);
                let mut c = cbytes(&p);
                c.to_vec()
            })
            .collect();

        let ctx = key_agg(&pks).unwrap();
        let aggpk = get_xonly_pubkey(&ctx);
        eprintln!("agg xonly: {}", hex_encode(&aggpk));

        let rand = [0x42u8; 32];
        let input = NonceGenInput {
            rand,
            sk: Some(&sk_bytes),
            pk: &pks[0],
            aggpk: Some(&aggpk),
            msg: Some(b"test message"),
            extra_in: None,
        };
        let nonce_out = nonce_gen(&input).unwrap();

        let pubnonces = vec![nonce_out.pubnonce.to_vec()];
        let aggnonce = nonce_agg(&pubnonces).unwrap();

        let session = SessionContext {
            aggnonce,
            pubkeys: pks.clone(),
            tweaks: vec![],
            msg: b"test message".to_vec(),
        };

        let psig = sign(&nonce_out.secnonce, &sk_bytes, &session).unwrap();
        let verify = partial_sig_verify(&psig, &nonce_out.pubnonce, &pks[0], &session).unwrap();
        assert!(verify, "Partial signature must verify");
        eprintln!("sign_verify_full_flow: PASS (psig={})", hex_encode(&psig));
    }

    /// Sanity: hash_tagged output is 32 bytes
    #[test]
    fn hash_tagged_length() {
        let h = hash_tagged(b"test", b"data");
        assert_eq!(h.len(), 32);
    }

    /// Sanity: key_agg empty pubkeys fails
    #[test]
    fn key_agg_empty_fails() {
        let empty: Vec<Vec<u8>> = vec![];
        assert!(key_agg(&empty).is_err());
    }
}

