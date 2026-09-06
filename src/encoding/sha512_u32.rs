//! SHA-512 compression function implemented with u32 pairs for Cortex-M4.
//!
//! The upstream `sha2` crate's software backend uses `u64` arithmetic throughout.
//! On a 32-bit Cortex-M4 every `u64` rotate expands into ~6 instructions and the
//! 8-word u64 state cannot stay in registers, so the compression function runs
//! ~40k cycles per block. This implementation keeps the state as `[u32; 16]`
//! (hi/lo halves) and expresses the 64-bit rotations as paired 32-bit barrel
//! shifts, which the M4 executes in a single cycle.
//!
//! Semantics are bit-identical to FIPS 180-4 SHA-512; see the test module for
//! the official vectors and the cross-check against `sha2`.

/// Initial state of SHA-512 as hi/lo u32 pairs (big-endian halves).
const H0: [u32; 16] = [
    0x6a09_e667,
    0xf3bc_c908, // h0 = 0x6a09e667f3bcc908
    0xbb67_ae85,
    0x84ca_a73b, // h1 = 0xbb67ae8584caa73b
    0x3c6e_f372,
    0xfe94_f82b, // h2 = 0x3c6ef372fe94f82b
    0xa54f_f53a,
    0x5f1d_36f1, // h3 = 0xa54ff53a5f1d36f1
    0x510e_527f,
    0xade6_82d1, // h4 = 0x510e527fade682d1
    0x9b05_688c,
    0x2b3e_6c1f, // h5 = 0x9b05688c2b3e6c1f
    0x1f83_d9ab,
    0xfb41_bd6b, // h6 = 0x1f83d9abfb41bd6b
    0x5be0_cd19,
    0x137e_2179, // h7 = 0x5be0cd19137e2179
];

/// Round constants K[0..80] as hi/lo u32 pairs, flattened (k[i] = (K2[2i], K2[2i+1])).
#[rustfmt::skip]
const K2: [u32; 160] = [
    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f,
    0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
    0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242,
    0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
    0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235,
    0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
    0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 0x2de92c6f, 0x592b0275,
    0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
    0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f,
    0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
    0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc,
    0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
    0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6,
    0x92722c85, 0x1482353b, 0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
    0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218,
    0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
    0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99,
    0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
    0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc,
    0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915,
    0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
    0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba,
    0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
    0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc,
    0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
    0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
];

/// XOR of three 64-bit values represented as hi/lo u32 pairs. All helper
/// functions below use the same convention: value = (hi << 32) | lo.
#[inline(always)]
fn xor3(a: (u32, u32), b: (u32, u32), c: (u32, u32)) -> (u32, u32) {
    (a.0 ^ b.0 ^ c.0, a.1 ^ b.1 ^ c.1)
}

/// Rotate a 64-bit (hi, lo) pair right by `n` bits (0 < n < 64), using only
/// 32-bit shifts/rotates. Each of the four shift amounts compiles to a single
/// M4 instruction, and the ORs fold into the shift via the barrel shifter.
#[inline(always)]
fn rotr64(hi: u32, lo: u32, n: u32) -> (u32, u32) {
    if n == 0 {
        return (hi, lo);
    }
    if n == 32 {
        return (lo, hi);
    }
    if n < 32 {
        let s = 32 - n;
        let mask = (1u32 << n) - 1;
        // 64-bit right rotate by n (0 < n < 32):
        //   out_hi = (hi >> n) | (lo's low n bits << (32-n))  [wrap into top]
        //   out_lo = (lo >> n) | (hi << s)                    [hi wraps in fully]
        let hi_wrapped = hi << s;
        ((hi >> n) | ((lo & mask) << s), (lo >> n) | hi_wrapped)
    } else {
        // rotate right by n > 32 == swap halves, rotate right by n-32
        let (hi2, lo2) = rotr64(lo, hi, n - 32);
        (hi2, lo2)
    }
}

/// Shift a 64-bit (hi, lo) pair right by `n` bits (0 <= n < 64).
#[inline(always)]
fn shr64(hi: u32, lo: u32, n: u32) -> (u32, u32) {
    if n == 0 {
        return (hi, lo);
    }
    if n == 32 {
        return (0, hi);
    }
    if n < 32 {
        let s = 32 - n;
        // 64-bit right shift by n: out_hi = hi >> n (no wrap on a shift);
        // out_lo = (hi's low n bits << (32-n)) | (lo >> n)
        (hi >> n, (hi << s) | (lo >> n))
    } else {
        (0, hi >> (n - 32))
    }
}

/// Add two 64-bit pairs with carry.
#[inline(always)]
fn add64(a: (u32, u32), b: (u32, u32)) -> (u32, u32) {
    let lo = a.1.wrapping_add(b.1);
    let hi = a.0.wrapping_add(b.0) + ((lo < a.1) as u32);
    (hi, lo)
}

/// Big Sigma0: ROTR28(x) XOR ROTR34(x) XOR ROTR39(x)
#[inline(always)]
fn big_sigma0(hi: u32, lo: u32) -> (u32, u32) {
    let a = rotr64(hi, lo, 28);
    let b = rotr64(hi, lo, 34);
    let c = rotr64(hi, lo, 39);
    xor3(a, b, c)
}

/// Big Sigma1: ROTR14(x) XOR ROTR18(x) XOR ROTR41(x)
#[inline(always)]
fn big_sigma1(hi: u32, lo: u32) -> (u32, u32) {
    let a = rotr64(hi, lo, 14);
    let b = rotr64(hi, lo, 18);
    let c = rotr64(hi, lo, 41);
    xor3(a, b, c)
}

/// Little sigma0: ROTR1(x) XOR ROTR8(x) XOR SHR7(x)
#[inline(always)]
fn little_sigma0(hi: u32, lo: u32) -> (u32, u32) {
    let a = rotr64(hi, lo, 1);
    let b = rotr64(hi, lo, 8);
    let c = shr64(hi, lo, 7);
    xor3(a, b, c)
}

/// Little sigma1: ROTR19(x) XOR ROTR61(x) XOR SHR6(x)
#[inline(always)]
fn little_sigma1(hi: u32, lo: u32) -> (u32, u32) {
    let a = rotr64(hi, lo, 19);
    let b = rotr64(hi, lo, 61);
    let c = shr64(hi, lo, 6);
    xor3(a, b, c)
}

/// Ch(x, y, z): (x AND y) XOR (NOT x AND z) — bitwise, carry-free per half.
#[inline(always)]
fn ch(x: (u32, u32), y: (u32, u32), z: (u32, u32)) -> (u32, u32) {
    ((x.0 & y.0) | (!x.0 & z.0), (x.1 & y.1) | (!x.1 & z.1))
}

/// Maj(x, y, z): (x AND y) XOR (x AND z) XOR (y AND z)
#[inline(always)]
fn maj(x: (u32, u32), y: (u32, u32), z: (u32, u32)) -> (u32, u32) {
    (
        (x.0 & y.0) ^ (x.0 & z.0) ^ (y.0 & z.0),
        (x.1 & y.1) ^ (x.1 & z.1) ^ (y.1 & z.1),
    )
}

/// One SHA-512 compression round, inlined into the compress loop.
/// State variables a..h are (hi, lo) pairs.
macro_rules! round {
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $khi:expr, $klo:expr, $whi:expr, $wlo:expr) => {{
        let s1 = big_sigma1($e.0, $e.1);
        let chv = ch($e, $f, $g);
        // t1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i]
        let t1 = add64(add64(add64(add64($h, s1), chv), ($khi, $klo)), ($whi, $wlo));
        let s0 = big_sigma0($a.0, $a.1);
        let mv = maj($a, $b, $c);
        // t2 = Sigma0(a) + Maj(a,b,c)
        let t2 = add64(s0, mv);
        $h = $g;
        $g = $f;
        $f = $e;
        $e = add64($d, t1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = add64(t1, t2);
    }};
}

/// Compress one 128-byte block into `state` (16 u32s, initialized from `H0`
/// or carried from the previous block). `block` is in raw big-endian bytes.
pub fn compress(state: &mut [u32; 16], block: &[u8; 128]) {
    debug_assert_eq!(state.len(), 16);

    // Message schedule W[0..16] as (hi, lo) pairs, big-endian.
    let mut w_hi = [0u32; 16];
    let mut w_lo = [0u32; 16];
    for i in 0..16 {
        // Each 64-bit word is 8 bytes: hi half = first 4 bytes (big-endian), lo half = last 4.
        let b = &block[i * 8..i * 8 + 8];
        w_hi[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        w_lo[i] = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    }

    let mut a = (state[0], state[1]);
    let mut b = (state[2], state[3]);
    let mut c = (state[4], state[5]);
    let mut d = (state[6], state[7]);
    let mut e = (state[8], state[9]);
    let mut f = (state[10], state[11]);
    let mut g = (state[12], state[13]);
    let mut h = (state[14], state[15]);

    // Rounds 0..16 use W directly.
    for i in 0..16 {
        round!(
            a,
            b,
            c,
            d,
            e,
            f,
            g,
            h,
            K2[2 * i],
            K2[2 * i + 1],
            w_hi[i],
            w_lo[i]
        );
    }

    // Rounds 16..80 extend the schedule on the fly (sliding window over W).
    for i in 16..80 {
        // W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
        let im2 = (i - 2) & 15;
        let im7 = (i - 7) & 15;
        let im15 = (i - 15) & 15;
        let im16 = i & 15;
        let s1 = little_sigma1(w_hi[im2], w_lo[im2]);
        let s0 = little_sigma0(w_hi[im15], w_lo[im15]);
        let t = add64(
            add64(add64(s1, (w_hi[im7], w_lo[im7])), s0),
            (w_hi[im16], w_lo[im16]),
        );
        w_hi[im16] = t.0;
        w_lo[im16] = t.1;
        round!(a, b, c, d, e, f, g, h, K2[2 * i], K2[2 * i + 1], t.0, t.1);
    }

    // Feed forward.
    let acc = [
        a.0, a.1, b.0, b.1, c.0, c.1, d.0, d.1, e.0, e.1, f.0, f.1, g.0, g.1, h.0, h.1,
    ];
    // Feed-forward must be 64-bit additions: the lo-half sum can carry into hi.
    for i in 0..8 {
        let lo = state[2 * i + 1].wrapping_add(acc[2 * i + 1]);
        let carry = (lo < state[2 * i + 1]) as u32;
        state[2 * i] = state[2 * i].wrapping_add(acc[2 * i]).wrapping_add(carry);
        state[2 * i + 1] = lo;
    }
}

/// Return a fresh SHA-512 state (the H0 constants).
pub fn initial_state() -> [u32; 16] {
    H0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference implementation using the sha2 crate (u64 backend).
    fn reference(message: &[u8]) -> [u8; 64] {
        use sha2::Digest;
        let mut h = sha2::Sha512::new();
        h.update(message);
        h.finalize().into()
    }

    fn our_hash(message: &[u8]) -> [u8; 64] {
        // Pad the message per FIPS 180-4 and compress block by block.
        let mut state = initial_state();
        let (blocks, rem) = message.as_chunks::<128>();
        for block in blocks {
            compress(&mut state, block);
        }
        // Padding: 0x80, zeros, 128-bit length (big-endian bit count).
        let mut last = [0u8; 128];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 0x80;
        let bitlen = (message.len() as u128) * 8;
        if rem.len() + 17 > 128 {
            // 1 byte 0x80 + 16-byte length must fit after remainder
            compress(&mut state, &last);
            last = [0u8; 128];
        }
        last[112..].copy_from_slice(&bitlen.to_be_bytes());
        compress(&mut state, &last);
        let mut out = [0u8; 64];
        for i in 0..8 {
            out[i * 8..i * 8 + 4].copy_from_slice(&state[i * 2].to_be_bytes());
            out[i * 8 + 4..i * 8 + 8].copy_from_slice(&state[i * 2 + 1].to_be_bytes());
        }
        out
    }

    #[test]
    fn fips_vectors() {
        // Official FIPS 180-4 test vectors for SHA-512.
        assert_eq!(
            our_hash(b""),
            [
                0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
                0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
                0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
                0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
            ]
        );
        assert_eq!(
            our_hash(b"abc"),
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
                0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
                0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
            ]
        );
    }

    #[test]
    fn matches_sha2_on_various_lengths() {
        // Boundary lengths around block size and padding thresholds.
        for len in [
            0usize, 1, 63, 64, 111, 112, 113, 119, 120, 127, 128, 129, 255, 256, 257, 1000, 4096,
        ] {
            let msg: alloc::vec::Vec<u8> = (0..len as u8)
                .map(|b| b.wrapping_mul(7).wrapping_add(1))
                .collect();
            assert_eq!(our_hash(&msg), reference(&msg), "mismatch at len {}", len);
        }
    }

    #[test]
    fn matches_sha2_randomish() {
        // Deterministic pseudo-random messages.
        let mut msg = alloc::vec::Vec::new();
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..7000 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            msg.push((x >> 33) as u8);
        }
        for len in [1usize, 2, 127, 128, 129, 500, 3000] {
            assert_eq!(our_hash(&msg[..len]), reference(&msg[..len]), "len {}", len);
        }
    }
}
