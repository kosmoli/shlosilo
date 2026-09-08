use alloc::vec::Vec;
use core::cmp::PartialEq;
use core::mem::swap;

use cnaes::{AES_BLOCK_SIZE, CN_AES_KEY_SIZE};
use digest::Digest as _;
use groestl::Groestl256;
use jh::Jh256;
use skein::{consts::U32, Skein512};

use crate::{
    blake256::{Blake256, Digest as _},
    cnaes,
    util::{subarray, subarray_copy, subarray_mut},
};
// Mirror the bp probe pattern: cfg-gated use + noop fallback so feature-off
// builds compile unchanged.
#[cfg(feature = "cn-timing")]
use crate::cn_timing_hook::PhaseProbe;
#[cfg(not(feature = "cn-timing"))]
mod noop_probe {
    pub(crate) struct PhaseProbe;
    impl PhaseProbe {
        pub(crate) fn start(_phase: u8) -> Option<Self> {
            None
        }
        pub(crate) fn end(&mut self) {}
    }
}
#[cfg(not(feature = "cn-timing"))]
use noop_probe::PhaseProbe;

pub(crate) const MEMORY: usize = 1 << 21; // 2MB scratchpad
pub(crate) const MEMORY_BLOCKS: usize = MEMORY / AES_BLOCK_SIZE;

const ITER: usize = 1 << 20;
const AES_KEY_SIZE: usize = CN_AES_KEY_SIZE;
const INIT_BLOCKS: usize = 8;
const INIT_SIZE_BYTE: usize = INIT_BLOCKS * AES_BLOCK_SIZE;

const KECCAK1600_BYTE_SIZE: usize = 200;

#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum Variant {
    V0,
    V1,
    V2,
    R,
}

/// Equivalent struct in the C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L469-L477>
struct CnSlowHashState {
    b: [u8; KECCAK1600_BYTE_SIZE],
}

impl Default for CnSlowHashState {
    fn default() -> Self {
        Self {
            b: [0; KECCAK1600_BYTE_SIZE],
        }
    }
}

impl CnSlowHashState {
    const fn get_keccak_bytes(&self) -> &[u8; KECCAK1600_BYTE_SIZE] {
        &self.b
    }

    const fn get_keccak_bytes_mut(&mut self) -> &mut [u8; KECCAK1600_BYTE_SIZE] {
        &mut self.b
    }

    fn get_keccak_word(&self, index: usize) -> u64 {
        u64::from_le_bytes(subarray_copy(&self.b, index * 8))
    }

    fn get_k(&self) -> [u128; 4] {
        [
            u128::from_le_bytes(subarray_copy(&self.b, 0)),
            u128::from_le_bytes(subarray_copy(&self.b, 16)),
            u128::from_le_bytes(subarray_copy(&self.b, 32)),
            u128::from_le_bytes(subarray_copy(&self.b, 48)),
        ]
    }

    fn get_aes_key0(&self) -> &[u8; AES_KEY_SIZE] {
        subarray(&self.b, 0)
    }

    fn get_aes_key1(&self) -> &[u8; AES_KEY_SIZE] {
        subarray(&self.b, AES_KEY_SIZE)
    }

    #[inline]
    fn get_init(&self) -> [u128; INIT_BLOCKS] {
        let mut init = [0_u128; INIT_BLOCKS];
        for (i, block) in init.iter_mut().enumerate() {
            *block = u128::from_le_bytes(subarray_copy(&self.b, 64 + i * AES_BLOCK_SIZE));
        }
        init
    }

    fn set_init(&mut self, init: &[u128; INIT_BLOCKS]) {
        for (i, block) in init.iter().enumerate() {
            self.b[64 + i * AES_BLOCK_SIZE..64 + (i + 1) * AES_BLOCK_SIZE]
                .copy_from_slice(&block.to_le_bytes());
        }
    }
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/hash.c#L38-L47>
fn hash_permutation(b: &mut [u8; KECCAK1600_BYTE_SIZE]) {
    let mut state = [0_u64; 25];

    for (i, state_i) in state.iter_mut().enumerate() {
        *state_i = u64::from_le_bytes(subarray_copy(b, i * 8));
    }

    // Same as keccakf in the C code
    keccak::keccak_p(&mut state, 24);

    for (i, chunk) in state.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&chunk.to_le_bytes());
    }
}

fn keccak1600(input: &[u8], out: &mut [u8; KECCAK1600_BYTE_SIZE]) {
    let mut hasher = sha3::Keccak256Full::new();
    hasher.update(input);
    let result = hasher.finalize();
    out.copy_from_slice(result.as_ref());
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L1709C1-L1709C27>
#[inline]
#[expect(clippy::cast_possible_truncation)]
const fn e2i(a: u128) -> usize {
    const MASK: u64 = ((MEMORY_BLOCKS) - 1) as u64;

    // truncates upper 64 bits before dividing
    let value = (a as u64) / (AES_BLOCK_SIZE as u64);

    // mask is 0x1ffff, so no data is truncated if usize is 32 bits
    (value & MASK) as usize
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L1711-L1720>
#[expect(clippy::cast_possible_truncation)]
fn mul(a: u64, b: u64) -> u128 {
    let product = u128::from(a).wrapping_mul(u128::from(b));
    let hi = (product >> 64) as u64;
    let lo = product as u64;

    // swap hi and low, so this isn't just a multiply
    (u128::from(lo) << 64) | u128::from(hi)
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L1722-L1733>
#[expect(clippy::cast_possible_truncation)]
fn sum_half_blocks(a: u128, b: u128) -> u128 {
    let a_low = a as u64;
    let b_low = b as u64;
    let sum_low = a_low.wrapping_add(b_low);

    let a_high = (a >> 64) as u64;
    let b_high = (b >> 64) as u64;
    let sum_high = a_high.wrapping_add(b_high);

    (u128::from(sum_high) << 64) | u128::from(sum_low)
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L144-L151>
fn variant1_init(state: &CnSlowHashState, data: &[u8], variant: Variant) -> u64 {
    const NONCE_PTR_INDEX: usize = 35;

    if variant != Variant::V1 {
        return 0;
    }

    assert!(
        data.len() >= 43,
        "Cryptonight variant 1 needs at least 43 bytes of data"
    );

    let mut tweak1_2 = u64::from_le_bytes(subarray_copy(&state.get_keccak_bytes(), 192));
    tweak1_2 ^= u64::from_le_bytes(subarray_copy(data, NONCE_PTR_INDEX));

    tweak1_2
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L120-L127>
fn variant1_1(p: &mut u128, variant: Variant) {
    const MASK_BYTE11: u128 = !(0xFF << (11 * 8)); // all bits except the 11th byte are ones
    const TABLE: u32 = 0x75310_u32;

    #[expect(clippy::cast_possible_truncation)]
    if variant == Variant::V1 {
        let old_byte11 = (*p >> (11 * 8)) as u8;
        let index = (((old_byte11 >> 3) & 6) | (old_byte11 & 1)) << 1;
        let new_byte11 = old_byte11 ^ ((TABLE >> index) & 0x30) as u8;
        *p = (*p & MASK_BYTE11) | (u128::from(new_byte11) << (11 * 8));
    }
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L129C1-L133C13>
fn variant1_2(c2: &mut u128, tweak1_2: u64, variant: Variant) {
    if variant == Variant::V1 {
        *c2 ^= u128::from(tweak1_2) << 64;
    }
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L171-L181>
fn variant_2_init(b: &mut [u128; 2], state: &CnSlowHashState, variant: Variant) -> (u64, u64) {
    if variant != Variant::V2 && variant != Variant::R {
        return (0, 0);
    }

    let keccak_state_bytes = state.get_keccak_bytes();
    b[1] = u128::from_le_bytes(subarray_copy(keccak_state_bytes, 64))
        ^ u128::from_le_bytes(subarray_copy(keccak_state_bytes, 80));
    let division_result = state.get_keccak_word(12);
    let sqrt_result = state.get_keccak_word(13);

    (division_result, sqrt_result)
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L295-L299>
fn variant_2_2(long_state: &mut [u128; MEMORY_BLOCKS], j: usize, d: &mut u128, variant: Variant) {
    if variant == Variant::V2 {
        let chunk1_start = j ^ 0x1;
        let chunk2_start = j ^ 0x2;
        long_state[chunk1_start] ^= *d;
        *d ^= long_state[chunk2_start];
    }
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L319-L334>
/// The compiler would inline this code even without the `#[inline]` attribute, but we'd like
/// to avoid coping `r` and `code` between stack addresses.
#[inline]
fn variant4_math_init(_height: u64, _state: &CnSlowHashState, _variant: Variant) -> NoV4State {
    NoV4State
}

/// Placeholder for the R-variant scratch state (V0/V1/V2 never use it).
struct NoV4State;

fn extra_hashes(input: &[u8; KECCAK1600_BYTE_SIZE]) -> [u8; 32] {
    match input[0] & 0x3 {
        0 => Blake256::digest(input),
        1 => Groestl256::digest(input).into(),
        2 => Jh256::digest(input).into(),
        3 => Skein512::<U32>::digest(input).into(),
        _ => unreachable!(),
    }
}

/// Original C code:
/// <https://github.com/monero-project/monero/blob/v0.18.3.4/src/crypto/slow-hash.c#L1776-L1873>
#[expect(clippy::cast_possible_truncation)]
pub(crate) fn cn_slow_hash(data: &[u8], variant: Variant, height: u64) -> [u8; 32] {
    #[cfg(feature = "cn-timing")]
    let mut probe_total = PhaseProbe::start(5);
    let mut state = CnSlowHashState::default();
    #[cfg(feature = "cn-timing")]
    let mut p1 = PhaseProbe::start(1);
    keccak1600(data, state.get_keccak_bytes_mut());
    #[cfg(feature = "cn-timing")]
    p1.as_mut().map_or((), |p| p.end());
    let aes_expanded_key = cnaes::key_extend(state.get_aes_key0());
    let mut text = state.get_init();

    let tweak1_2 = variant1_init(&state, data, variant);
    let mut b = [0_u128; 2];
    let (mut division_result, mut sqrt_result) = variant_2_init(&mut b, &state, variant);
    let _v4state = variant4_math_init(height, &state, variant);

    // Use a vector so the memory is allocated on the heap. We might have 2MB
    // available on the stack, but that optimization would only be meaningful if
    // this code was still used for mining.
    let mut long_state: Vec<u128> = Vec::with_capacity(MEMORY_BLOCKS);

    #[cfg(feature = "cn-timing")]
    let mut p2 = PhaseProbe::start(2);
    for i in 0..MEMORY_BLOCKS {
        let block = &mut text[i % INIT_BLOCKS];
        *block = cnaes::aesb_pseudo_round(*block, &aes_expanded_key);
        long_state.push(*block);
    }
    #[cfg(feature = "cn-timing")]
    p2.as_mut().map_or((), |p| p.end());

    // Treat long_state as an array now that it's initialized on the heap
    let long_state: &mut [u128; MEMORY_BLOCKS] = subarray_mut(&mut long_state, 0);

    let k = state.get_k();
    let mut a = k[0] ^ k[2];
    b[0] = k[1] ^ k[3];

    let mut c1;
    let mut c2;
    let mut a1;

    #[cfg(feature = "cn-timing")]
    let mut p3 = PhaseProbe::start(3);
    for _ in 0..ITER / 2 {
        /* Dependency chain: address -> read value ------+
         * written value <-+ hard function (AES or MUL) <+
         * next address  <-+
         */
        // Iteration
        let mut j = e2i(a);
        c1 = long_state[j];
        cnaes::aesb_single_round(&mut c1, a);
        // V2 shuffle: no-op for V0
        let _ = (&c1, &a, &b, &*long_state, j, &variant);

        long_state[j] = c1 ^ b[0];
        variant1_1(&mut long_state[j], variant);

        /* Iteration 2 */
        j = e2i(c1);
        c2 = long_state[j];

        a1 = a;
        // V2 integer math: no-op for V0
        let _ = (&mut c2, c1, &mut division_result, &mut sqrt_result, variant);
        // V4 random math: no-op for V0
        let _ = (&mut a1, &mut c2, &b);
        let mut d = mul(c1 as u64, c2 as u64);
        variant_2_2(long_state, j, &mut d, variant);
        // V2 shuffle: no-op for V0
        let _ = (&c1, &a, &b, &*long_state, j, &variant);
        a1 = sum_half_blocks(a1, d);
        swap(&mut a1, &mut c2);
        a1 ^= c2;
        variant1_2(&mut c2, tweak1_2, variant);
        long_state[j] = c2;

        if variant == Variant::V2 || variant == Variant::R {
            b[1] = b[0];
        }
        b[0] = c1;
        a = a1;
    }

    #[cfg(feature = "cn-timing")]
    p3.as_mut().map_or((), |p| p.end());

    let mut text = state.get_init();
    let aes_expanded_key = cnaes::key_extend(state.get_aes_key1());
    #[cfg(feature = "cn-timing")]
    let mut p4 = PhaseProbe::start(4);
    for i in 0..MEMORY / INIT_SIZE_BYTE {
        for (j, block) in text.iter_mut().enumerate() {
            let ls_index = i * INIT_BLOCKS + j;
            *block ^= long_state[ls_index];
            *block = cnaes::aesb_pseudo_round(*block, &aes_expanded_key);
        }
    }
    state.set_init(&text);

    hash_permutation(state.get_keccak_bytes_mut());

    let out = extra_hashes(state.get_keccak_bytes());
    #[cfg(feature = "cn-timing")]
    p4.as_mut().map_or((), |p| p.end());
    #[cfg(feature = "cn-timing")]
    probe_total.as_mut().map_or((), |p| p.end());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_to_array;

    #[test]
    fn test_keccak1600() {
        let input: [u8; 44] = hex_to_array(
            "5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374"
        );
        let mut output = [0_u8; KECCAK1600_BYTE_SIZE];
        keccak1600(&input, &mut output);
        let output_hex = "af6fe96f8cb409bdd2a61fb837e346f1a28007b0f078a8d68bc1224b6fcfcc3c39f1244db8c0af06e94173db4a54038a2f7a6a9c729928b5ec79668a30cbf5f266110665e23e891ea4ee2337fb304b35bf8d9c2e4c3524e52e62db67b0b170487a68a34f8026a81b35dc835c60b356d2c411ad227b6c67e30e9b57ba34b3cf27fccecae972850cf3889bb3ff8347b55a5710d58086973d12d75a3340a39430b65ee2f4be27c21e7b39f47341dd036fe13bf43bb2c55bce498a3adcbf07397ea66062b66d56cd8136";
        assert_eq!(hex::encode(output), output_hex);
    }

    #[test]
    fn test_mul() {
        let test = |a_hex: &str, b_hex: &str, expected_hex: &str| {
            let a = u64::from_le_bytes(hex_to_array(a_hex));
            let b = u64::from_le_bytes(hex_to_array(b_hex));
            let res = mul(a, b);
            assert_eq!(hex::encode(res.to_le_bytes()), expected_hex);
        };
        test(
            "0100000000000000",
            "0100000000000000",
            "00000000000000000100000000000000",
        );
        test(
            "ffffffffffffffff",
            "0200000000000000",
            "0100000000000000feffffffffffffff",
        );
        test(
            "34504affdab54e6d",
            "b352de34917bcc4f",
            "2d82d3509a9912225cbcbe6b16321e17",
        );
        test(
            "26ce23ce804055ed",
            "d8e42f12da72202a",
            "1f531a54b7110e2710c8c956b3f98f90",
        );
    }

    #[test]
    fn test_hash_permutations() {
        let mut state_bytes: [u8; KECCAK1600_BYTE_SIZE] = hex_to_array(
            "af6fe96f8cb409bdd2a61fb837e346f1a28007b0f078a8d68bc1224b6fcfcc3c39f1244db8c0af06e94173db4a54038a2f7a6a9c729928b5ec79668a30cbf5f2622fea9d7982e587e6612c4e6a1d28fdbaba4af1aea99e63322a632d514f35b4fc5cf231e9a6328efb5eb22ad2cfabe571ee8b6ef7dbc64f63185d54a771bdccd207b75e10547b4928f5dcb309192d88bf313d8bc53c8fe71da7ea93355d266c5cc8d39a1273e44b074d143849a3b302edad73c2e61f936c502f6bbabb972b616062b66d56cd8136"
        );
        const EXPECTED: &str = "31e2fb6eb8e2e376d42a53bc88166378f2a23cf9be54645ff69e8ade3aa4b7ad35040d0e3ad0ee0d8562d53a51acdf14f44de5c097c48a29f63676346194b3af13c3c45af214335a14329491081068a32ea29b3a6856e0efa737dff49d3b5dbf3f7847f058bb41d36347c19d5cd5bdb354ac64a86156c8194e19b0f62d109a8112024a7734730a2bb221c137d3034204e1e57d9cec9689bc199de684f38aeed4624b84c39675a4755ce9b69fde9d36cabd12f1aef4a5b2bb6c6126900799f2109e9b6b55d7bb3ff5";
        hash_permutation(&mut state_bytes);
        assert_eq!(hex::encode(state_bytes), EXPECTED);
    }

    #[test]
    fn test_extra_hashes() {
        let mut input = [0_u8; KECCAK1600_BYTE_SIZE];
        for (i, val) in input.iter_mut().enumerate() {
            *val = u8::try_from(i & 0xFF).unwrap();
        }

        const EXPECTED_BLAKE: &str =
            "c4d944c2b1c00a8ee627726b35d4cd7fe018de090bc637553cc782e25f974cba";
        const EXPECTED_GROESTL: &str =
            "73905cfed57520c60eb468defc58a925170cecc6b4a9f2f6e56d34d674d64111";
        const EXPECTED_JH: &str =
            "71a4f8ae96c48df7ace370854824a60a2f247fbf903c7b936f6f99d164c2f6b1";
        const EXPECTED_SKEIN: &str =
            "040e79b9daa0fc6219234a06b3889f86f8b02b78dcc25a9874ca95630cf6b5e6";

        const EXPECTED: [&str; 4] = [
            EXPECTED_BLAKE,
            EXPECTED_GROESTL,
            EXPECTED_JH,
            EXPECTED_SKEIN,
        ];

        for (i, expected) in EXPECTED.iter().enumerate() {
            input[0] = u8::try_from(i).unwrap();
            let output = extra_hashes(&input);
            assert_eq!(hex::encode(output), *expected, "hash {i}");
        }
    }
}
