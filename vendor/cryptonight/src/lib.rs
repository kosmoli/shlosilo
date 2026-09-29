#![no_std]

#[cfg(feature = "alloc-fallback")]
extern crate alloc;

mod blake256;
mod cnaes;
mod slow_hash;
mod util;

#[cfg(feature = "cn-timing")]
pub mod cn_timing_hook;

#[cfg(feature = "alloc-fallback")]
use slow_hash::cn_slow_hash;
use slow_hash::cn_slow_hash_into;

/// Device-phase timing hooks (feature `cn-timing`; no-op stubs otherwise).
#[cfg(feature = "cn-timing")]
pub use cn_timing_hook::{phase_ms, register_clock, reset_all};
#[cfg(not(feature = "cn-timing"))]
pub fn register_clock(_f: Option<extern "C" fn() -> u32>) {}
#[cfg(not(feature = "cn-timing"))]
pub fn reset_all() {}
#[cfg(not(feature = "cn-timing"))]
pub fn phase_ms(_phase: u8) -> u32 {
    0
}

/// Calculates the `CryptoNight` v0 hash of buf over caller scratch (A1).
/// Scratch is secret-bearing and zeroed on exit. Capacity/alignment
/// failures are explicit errors.
pub fn cryptonight_hash_v0_into(
    buf: &[u8],
    scratch: &mut [u8],
) -> Result<[u8; 32], slow_hash::CnScratchError> {
    cn_slow_hash_into(buf, slow_hash::Variant::V0, 0, scratch)
}

/// Test/legacy convenience (allocates the scratchpad).
#[cfg(feature = "alloc-fallback")]
pub fn cryptonight_hash_v0(buf: &[u8]) -> [u8; 32] {
    cn_slow_hash(buf, slow_hash::Variant::V0, 0)
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn slow_hash_0() {
        fn test(inp: &str, exp: &str) {
            let res = hex::encode(cryptonight_hash_v0(&hex::decode(inp).unwrap()));
            assert_eq!(&res, exp);
        }

        // https://github.com/monero-project/monero/blob/67d190ce7c33602b6a3b804f633ee1ddb7fbb4a1/tests/hash/tests-slow.txt
        test(
            "6465206f6d6e69627573206475626974616e64756d",
            "2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5",
        );
        test(
            "6162756e64616e732063617574656c61206e6f6e206e6f636574",
            "722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4",
        );
    }
}
