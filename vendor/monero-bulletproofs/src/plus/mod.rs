#![allow(non_snake_case, clippy::many_single_char_names)]

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, EdwardsPoint, Scalar};

#[cfg(feature = "alloc-fallback")]
pub(crate) use crate::{monero_h, point_vector::PointVector, scalar_vector::ScalarVector};

pub(crate) mod transcript;
pub mod weighted_inner_product;
pub use weighted_inner_product::WipScratch;
pub(crate) use weighted_inner_product::*;
pub(crate) mod aggregate_range_proof;
pub(crate) use aggregate_range_proof::*;

pub(crate) fn padded_pow_of_2(i: usize) -> usize {
    let mut next_pow_of_2 = 1;
    while next_pow_of_2 < i {
        next_pow_of_2 <<= 1;
    }
    next_pow_of_2
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum GeneratorsList {
    GBold,
    HBold,
}

#[derive(Clone, Debug)]
pub(crate) struct BpPlusGenerators {
    g_bold: &'static [EdwardsPoint],
    h_bold: &'static [EdwardsPoint],
}

include!(concat!(env!("OUT_DIR"), "/generators_plus.rs"));

impl BpPlusGenerators {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Result<Self, crate::generator_cache_hook::InitError> {
        let gens = &generators()?;
        Ok(BpPlusGenerators {
            g_bold: &gens.G,
            h_bold: &gens.H,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.g_bold.len()
    }

#[cfg(feature = "alloc-fallback")]
    pub(crate) fn g() -> EdwardsPoint {
        monero_h()
    }

    pub(crate) fn h() -> EdwardsPoint {
        ED25519_BASEPOINT_POINT
    }

    pub(crate) fn generator(&self, list: GeneratorsList, i: usize) -> EdwardsPoint {
        match list {
            GeneratorsList::GBold => self.g_bold[i],
            GeneratorsList::HBold => self.h_bold[i],
        }
    }

#[cfg(feature = "alloc-fallback")]
    pub(crate) fn reduce(&self, generators: usize) -> Self {
        // Round to the nearest power of 2
        let generators = padded_pow_of_2(generators);
        assert!(
            generators <= self.g_bold.len(),
            "instantiated with less generators than application required"
        );

        BpPlusGenerators {
            g_bold: &self.g_bold[..generators],
            h_bold: &self.h_bold[..generators],
        }
    }
}

// Returns the little-endian decomposition.
#[cfg(feature = "alloc-fallback")]
fn u64_decompose(value: u64) -> ScalarVector {
    let mut bits = ScalarVector::new(64);
    for bit in 0..64 {
        bits[bit] = Scalar::from((value >> bit) & 1);
    }
    bits
}
