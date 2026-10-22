use core::ops::{Index, IndexMut};
#[cfg(feature = "alloc-fallback")]
use std_shims::vec::Vec;

use zeroize::Zeroize;

use curve25519_dalek::edwards::EdwardsPoint;

use crate::scalar_vector::ScalarVector;

#[cfg(test)]
use crate::core::multiexp;

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
#[cfg(feature = "alloc-fallback")]
pub(crate) struct PointVector(pub(crate) Vec<EdwardsPoint>);

#[cfg(feature = "alloc-fallback")]
impl Index<usize> for PointVector {
    type Output = EdwardsPoint;
    #[cfg(feature = "alloc-fallback")]
    fn index(&self, index: usize) -> &EdwardsPoint {
        &self.0[index]
    }
}

#[cfg(feature = "alloc-fallback")]
impl IndexMut<usize> for PointVector {
    #[cfg(feature = "alloc-fallback")]
    fn index_mut(&mut self, index: usize) -> &mut EdwardsPoint {
        &mut self.0[index]
    }
}

#[cfg(feature = "alloc-fallback")]
impl PointVector {
    pub(crate) fn mul_vec(&self, vector: &ScalarVector) -> Self {
        assert_eq!(self.len(), vector.len());
        let mut res = self.clone();
        for (i, val) in res.0.iter_mut().enumerate() {
            *val *= vector.0[i];
        }
        res
    }

    #[cfg(test)]
    pub(crate) fn multiexp(&self, vector: &ScalarVector) -> EdwardsPoint {
        debug_assert_eq!(self.len(), vector.len());
        let mut res = Vec::with_capacity(self.len());
        for (point, scalar) in self.0.iter().copied().zip(vector.0.iter().copied()) {
            res.push((scalar, point));
        }
        // Z5.3 scratch API: the core multiexp takes caller scratch; this
        // test-only helper provisions its own (vendor test-infra patch).
        let cap = res.len().max(1);
        let mut storage = vec![0u8; curve25519_dalek::scratch::StrausScratch::storage_bytes(cap)];
        let mut straus = curve25519_dalek::scratch::StrausScratch::new(&mut storage, cap)
            .expect("straus scratch");
        multiexp(&res, &mut straus).expect("multiexp")
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    #[cfg(feature = "alloc-fallback")]
    pub(crate) fn split(mut self) -> (Self, Self) {
        debug_assert!(self.len() > 1);
        let r = self.0.split_off(self.0.len() / 2);
        debug_assert_eq!(self.len(), r.len());
        (self, PointVector(r))
    }
}
