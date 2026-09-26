// -*- mode: rust; -*-
//
// This file is part of curve25519-dalek.
// Copyright (c) 2016-2021 isis lovecruft
// Copyright (c) 2016-2019 Henry de Valence
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Henry de Valence <hdevalence@hdevalence.ca>

#![allow(non_snake_case)]

#[curve25519_dalek_derive::unsafe_target_feature_specialize(
    "avx2",
    conditional("avx512ifma,avx512vl", nightly)
)]
pub mod spec {

    use alloc::vec::Vec;

    use core::borrow::Borrow;
    use core::cmp::Ordering;

    #[cfg(feature = "zeroize")]
    use zeroize::Zeroizing;

    #[for_target_feature("avx2")]
    use crate::backend::vector::avx2::{CachedPoint, ExtendedPoint};

    #[for_target_feature("avx512ifma")]
    use crate::backend::vector::ifma::{CachedPoint, ExtendedPoint};

    use crate::edwards::EdwardsPoint;
    use crate::scalar::Scalar;
    use crate::traits::{Identity, MultiscalarMul, VartimeMultiscalarMul};
    use crate::window::{LookupTable, NafLookupTable5};

    /// Multiscalar multiplication using interleaved window / Straus'
    /// method.  See the `Straus` struct in the serial backend for more
    /// details.
    ///
    /// This exists as a seperate implementation from that one because the
    /// AVX2 code uses different curve models (it does not pass between
    /// multiple models during scalar mul), and it has to convert the
    /// point representation on the fly.
    pub struct Straus {}

    impl MultiscalarMul for Straus {
        type Point = EdwardsPoint;

        fn multiscalar_mul<I, J>(scalars: I, points: J) -> EdwardsPoint
        where
            I: IntoIterator,
            I::Item: Borrow<Scalar>,
            J: IntoIterator,
            J::Item: Borrow<EdwardsPoint>,
        {
            // shlosilo vendor patch (Z5.3 cut 5): small term counts (<= SMALL,
            // covering the hot 2-3-term CLSAG/next_G_H calls) build the tables
            // and digits in INLINE storage — no allocation. Same tables, same
            // digits, same accumulation loop; storage only. The secret-derived
            // digits stay `Zeroizing` on both paths.
            const SMALL: usize = 4;
            let mut scalars = scalars.into_iter();
            let mut points = points.into_iter();
            let (lo, hi) = scalars.size_hint();
            if hi == Some(lo) && lo <= SMALL && points.size_hint() == (lo, Some(lo)) {
                let n = lo;
                let fill = LookupTable::<CachedPoint>::from(&EdwardsPoint::identity());
                let mut lookup_tables = [fill; SMALL];
                #[cfg(feature = "zeroize")]
                let mut scalar_digits_vec = Zeroizing::new([[0i8; 64]; SMALL]);
                #[cfg(not(feature = "zeroize"))]
                let mut scalar_digits_vec = [[0i8; 64]; SMALL];
                for i in 0 .. n {
                    lookup_tables[i] =
                        LookupTable::<CachedPoint>::from(points.next().unwrap().borrow());
                    scalar_digits_vec[i] = scalars.next().unwrap().borrow().as_radix_16();
                }
                let mut Q = ExtendedPoint::identity();
                for j in (0 .. 64).rev() {
                    Q = Q.mul_by_pow_2(4);
                    for i in 0 .. n {
                        // Q = Q + s_{i,j} * P_i
                        Q = &Q + &lookup_tables[i].select(scalar_digits_vec[i][j]);
                    }
                }
                return Q.into();
            }

            // Construct a lookup table of [P,2P,3P,4P,5P,6P,7P,8P]
            // for each input point P
            let lookup_tables: Vec<_> = points
                .map(|point| LookupTable::<CachedPoint>::from(point.borrow()))
                .collect();

            let scalar_digits_vec: Vec<_> = scalars
                .map(|s| s.borrow().as_radix_16())
                .collect();
            // Pass ownership to a `Zeroizing` wrapper
            #[cfg(feature = "zeroize")]
            let scalar_digits_vec = Zeroizing::new(scalar_digits_vec);

            let mut Q = ExtendedPoint::identity();
            for j in (0..64).rev() {
                Q = Q.mul_by_pow_2(4);
                let it = scalar_digits_vec.iter().zip(lookup_tables.iter());
                for (s_i, lookup_table_i) in it {
                    // Q = Q + s_{i,j} * P_i
                    Q = &Q + &lookup_table_i.select(s_i[j]);
                }
            }
            Q.into()
        }
    }

    impl Straus {
        /// shlosilo vendor patch (Z5.3 D-cut): the constant-time Straus over
        /// caller-provided scratch — same tables, digits and accumulation
        /// loop as `multiscalar_mul`; storage only. The digit array is
        /// secret-derived and is zeroized on every exit path.
        pub fn multiscalar_mul_scratch<I, J>(
            scalars: I,
            points: J,
            scratch: &mut crate::scratch::StrausScratch,
        ) -> Result<EdwardsPoint, crate::scratch::ScratchError>
        where
            I: IntoIterator,
            I::Item: Borrow<Scalar>,
            J: IntoIterator,
            J::Item: Borrow<EdwardsPoint>,
        {
            use crate::scratch::ScratchError;
            use crate::traits::Identity;
            let mut scalars = scalars.into_iter();
            let mut points = points.into_iter();
            let (lo, hi) = scalars.size_hint();
            if hi != Some(lo) || points.size_hint() != (lo, Some(lo)) {
                return Err(ScratchError::TooSmall);
            }
            let n = lo;

            let table_size = core::mem::size_of::<LookupTable<CachedPoint>>();
            let digits_size = core::mem::size_of::<[i8; 64]>();
            let (tables_bytes, digits_bytes) =
                scratch.split(n * table_size, n * digits_size)?;
            // SAFETY: regions come from the aligned scratch; lengths are exact
            // multiples of the element sizes; every element is written before
            // it is read (tables/digits below).
            let lookup_tables: &mut [LookupTable<CachedPoint>] =
                unsafe { crate::scratch::StrausScratch::cast(tables_bytes) };
            let scalar_digits: &mut [[i8; 64]] =
                unsafe { crate::scratch::StrausScratch::cast(digits_bytes) };

            // The tables are public-point material; init with the identity
            // table (cheap, one construction + copies) so the slices are
            // fully initialized before any read.
            let fill = LookupTable::<CachedPoint>::from(&EdwardsPoint::identity());
            for t in lookup_tables.iter_mut() {
                *t = fill;
            }
            for (i, (scalar, point)) in scalars.zip(points).enumerate() {
                lookup_tables[i] = LookupTable::<CachedPoint>::from(point.borrow());
                scalar_digits[i] = scalar.borrow().as_radix_16();
            }

            let mut Q = ExtendedPoint::identity();
            for j in (0 .. 64).rev() {
                Q = Q.mul_by_pow_2(4);
                for (s_i, lookup_table_i) in scalar_digits.iter().zip(lookup_tables.iter()) {
                    Q = &Q + &lookup_table_i.select(s_i[j]);
                }
            }
            // Secret-derived digits: wipe on every path (success included —
            // the scratch is caller-owned and may be re-provisioned).
            for d in scalar_digits.iter_mut() {
                for b in d.iter_mut() {
                    *b = 0;
                }
            }
            Ok(Q.into())
        }

        /// shlosilo vendor patch (Z5.3 D-cut): the vartime Straus over
        /// caller-provided scratch (NAF digits are public-challenge material;
        /// no wipe, parity with the allocating path).
        pub fn optional_multiscalar_mul_scratch<I, J>(
            scalars: I,
            points: J,
            scratch: &mut crate::scratch::StrausScratch,
        ) -> Result<Option<EdwardsPoint>, crate::scratch::ScratchError>
        where
            I: IntoIterator,
            I::Item: Borrow<Scalar>,
            J: IntoIterator<Item = Option<EdwardsPoint>>,
        {
            use crate::scratch::ScratchError;
            use crate::traits::Identity;
            let mut scalars = scalars.into_iter();
            let mut points = points.into_iter();
            let (lo, hi) = scalars.size_hint();
            if hi != Some(lo) || points.size_hint() != (lo, Some(lo)) {
                return Err(ScratchError::TooSmall);
            }
            let n = lo;

            let table_size = core::mem::size_of::<NafLookupTable5<CachedPoint>>();
            let digits_size = core::mem::size_of::<[i8; 256]>();
            let (tables_bytes, digits_bytes) =
                scratch.split(n * table_size, n * digits_size)?;
            let lookup_tables: &mut [NafLookupTable5<CachedPoint>] =
                unsafe { crate::scratch::StrausScratch::cast(tables_bytes) };
            let nafs: &mut [[i8; 256]] = unsafe { crate::scratch::StrausScratch::cast(digits_bytes) };

            let fill = NafLookupTable5::<CachedPoint>::from(&EdwardsPoint::identity());
            for t in lookup_tables.iter_mut() {
                *t = fill;
            }
            for (i, (scalar, point)) in scalars.zip(points).enumerate() {
                let Some(p) = point else {
                    return Ok(None);
                };
                lookup_tables[i] = NafLookupTable5::<CachedPoint>::from(&p);
                nafs[i] = scalar.borrow().non_adjacent_form(5);
            }

            let mut Q = ExtendedPoint::identity();
            for i in (0 .. 256).rev() {
                Q = Q.double();
                for (naf, lookup_table) in nafs.iter().zip(lookup_tables.iter()) {
                    match naf[i].cmp(&0) {
                        Ordering::Greater => {
                            Q = &Q + &lookup_table.select(naf[i] as usize);
                        }
                        Ordering::Less => {
                            Q = &Q - &lookup_table.select(-naf[i] as usize);
                        }
                        Ordering::Equal => {}
                    }
                }
            }
            Ok(Some(Q.into()))
        }
    }

    impl VartimeMultiscalarMul for Straus {
        type Point = EdwardsPoint;

        fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<EdwardsPoint>
        where
            I: IntoIterator,
            I::Item: Borrow<Scalar>,
            J: IntoIterator<Item = Option<EdwardsPoint>>,
        {
            // shlosilo vendor patch (Z5.3 cut 5): small-count inline path
            // (vartime digits are public-challenge material, no Zeroizing —
            // parity with the Vec path below).
            const SMALL: usize = 4;
            let mut scalars = scalars.into_iter();
            let mut points = points.into_iter();
            let (lo, hi) = scalars.size_hint();
            if hi == Some(lo) && lo <= SMALL && points.size_hint() == (lo, Some(lo)) {
                let n = lo;
                let fill = NafLookupTable5::<CachedPoint>::from(&EdwardsPoint::identity());
                let mut lookup_tables = [fill; SMALL];
                let mut nafs = [[0i8; 256]; SMALL];
                for i in 0 .. n {
                    let P = points.next().unwrap()?;
                    lookup_tables[i] = NafLookupTable5::<CachedPoint>::from(&P);
                    nafs[i] = scalars.next().unwrap().borrow().non_adjacent_form(5);
                }
                let mut Q = ExtendedPoint::identity();
                for i in (0 .. 256).rev() {
                    Q = Q.double();
                    for j in 0 .. n {
                        match nafs[j][i].cmp(&0) {
                            Ordering::Greater => {
                                Q = &Q + &lookup_tables[j].select(nafs[j][i] as usize);
                            }
                            Ordering::Less => {
                                Q = &Q - &lookup_tables[j].select(-nafs[j][i] as usize);
                            }
                            Ordering::Equal => {}
                        }
                    }
                }
                return Some(Q.into());
            }

            let nafs: Vec<_> = scalars
                .map(|c| c.borrow().non_adjacent_form(5))
                .collect();
            let lookup_tables: Vec<_> = points
                .map(|P_opt| P_opt.map(|P| NafLookupTable5::<CachedPoint>::from(&P)))
                .collect::<Option<Vec<_>>>()?;

            let mut Q = ExtendedPoint::identity();

            for i in (0..256).rev() {
                Q = Q.double();

                for (naf, lookup_table) in nafs.iter().zip(lookup_tables.iter()) {
                    match naf[i].cmp(&0) {
                        Ordering::Greater => {
                            Q = &Q + &lookup_table.select(naf[i] as usize);
                        }
                        Ordering::Less => {
                            Q = &Q - &lookup_table.select(-naf[i] as usize);
                        }
                        Ordering::Equal => {}
                    }
                }
            }

            Some(Q.into())
        }
    }
}
