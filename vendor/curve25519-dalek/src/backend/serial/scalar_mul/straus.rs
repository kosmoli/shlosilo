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

//! Implementation of the interleaved window method, also known as Straus' method.

#![allow(non_snake_case)]

use alloc::vec::Vec;

use core::borrow::Borrow;
use core::cmp::Ordering;

use crate::edwards::EdwardsPoint;
use crate::scalar::Scalar;
use crate::traits::MultiscalarMul;
use crate::traits::VartimeMultiscalarMul;

/// Perform multiscalar multiplication by the interleaved window
/// method, also known as Straus' method (since it was apparently
/// [first published][solution] by Straus in 1964, as a solution to [a
/// problem][problem] posted in the American Mathematical Monthly in
/// 1963).
///
/// It is easy enough to reinvent, and has been repeatedly.  The basic
/// idea is that when computing
/// \\[
/// Q = s_1 P_1 + \cdots + s_n P_n
/// \\]
/// by means of additions and doublings, the doublings can be shared
/// across the \\( P_i \\\).
///
/// We implement two versions, a constant-time algorithm using fixed
/// windows and a variable-time algorithm using sliding windows.  They
/// are slight variations on the same idea, and are described in more
/// detail in the respective implementations.
///
/// [solution]: https://www.jstor.org/stable/2310929
/// [problem]: https://www.jstor.org/stable/2312273
pub struct Straus {}

impl MultiscalarMul for Straus {
    type Point = EdwardsPoint;

    /// Constant-time Straus using a fixed window of size \\(4\\).
    ///
    /// Our goal is to compute
    /// \\[
    /// Q = s_1 P_1 + \cdots + s_n P_n.
    /// \\]
    ///
    /// For each point \\( P_i \\), precompute a lookup table of
    /// \\[
    /// P_i, 2P_i, 3P_i, 4P_i, 5P_i, 6P_i, 7P_i, 8P_i.
    /// \\]
    ///
    /// For each scalar \\( s_i \\), compute its radix-\\(2^4\\)
    /// signed digits \\( s_{i,j} \\), i.e.,
    /// \\[
    ///    s_i = s_{i,0} + s_{i,1} 16^1 + ... + s_{i,63} 16^{63},
    /// \\]
    /// with \\( -8 \leq s_{i,j} < 8 \\).  Since \\( 0 \leq |s_{i,j}|
    /// \leq 8 \\), we can retrieve \\( s_{i,j} P_i \\) from the
    /// lookup table with a conditional negation: using signed
    /// digits halves the required table size.
    ///
    /// Then as in the single-base fixed window case, we have
    /// \\[
    /// \begin{aligned}
    /// s_i P_i &= P_i (s_{i,0} +     s_{i,1} 16^1 + \cdots +     s_{i,63} 16^{63})   \\\\
    /// s_i P_i &= P_i s_{i,0} + P_i s_{i,1} 16^1 + \cdots + P_i s_{i,63} 16^{63}     \\\\
    /// s_i P_i &= P_i s_{i,0} + 16(P_i s_{i,1} + 16( \cdots +16P_i s_{i,63})\cdots )
    /// \end{aligned}
    /// \\]
    /// so each \\( s_i P_i \\) can be computed by alternately adding
    /// a precomputed multiple \\( P_i s_{i,j} \\) of \\( P_i \\) and
    /// repeatedly doubling.
    ///
    /// Now consider the two-dimensional sum
    /// \\[
    /// \begin{aligned}
    /// s\_1 P\_1 &=& P\_1 s\_{1,0} &+& 16 (P\_1 s\_{1,1} &+& 16 ( \cdots &+& 16 P\_1 s\_{1,63}&) \cdots ) \\\\
    ///     +     & &      +        & &      +            & &             & &     +            &           \\\\
    /// s\_2 P\_2 &=& P\_2 s\_{2,0} &+& 16 (P\_2 s\_{2,1} &+& 16 ( \cdots &+& 16 P\_2 s\_{2,63}&) \cdots ) \\\\
    ///     +     & &      +        & &      +            & &             & &     +            &           \\\\
    /// \vdots    & &  \vdots       & &   \vdots          & &             & &  \vdots          &           \\\\
    ///     +     & &      +        & &      +            & &             & &     +            &           \\\\
    /// s\_n P\_n &=& P\_n s\_{n,0} &+& 16 (P\_n s\_{n,1} &+& 16 ( \cdots &+& 16 P\_n s\_{n,63}&) \cdots )
    /// \end{aligned}
    /// \\]
    /// The sum of the left-hand column is the result \\( Q \\); by
    /// computing the two-dimensional sum on the right column-wise,
    /// top-to-bottom, then right-to-left, we need to multiply by \\(
    /// 16\\) only once per column, sharing the doublings across all
    /// of the input points.
    fn multiscalar_mul<I, J>(scalars: I, points: J) -> EdwardsPoint
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<EdwardsPoint>,
    {
        use crate::backend::serial::curve_models::ProjectiveNielsPoint;
        use crate::traits::Identity;
        use crate::window::LookupTable;

        // shlosilo vendor patch (Z5.3 cut 5): small-count inline path (the
        // device straus — CLSAG/next_G_H hot calls are 2-3 terms). Same
        // tables/digits/loop; storage only. Secret digits stay wiped.
        const SMALL: usize = 4;
        let mut scalars = scalars.into_iter();
        let mut points = points.into_iter();
        let (lo, hi) = scalars.size_hint();
        if hi == Some(lo) && lo <= SMALL && points.size_hint() == (lo, Some(lo)) {
            let n = lo;
            let fill = LookupTable::<ProjectiveNielsPoint>::from(&EdwardsPoint::identity());
            let mut lookup_tables = [fill; SMALL];
            let mut scalar_digits = [[0i8; 64]; SMALL];
            for i in 0 .. n {
                lookup_tables[i] =
                    LookupTable::<ProjectiveNielsPoint>::from(points.next().unwrap().borrow());
                scalar_digits[i] = scalars.next().unwrap().borrow().as_radix_16();
            }
            let mut Q = EdwardsPoint::identity();
            for j in (0 .. 64).rev() {
                Q = Q.mul_by_pow_2(4);
                for i in 0 .. n {
                    let R_i = lookup_tables[i].select(scalar_digits[i][j]);
                    Q = (&Q + &R_i).as_extended();
                }
            }
            #[cfg(feature = "zeroize")]
            zeroize::Zeroize::zeroize(&mut scalar_digits);
            return Q;
        }

        let lookup_tables: Vec<_> = points
            .map(|point| LookupTable::<ProjectiveNielsPoint>::from(point.borrow()))
            .collect();

        // This puts the scalar digits into a heap-allocated Vec.
        // To ensure that these are erased, pass ownership of the Vec into a
        // Zeroizing wrapper.
        #[cfg_attr(not(feature = "zeroize"), allow(unused_mut))]
        let mut scalar_digits: Vec<_> = scalars
            .map(|s| s.borrow().as_radix_16())
            .collect();

        let mut Q = EdwardsPoint::identity();
        for j in (0..64).rev() {
            Q = Q.mul_by_pow_2(4);
            let it = scalar_digits.iter().zip(lookup_tables.iter());
            for (s_i, lookup_table_i) in it {
                // R_i = s_{i,j} * P_i
                let R_i = lookup_table_i.select(s_i[j]);
                // Q = Q + R_i
                Q = (&Q + &R_i).as_extended();
            }
        }

        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(&mut scalar_digits);

        Q
    }
}

impl Straus {
    /// shlosilo vendor patch (Z5.3 D-cut): ct Straus over caller scratch
    /// (device path). Same tables/digits/loop as `multiscalar_mul`; the
    /// secret-derived radix-16 digits are zeroized on every exit path.
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
        use crate::backend::serial::curve_models::ProjectiveNielsPoint;
        use crate::scratch::ScratchError;
        use crate::traits::Identity;
        use crate::window::LookupTable;
        let mut scalars = scalars.into_iter();
        let mut points = points.into_iter();
        let (lo, hi) = scalars.size_hint();
        if hi != Some(lo) || points.size_hint() != (lo, Some(lo)) {
            return Err(ScratchError::TooSmall);
        }
        let n = lo;
        let table_size = core::mem::size_of::<LookupTable<ProjectiveNielsPoint>>();
        let digits_size = core::mem::size_of::<[i8; 64]>();
        let (tables_bytes, digits_bytes) = scratch.split(n * table_size, n * digits_size)?;
        let lookup_tables: &mut [LookupTable<ProjectiveNielsPoint>] =
            unsafe { crate::scratch::StrausScratch::cast(tables_bytes) };
        let scalar_digits: &mut [[i8; 64]] =
            unsafe { crate::scratch::StrausScratch::cast(digits_bytes) };
        let fill = LookupTable::<ProjectiveNielsPoint>::from(&EdwardsPoint::identity());
        for t in lookup_tables.iter_mut() {
            *t = fill;
        }
        for (i, (scalar, point)) in scalars.zip(points).enumerate() {
            lookup_tables[i] = LookupTable::<ProjectiveNielsPoint>::from(point.borrow());
            scalar_digits[i] = scalar.borrow().as_radix_16();
        }
        let mut Q = EdwardsPoint::identity();
        for j in (0 .. 64).rev() {
            Q = Q.mul_by_pow_2(4);
            for (s_i, lookup_table_i) in scalar_digits.iter().zip(lookup_tables.iter()) {
                let R_i = lookup_table_i.select(s_i[j]);
                Q = (&Q + &R_i).as_extended();
            }
        }
        for d in scalar_digits.iter_mut() {
            for b in d.iter_mut() {
                *b = 0;
            }
        }
        Ok(Q)
    }

    /// shlosilo vendor patch (Z5.3 D-cut): vartime Straus over caller scratch
    /// (NAF digits public; no wipe, parity with the allocating path).
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
        use crate::backend::serial::curve_models::{
            CompletedPoint, ProjectiveNielsPoint, ProjectivePoint,
        };
        use crate::scratch::ScratchError;
        use crate::traits::Identity;
        use crate::window::NafLookupTable5;
        let mut scalars = scalars.into_iter();
        let mut points = points.into_iter();
        let (lo, hi) = scalars.size_hint();
        if hi != Some(lo) || points.size_hint() != (lo, Some(lo)) {
            return Err(ScratchError::TooSmall);
        }
        let n = lo;
        let table_size = core::mem::size_of::<NafLookupTable5<ProjectiveNielsPoint>>();
        let digits_size = core::mem::size_of::<[i8; 256]>();
        let (tables_bytes, digits_bytes) = scratch.split(n * table_size, n * digits_size)?;
        let lookup_tables: &mut [NafLookupTable5<ProjectiveNielsPoint>] =
            unsafe { crate::scratch::StrausScratch::cast(tables_bytes) };
        let nafs: &mut [[i8; 256]] = unsafe { crate::scratch::StrausScratch::cast(digits_bytes) };
        let fill = NafLookupTable5::<ProjectiveNielsPoint>::from(&EdwardsPoint::identity());
        for t in lookup_tables.iter_mut() {
            *t = fill;
        }
        for (i, (scalar, point)) in scalars.zip(points).enumerate() {
            let Some(p) = point else {
                return Ok(None);
            };
            lookup_tables[i] = NafLookupTable5::<ProjectiveNielsPoint>::from(&p);
            nafs[i] = scalar.borrow().non_adjacent_form(5);
        }
        let mut r = ProjectivePoint::identity();
        for i in (0 .. 256).rev() {
            let mut t: CompletedPoint = r.double();
            for (naf, lookup_table) in nafs.iter().zip(lookup_tables.iter()) {
                match naf[i].cmp(&0) {
                    Ordering::Greater => {
                        t = &t.as_extended() + &lookup_table.select(naf[i] as usize)
                    }
                    Ordering::Less => t = &t.as_extended() - &lookup_table.select(-naf[i] as usize),
                    Ordering::Equal => {}
                }
            }
            r = t.as_projective();
        }
        Ok(Some(r.as_extended()))
    }
}

impl VartimeMultiscalarMul for Straus {
    type Point = EdwardsPoint;

    /// Variable-time Straus using a non-adjacent form of width \\(5\\).
    ///
    /// This is completely similar to the constant-time code, but we
    /// use a non-adjacent form for the scalar, and do not do table
    /// lookups in constant time.
    ///
    /// The non-adjacent form has signed, odd digits.  Using only odd
    /// digits halves the table size (since we only need odd
    /// multiples), or gives fewer additions for the same table size.
    fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<EdwardsPoint>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<EdwardsPoint>>,
    {
        use crate::backend::serial::curve_models::{
            CompletedPoint, ProjectiveNielsPoint, ProjectivePoint,
        };
        use crate::traits::Identity;
        use crate::window::NafLookupTable5;

        // shlosilo vendor patch (Z5.3 cut 5): small-count inline path (public
        // challenge digits, no wipe — parity with the Vec path).
        const SMALL: usize = 4;
        let mut scalars = scalars.into_iter();
        let mut points = points.into_iter();
        let (lo, hi) = scalars.size_hint();
        if hi == Some(lo) && lo <= SMALL && points.size_hint() == (lo, Some(lo)) {
            let n = lo;
            let fill = NafLookupTable5::<ProjectiveNielsPoint>::from(&EdwardsPoint::identity());
            let mut lookup_tables = [fill; SMALL];
            let mut nafs = [[0i8; 256]; SMALL];
            for i in 0 .. n {
                let P = points.next().unwrap()?;
                lookup_tables[i] = NafLookupTable5::<ProjectiveNielsPoint>::from(&P);
                nafs[i] = scalars.next().unwrap().borrow().non_adjacent_form(5);
            }
            let mut r = ProjectivePoint::identity();
            for i in (0 .. 256).rev() {
                let mut t: CompletedPoint = r.double();
                for j in 0 .. n {
                    match nafs[j][i].cmp(&0) {
                        Ordering::Greater => {
                            t = &t.as_extended() + &lookup_tables[j].select(nafs[j][i] as usize)
                        }
                        Ordering::Less => {
                            t = &t.as_extended() - &lookup_tables[j].select(-nafs[j][i] as usize)
                        }
                        Ordering::Equal => {}
                    }
                }
                r = t.as_projective();
            }
            return Some(r.as_extended());
        }

        let nafs: Vec<_> = scalars
            .map(|c| c.borrow().non_adjacent_form(5))
            .collect();

        let lookup_tables = points
            .map(|P_opt| P_opt.map(|P| NafLookupTable5::<ProjectiveNielsPoint>::from(&P)))
            .collect::<Option<Vec<_>>>()?;

        let mut r = ProjectivePoint::identity();

        for i in (0..256).rev() {
            let mut t: CompletedPoint = r.double();

            for (naf, lookup_table) in nafs.iter().zip(lookup_tables.iter()) {
                match naf[i].cmp(&0) {
                    Ordering::Greater => {
                        t = &t.as_extended() + &lookup_table.select(naf[i] as usize)
                    }
                    Ordering::Less => t = &t.as_extended() - &lookup_table.select(-naf[i] as usize),
                    Ordering::Equal => {}
                }
            }

            r = t.as_projective();
        }

        Some(r.as_extended())
    }
}
