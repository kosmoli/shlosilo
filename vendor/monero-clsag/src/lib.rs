#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

use core::ops::Deref as _;
use std_shims::{
  vec::Vec,
  io::{self, Read, Write},
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use subtle::{Choice, ConstantTimeEq as _, ConditionallySelectable as _};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_POINT,
  scalar::Scalar as DScalar,
  traits::{IsIdentity as _, MultiscalarMul as _, VartimePrecomputedMultiscalarMul as _},
  edwards::{EdwardsPoint, VartimeEdwardsPrecomputation},
};
#[cfg(feature = "compile-time-generators")]
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
#[cfg(not(feature = "compile-time-generators"))]
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as ED25519_BASEPOINT_TABLE;

use monero_io::*;
use monero_ed25519::*;

mod decoys;
pub(crate) use decoys::{MAX_RING_SIZE, RING_MAX};
pub use decoys::Decoys;

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use multisig::{ClsagMultisigMaskSender, ClsagAddendum, ClsagMultisig};

#[cfg(all(feature = "std", test))]
mod tests;

#[cfg(feature = "std")]
static G_PRECOMP_CELL: std_shims::sync::LazyLock<VartimeEdwardsPrecomputation> =
  std_shims::sync::LazyLock::new(|| VartimeEdwardsPrecomputation::new([ED25519_BASEPOINT_POINT]));
/// A cached (if std) pre-computation of the Ed25519 generator, G.
#[cfg(feature = "std")]
#[allow(non_snake_case)]
fn G_PRECOMP() -> &'static VartimeEdwardsPrecomputation {
  &G_PRECOMP_CELL
}
/// A cached (if std) pre-computation of the Ed25519 generator, G.
#[cfg(not(feature = "std"))]
#[allow(non_snake_case)]
fn G_PRECOMP() -> VartimeEdwardsPrecomputation {
  VartimeEdwardsPrecomputation::new([ED25519_BASEPOINT_POINT])
}

/// Errors when working with CLSAGs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ClsagError {
  /// The ring was invalid (such as being too small or too large).
  #[error("invalid ring")]
  InvalidRing,
  /// The sign batch or its output slice exceeded `MAX_INPUTS` / its length.
  #[error("too many inputs for the sign batch/output capacity")]
  TooManyInputs,
  /// The discrete logarithm of the key, scaling G, wasn't equivalent to the signing ring member.
  #[error("invalid commitment")]
  InvalidKey,
  /// The commitment opening provided did not match the ring member's.
  #[error("invalid commitment")]
  InvalidCommitment,
  /// The key image was invalid (such as being identity or torsioned)
  #[error("invalid key image")]
  InvalidImage,
  /// The `D` component was invalid.
  #[error("invalid D")]
  InvalidD,
  /// The `s` vector was invalid.
  #[error("invalid s")]
  InvalidS,
  /// The `c1` variable was invalid.
  #[error("invalid c1")]
  InvalidC1,
}

// shlosilo vendor patch (clsag 方案 A, 2026-09-26): zero-semantic-change
// de-alloc. Ring/inputs-sized scratch moves to fixed-capacity `heapless::Vec`
// (RING_MAX) or caller-provided output slices; over-capacity is always an
// EXPLICIT error. Crypto semantics untouched.
use core::mem::MaybeUninit;
use heapless::Vec as HVec;

/// Max inputs per `sign` batch (per-input scratch bound). Over-capacity is an
/// explicit `ClsagError::TooManyInputs`.
pub const MAX_INPUTS: usize = 16;

/// Context on the input being signed for.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClsagContext {
  // The opening for the commitment of the signing ring member
  commitment: Commitment,
  // Selected ring members' positions, signer index, and ring
  decoys: Decoys,
}

impl ClsagContext {
  /// Create a new context, as necessary for signing.
  ///
  /// This function runs in time variable to the length of the ring and the validity of the
  /// arguments.
  pub fn new(decoys: Decoys, commitment: Commitment) -> Result<ClsagContext, ClsagError> {
    // Validate the commitment matches
    if bool::from(!decoys.signer_ring_members()[1].ct_eq(&commitment.commit())) {
      Err(ClsagError::InvalidCommitment)?;
    }

    Ok(ClsagContext { commitment, decoys })
  }
}

#[allow(clippy::large_enum_variant)]
enum Mode {
  Sign { signer_index: u8, A: EdwardsPoint, AH: EdwardsPoint },
  Verify { c1: DScalar, D_serialized: CompressedPoint },
}

// Core of the CLSAG algorithm, applicable to both sign and verify with minimal differences
//
// Said differences are covered via the above Mode
fn core(
  ring: &[[Point; 2]],
  I: &EdwardsPoint,
  pseudo_out: &EdwardsPoint,
  msg_hash: &[u8; 32],
  D_torsion_free: &EdwardsPoint,
  s: &[Scalar],
  A_c1: &Mode,
) -> ((EdwardsPoint, DScalar, DScalar), DScalar) {
  let n = ring.len();

  let images_precomp = match A_c1 {
    Mode::Sign { .. } => None,
    Mode::Verify { .. } => Some(VartimeEdwardsPrecomputation::new([I, D_torsion_free])),
  };
  let D_inv_eight = D_torsion_free * Scalar::INV_EIGHT.into();

  // Generate the transcript
  // Instead of generating multiple, a single transcript is created and then edited as needed
  const PREFIX: &[u8] = b"CLSAG_";
  #[rustfmt::skip]
  const AGG_0: &[u8]  =       b"agg_0";
  #[rustfmt::skip]
  const ROUND: &[u8]  =       b"round";
  const PREFIX_AGG_0_LEN: usize = PREFIX.len() + AGG_0.len();

  // shlosilo vendor patch: fixed-capacity transcript buffer. `n <= RING_MAX`
  // is enforced by `Decoys`; the exact worst case is ((2 * 16) + 5) * 32.
  let mut to_hash = HVec::<u8, { ((2 * RING_MAX) + 5) * 32 }>::new();
  to_hash.extend(PREFIX.iter().copied());
  to_hash.extend(AGG_0.iter().copied());
  to_hash.extend([0; 32 - PREFIX_AGG_0_LEN]);

  let mut P = HVec::<_, RING_MAX>::new();
  for member in ring {
    P.push(member[0].into()).ok().unwrap();
    to_hash.extend(member[0].compress().to_bytes().iter().copied());
  }

  let mut C = HVec::<_, RING_MAX>::new();
  for member in ring {
    C.push(member[1].into() - pseudo_out).ok().unwrap();
    to_hash.extend(member[1].compress().to_bytes().iter().copied());
  }

  to_hash.extend(I.compress().to_bytes().iter().copied());
  match A_c1 {
    Mode::Sign { .. } => {
      to_hash.extend(D_inv_eight.compress().to_bytes().iter().copied());
    }
    Mode::Verify { D_serialized, .. } => {
      to_hash.extend(D_serialized.to_bytes().iter().copied());
    }
  }
  to_hash.extend(pseudo_out.compress().to_bytes().iter().copied());
  // mu_P with agg_0
  let mu_P = Scalar::hash(&to_hash).into();
  // mu_C with agg_1
  to_hash[PREFIX_AGG_0_LEN - 1] = b'1';
  let mu_C = Scalar::hash(&to_hash).into();

  // Truncate it for the round transcript, altering the DST as needed
  to_hash.truncate(((2 * n) + 1) * 32);
  for i in 0 .. ROUND.len() {
    to_hash[PREFIX.len() + i] = ROUND[i];
  }
  // Unfortunately, it's I D pseudo_out instead of pseudo_out I D, meaning this needs to be
  // truncated just to add it back
  to_hash.extend(pseudo_out.compress().to_bytes().iter().copied());
  to_hash.extend(msg_hash.iter().copied());

  // Configure the loop based on if we're signing or verifying
  let start;
  let end;
  let iter_end;
  let mut c;
  match A_c1 {
    Mode::Sign { signer_index, A, AH } => {
      let signer_index = usize::from(*signer_index);
      start = signer_index + 1;
      end = signer_index + n;
      iter_end = 2 * n;
      to_hash.extend(A.compress().to_bytes().iter().copied());
      to_hash.extend(AH.compress().to_bytes().iter().copied());
      c = Scalar::hash(&to_hash).into();
    }

    Mode::Verify { c1, .. } => {
      start = 0;
      end = n;
      iter_end = n;
      c = *c1;
    }
  }

  // Perform the core loop
  let mut in_range = Choice::from(0);
  let mut c1 = c;
  for mut i in 0 .. iter_end {
    in_range |= i.ct_eq(&start);
    in_range ^= i.ct_eq(&end);
    i %= n;

    let c_p = mu_P * c;
    let c_c = mu_C * c;

    // (s_i * G) + (c_p * P_i) + (c_c * C_i)
    let L = match A_c1 {
      Mode::Sign { .. } => EdwardsPoint::multiscalar_mul(
        [s[i].into(), c_p, c_c],
        [ED25519_BASEPOINT_POINT, P[i], C[i]],
      ),
      Mode::Verify { .. } => {
        G_PRECOMP().vartime_mixed_multiscalar_mul([s[i].into()], [c_p, c_c], [P[i], C[i]])
      }
    };

    let PH = Point::biased_hash(P[i].compress().0).into();

    // (c_p * I) + (c_c * D) + (s_i * PH)
    let R = match A_c1 {
      Mode::Sign { .. } => {
        EdwardsPoint::multiscalar_mul([c_p, c_c, s[i].into()], [I, D_torsion_free, &PH])
      }
      Mode::Verify { .. } => images_precomp
        .as_ref()
        .expect("value populated when verifying wasn't populated")
        .vartime_mixed_multiscalar_mul([c_p, c_c], [s[i].into()], [PH]),
    };

    to_hash.truncate(((2 * n) + 3) * 32);
    to_hash.extend(L.compress().to_bytes().iter().copied());
    to_hash.extend(R.compress().to_bytes().iter().copied());
    c.conditional_assign(&Scalar::hash(&to_hash).into(), in_range);

    c1.conditional_assign(&c, in_range & i.ct_eq(&(n - 1)));
  }

  // This first tuple is needed to continue signing, the latter is the c to be tested/worked with
  ((D_inv_eight, c * mu_P, c * mu_C), c1)
}

/// The CLSAG signature, as used in Monero.
///
/// shlosilo vendor patch: `Zeroize` is manual (the `s` field is a fixed-capacity
/// `heapless::Vec`, wiped element-wise + cleared — `Vec::zeroize` parity).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Clsag {
  /// The difference of the commitment randomnesses, scaling the key image generator.
  pub D: CompressedPoint,
  /// The responses for each ring member.
  pub s: HVec<Scalar, RING_MAX>,
  /// The first challenge in the ring.
  pub c1: Scalar,
}

struct ClsagSignCore {
  incomplete_clsag: Clsag,
  pseudo_out: EdwardsPoint,
  key_challenge: DScalar,
  challenged_mask: DScalar,
}

impl Zeroize for Clsag {
  fn zeroize(&mut self) {
    self.D.zeroize();
    for response in self.s.iter_mut() {
      response.zeroize();
    }
    self.s.clear();
    self.c1.zeroize();
  }
}

impl Clsag {
  // Sign core is the extension of core as needed for signing, yet is shared between single signer
  // and multisig, hence why it's still core
  fn sign_core<R: RngCore + CryptoRng>(
    rng: &mut R,
    I: &EdwardsPoint,
    input: &ClsagContext,
    mask: DScalar,
    msg_hash: &[u8; 32],
    A: EdwardsPoint,
    AH: EdwardsPoint,
  ) -> ClsagSignCore {
    let signer_index = input.decoys.signer_index();

    let pseudo_out = Commitment::new(Scalar::from(mask), input.commitment.amount).commit().into();
    let mask_delta = input.commitment.mask.into() - mask;

    let H = Point::biased_hash(input.decoys.signer_ring_members()[0].compress().to_bytes()).into();
    let D = H * mask_delta;
    let mut s = HVec::new();
    for _ in 0 .. input.decoys.ring().len() {
      s.push(Scalar::random(rng)).ok().unwrap();
    }
    let ((D, c_p, c_c), c1) = core(
      input.decoys.ring(),
      I,
      &pseudo_out,
      msg_hash,
      &D,
      &s,
      &Mode::Sign { signer_index, A, AH },
    );

    ClsagSignCore {
      incomplete_clsag: Clsag {
        D: CompressedPoint::from(D.compress().to_bytes()),
        s,
        c1: Scalar::from(c1),
      },
      pseudo_out,
      key_challenge: c_p,
      challenged_mask: c_c * mask_delta,
    }
  }

  /// Sign CLSAG signatures for the provided inputs.
  ///
  /// Monero ensures the rerandomized input commitments have the same value as the outputs by
  /// checking `sum(rerandomized_input_commitments) - sum(output_commitments) == 0`. This requires
  /// not only the amounts balance, yet also
  /// `sum(input_commitment_masks) - sum(output_commitment_masks)`.
  ///
  /// Monero solves this by following the wallet protocol to determine each output commitment's
  /// randomness, then using random masks for all but the last input. The last input is
  /// rerandomized to the necessary mask for the equation to balance.
  ///
  /// Due to Monero having this behavior, it only makes sense to sign CLSAGs as a list, hence this
  /// API being the way it is.
  ///
  /// `inputs` is of the form (discrete logarithm of the key, context).
  ///
  /// `sum_outputs` is for the sum of the output commitments' masks.
  ///
  /// This function runs in time variable to the validity of the arguments and the public data.
  ///
  /// WARNING: This follows the Fiat-Shamir transcript format used by the Monero protocol, which
  /// makes assumptions on what has already been transcripted and bound to within `msg_hash`. Do
  /// not use this if you don't know what you're doing.
  /// shlosilo vendor patch: `inputs` is a mutable borrow (the secrets are
  /// wiped in place at the same point the old consuming API zeroized them, and
  /// the `Zeroizing` drop is the caller's backstop), results are written into
  /// `out` (the caller owns the output memory), and the filled count is
  /// returned. Over-capacity (`inputs.len() > MAX_INPUTS` or
  /// `out.len() < inputs.len()`) is an EXPLICIT `ClsagError::TooManyInputs`.
  pub fn sign<R: RngCore + CryptoRng>(
    rng: &mut R,
    inputs: &mut [(Zeroizing<Scalar>, ClsagContext)],
    sum_outputs: Scalar,
    msg_hash: [u8; 32],
    out: &mut [MaybeUninit<(Clsag, Point)>],
  ) -> Result<usize, ClsagError> {
    if (inputs.len() > MAX_INPUTS) || (out.len() < inputs.len()) {
      Err(ClsagError::TooManyInputs)?;
    }
    // Create the key images
    let mut key_image_generators = HVec::<_, MAX_INPUTS>::new();
    let mut key_images = HVec::<_, MAX_INPUTS>::new();
    for input in inputs.iter() {
      let key = Zeroizing::new((*input.0.deref()).into());
      let public_key = input.1.decoys.signer_ring_members()[0].into();

      // Check the key is consistent
      if bool::from(!(ED25519_BASEPOINT_TABLE * key.deref()).ct_eq(&public_key)) {
        Err(ClsagError::InvalidKey)?;
      }

      let key_image_generator = Point::biased_hash(public_key.compress().0).into();
      key_image_generators.push(key_image_generator).ok().unwrap();
      key_images.push(key_image_generator * key.deref()).ok().unwrap();
    }

    let mut filled = 0usize;
    let mut sum_pseudo_outs = DScalar::ZERO;
    for i in 0 .. inputs.len() {
      let mask;
      // If this is the last input, set the mask as described above
      if i == (inputs.len() - 1) {
        mask = sum_outputs.into() - sum_pseudo_outs;
      } else {
        mask = Scalar::random(rng).into();
        sum_pseudo_outs += mask;
      }

      let mut nonce = Zeroizing::new(Scalar::random(rng).into());
      let ClsagSignCore { mut incomplete_clsag, pseudo_out, key_challenge, challenged_mask } =
        Clsag::sign_core(
          rng,
          &key_images[i],
          &inputs[i].1,
          mask,
          &msg_hash,
          nonce.deref() * ED25519_BASEPOINT_TABLE,
          nonce.deref() * key_image_generators[i],
        );
      {
        // Effectively r - c x, except c x is (c_p x) + (c_c z), where z is the delta between the
        // ring member's commitment and our pseudo-out commitment (which will only have a known
        // discrete log over G if the amounts cancel out)
        let signer_s = Scalar::from(
          nonce.deref() -
            ((key_challenge * Zeroizing::new((*inputs[i].0.deref()).into()).deref()) +
              challenged_mask),
        );
        for s_index in 0 ..= MAX_RING_SIZE {
          if usize::from(s_index) == incomplete_clsag.s.len() {
            break;
          }
          let signer_index = s_index.ct_eq(&inputs[i].1.decoys.signer_index());
          incomplete_clsag.s[usize::from(s_index)].conditional_assign(&signer_s, signer_index);
        }
      }
      let clsag = incomplete_clsag;

      // Zeroize private keys and nonces.
      inputs[i].0.zeroize();
      nonce.zeroize();

      // shlosilo vendor patch: manual fill (heapless `FromIterator` silently
      // truncates over capacity — never used here).
      debug_assert!({
        let mut ring_c = HVec::<[CompressedPoint; 2], RING_MAX>::new();
        for r in inputs[i].1.decoys.ring() {
          ring_c.push([r[0].compress(), r[1].compress()]).ok().unwrap();
        }
        clsag
          .verify(
            &ring_c,
            &key_images[i].compress().to_bytes().into(),
            &pseudo_out.compress().to_bytes().into(),
            &msg_hash
          )
          .is_ok()
      });

      out[i].write((clsag, Point::from(pseudo_out)));
      filled += 1;
    }

    Ok(filled)
  }

  /// Verify a CLSAG signature for the provided context.
  ///
  /// WARNING: This follows the Fiat-Shamir transcript format used by the Monero protocol, which
  /// makes assumptions on what has already been transcripted and bound to within `msg_hash`. Do
  /// not use this if you don't know what you're doing.
  pub fn verify(
    &self,
    ring: &[[CompressedPoint; 2]],
    I: &CompressedPoint,
    pseudo_out: &CompressedPoint,
    msg_hash: &[u8; 32],
  ) -> Result<(), ClsagError> {
    // Preliminary checks
    // s, c1, and points must also be encoded canonically, which is checked at time of decode
    if ring.is_empty() {
      Err(ClsagError::InvalidRing)?;
    }
    if ring.len() != self.s.len() {
      Err(ClsagError::InvalidS)?;
    }

    let I = I.decompress().ok_or(ClsagError::InvalidImage)?;
    let Some(I) = I.key_image() else { Err(ClsagError::InvalidImage)? };

    let Some(pseudo_out) = pseudo_out.decompress() else {
      return Err(ClsagError::InvalidCommitment);
    };
    let Some(D) = self.D.decompress() else {
      return Err(ClsagError::InvalidD);
    };
    let D_torsion_free = D.into().mul_by_cofactor();
    if D_torsion_free.is_identity() {
      Err(ClsagError::InvalidD)?;
    }

    let ring = ring
      .into_iter()
      .map(|r| Some([r[0].decompress()?, r[1].decompress()?]))
      .collect::<Option<Vec<_>>>()
      .ok_or(ClsagError::InvalidRing)?;

    let (_, c1) = core(
      &ring,
      &I,
      &pseudo_out.into(),
      msg_hash,
      &D_torsion_free,
      &self.s,
      &Mode::Verify { c1: self.c1.into(), D_serialized: self.D },
    );
    if c1 != self.c1.into() {
      Err(ClsagError::InvalidC1)?;
    }
    Ok(())
  }

  /// Write a CLSAG.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_raw_vec(Scalar::write, &self.s, w)?;
    self.c1.write(w)?;
    self.D.write(w)
  }

  /// Read a CLSAG.
  pub fn read<R: Read>(decoys: usize, r: &mut R) -> io::Result<Clsag> {
    // shlosilo vendor patch: fixed-capacity decode (mirrors `read_raw_vec`'s
    // wire format) with an EXPLICIT bound error instead of Vec allocation.
    if decoys > RING_MAX {
      Err(io::Error::other("Decoys ring too large"))?;
    }
    let mut s = HVec::<Scalar, RING_MAX>::new();
    for _ in 0 .. decoys {
      s.push(Scalar::read(r)?).ok().unwrap();
    }
    Ok(Clsag { s, c1: Scalar::read(r)?, D: CompressedPoint::read(r)? })
  }
}
