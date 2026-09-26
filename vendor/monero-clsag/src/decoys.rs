#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io;

// shlosilo vendor patch (clsag 方案 A, 2026-09-26): zero-semantic-change
// de-alloc. Ring-sized storage moves to fixed-capacity `heapless::Vec`
// (capacity RING_MAX); every over-capacity path is an EXPLICIT error
// (`ClsagError::InvalidRing` / `io::Error`), never a silent truncation.
// Crypto semantics (validation, wire format, transcripts) are untouched. */
use heapless::Vec as HVec;

#[rustfmt::skip]
use subtle::{Choice, ConstantTimeEq as _, ConstantTimeLess as _, ConstantTimeGreater as _, ConditionallySelectable as _};
use zeroize::Zeroize;

use monero_io::*;
use monero_ed25519::*;

/// Decoy data, as used for producing a CLSAG.
///
/// shlosilo vendor patch: ring storage is fixed-capacity (`HVec<_, RING_MAX>`);
/// `Zeroize` is implemented manually because `offsets`/`ring` are PUBLIC data
/// (block positions and public keys) — wiping them protects nothing, but the
/// trait is kept for `ZeroizeOnDrop` bound compatibility.
#[derive(Clone)]
pub struct Decoys {
  offsets: HVec<u64, RING_MAX>,
  signer_index: u8,
  ring: HVec<[Point; 2], RING_MAX>,
}

impl Zeroize for Decoys {
  fn zeroize(&mut self) {
    for offset in self.offsets.iter_mut() {
      offset.zeroize();
    }
    self.offsets.clear();
    self.signer_index.zeroize();
    for pair in self.ring.iter_mut() {
      pair[0].zeroize();
      pair[1].zeroize();
    }
    self.ring.clear();
  }
}

/// Wipe-on-drop parity with the previous `#[derive(ZeroizeOnDrop)]`
/// (the derive cannot reach `heapless::Vec` fields; the manual impl wipes
/// element-wise and clears the lengths, matching `Vec::zeroize` semantics).
impl Drop for Decoys {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl core::fmt::Debug for Decoys {
  /// This implementation of `fmt` reveals the ring but not the index of the signer.
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("Decoys")
      .field("offsets", &self.offsets)
      .field("ring", &self.ring)
      .finish_non_exhaustive()
  }
}

/*
  shlosilo vendor patch: the fixed-capacity ring bound. The Monero protocol's
  ring size is `16` (the next hard fork removes rings entirely); the upstream
  generality (u8::MAX) is traded for caller-free storage with an EXPLICIT
  over-capacity rejection (`new` returns `None`, decode returns `io::Error`).
*/
pub(crate) const MAX_RING_SIZE: u8 = 16;

/// Fixed-capacity bound shared by every ring-sized buffer in this crate.
pub const RING_MAX: usize = 16;

/// Worst-case `Decoys` encoding size: 1 length varint + 16 offsets (10-byte
/// varints) + 1 signer byte + 16 ring pairs (64 bytes each) = 1187.
pub const SERIALIZE_MAX: usize = 1200;

#[allow(clippy::len_without_is_empty)]
impl Decoys {
  /// This equality runs in constant-time if the decoys are the same length.
  ///
  /// This is not a public function as it is not part of our API commitment.
  #[doc(hidden)]
  pub fn ct_eq(&self, other: &Self) -> Choice {
    let ring = self.ring.len().ct_eq(&other.ring.len()) &
      self.ring.iter().zip(&other.ring).fold(Choice::from(1u8), |accum, (lhs, rhs)| {
        accum & lhs.as_slice().ct_eq(rhs.as_slice())
      });
    self.offsets.ct_eq(&other.offsets) & self.signer_index.ct_eq(&other.signer_index) & ring
  }

  /// Create a new instance of decoy data.
  ///
  /// `offsets` are the positions of each ring member within the Monero blockchain, offset from the
  /// prior member's position (with the initial ring member offset from 0).
  ///
  /// This function runs in time variable to the length of the ring and the validity of the
  /// arguments.
  pub fn new(offsets: &[u64], signer_index: u8, ring: &[[Point; 2]]) -> Option<Self> {
    // We check the low eight bits are equal, then check the remaining bits are zero,
    // due to the lack of `usize::ct_gt`
    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    let ring_len_does_not_exceed_max =
      (ring.len() >> 8).ct_eq(&0) & (!(ring.len() as u8).ct_gt(&MAX_RING_SIZE));
    // This cast is safe `ring.len()` is checked to not exceed a `u8` constant
    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    let signer_index_points_to_ring_member = signer_index.ct_lt(&(ring.len() as u8));
    let offsets_align_with_ring = offsets.len().ct_eq(&ring.len());

    // Check these offsets form representable positions
    let mut offsets_representable = Choice::from(1u8);
    {
      let mut sum = 0u64;
      for (i, offset) in offsets.iter().enumerate() {
        let new_sum = sum.wrapping_add(*offset);
        if i != 0 {
          // This simultaneously checks we didn't underflow and that this offset was non-zero
          offsets_representable &= new_sum.ct_gt(&sum);
        }
        sum = new_sum;
      }
    }

    if !bool::from(
      ring_len_does_not_exceed_max &
        signer_index_points_to_ring_member &
        offsets_align_with_ring &
        offsets_representable,
    ) {
      return None;
    }
    // Validation passed => the lengths are <= RING_MAX; the copies cannot fail.
    let mut offsets_buf = HVec::new();
    offsets_buf.extend_from_slice(offsets).ok().unwrap();
    let mut ring_buf = HVec::new();
    ring_buf.extend_from_slice(ring).ok().unwrap();
    Some(Decoys { offsets: offsets_buf, signer_index, ring: ring_buf })
  }

  /// The length of the ring.
  pub fn len(&self) -> usize {
    self.offsets.len()
  }

  /// The positions of the ring members within the Monero blockchain, as their offsets.
  ///
  /// The list is formatted as the position of the first ring member, then the offset from each
  /// ring member to its prior.
  pub fn offsets(&self) -> &[u64] {
    &self.offsets
  }

  /// The positions of the ring members within the Monero blockchain.
  ///
  /// This function is runs in time variable to the length of the ring.
  pub fn positions(&self) -> HVec<u64, RING_MAX> {
    let mut res = HVec::new();
    res.push(self.offsets[0]).ok().unwrap();
    for m in 1 .. self.len() {
      res.push(res[m - 1] + self.offsets[m]).ok().unwrap();
    }
    res
  }

  /// The index of the signer within the ring.
  pub fn signer_index(&self) -> u8 {
    self.signer_index
  }

  /// The ring.
  pub fn ring(&self) -> &[[Point; 2]] {
    &self.ring
  }

  /// The [key, commitment] pair of the signer.
  ///
  /// This function is runs in time variable to the length of the ring.
  pub fn signer_ring_members(&self) -> [Point; 2] {
    let mut result = self.ring[0];
    for (i, member) in self.ring.iter().enumerate().skip(1) {
      let select = i.ct_eq(&usize::from(self.signer_index));
      result[0] = <_>::conditional_select(&result[0], &member[0], select);
      result[1] = <_>::conditional_select(&result[1], &member[1], select);
    }
    result
  }

  /// Write the Decoys.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn write(&self, w: &mut impl io::Write) -> io::Result<()> {
    write_vec(VarInt::write, &self.offsets, w)?;
    w.write_all(&[self.signer_index])?;
    write_raw_vec(
      |pair, w| {
        pair[0].compress().write(w)?;
        pair[1].compress().write(w)
      },
      &self.ring,
      w,
    )
  }

  /// shlosilo vendor patch: the caller-owned serialize form. Writes the same
  /// bytes the old `serialize() -> Vec<u8>` produced into `out`, returning the
  /// length. Over-capacity is an EXPLICIT `io::Error` (no truncation).
  pub fn serialize_into(&self, out: &mut [u8]) -> io::Result<usize> {
    struct SliceWriter<'a> {
      buf: &'a mut [u8],
      pos: usize,
    }
    impl<'a> io::Write for SliceWriter<'a> {
      fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let end = self.pos.checked_add(data.len()).ok_or_else(|| io::Error::other("overflow"))?;
        if end > self.buf.len() {
          return Err(io::Error::other("Decoys serialize buffer too small"));
        }
        self.buf[self.pos .. end].copy_from_slice(data);
        self.pos = end;
        Ok(data.len())
      }
    }
    let mut w = SliceWriter { buf: out, pos: 0 };
    self.write(&mut w)?;
    Ok(w.pos)
  }

  /// Serialize the Decoys into a fixed-capacity buffer (`SERIALIZE_MAX` bytes
  /// cover the worst case: 16 offsets of 10-byte varints + 16 ring pairs).
  pub fn serialize(&self) -> HVec<u8, SERIALIZE_MAX> {
    let mut tmp = [0u8; SERIALIZE_MAX];
    let n = self
      .serialize_into(&mut tmp)
      .expect("SERIALIZE_MAX covers the worst-case Decoys encoding");
    let mut res = HVec::new();
    res.extend_from_slice(&tmp[.. n]).ok().unwrap();
    res
  }

  /// Read a set of Decoys.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization. This may run in time variable to its value.
  pub fn read(r: &mut impl io::Read) -> io::Result<Decoys> {
    // shlosilo vendor patch: fixed-capacity decode mirroring `read_vec`'s wire
    // format (VarInt length + elements) with EXPLICIT bound errors instead of
    // Vec allocation.
    let declared_length: usize = VarInt::read(r)?;
    if declared_length > usize::from(MAX_RING_SIZE) {
      Err(io::Error::other("vector exceeds bound on length"))?;
    }
    let mut offsets = HVec::<u64, RING_MAX>::new();
    for _ in 0 .. declared_length {
      offsets.push(VarInt::read(r)?).ok().unwrap();
    }
    let signer_index = read_byte(r)?;
    let mut ring = HVec::<[Point; 2], RING_MAX>::new();
    for _ in 0 .. declared_length {
      ring
        .push([
          CompressedPoint::read(r)?
            .decompress()
            .ok_or(io::Error::other("Decoys had invalid key in ring"))?,
          CompressedPoint::read(r)?
            .decompress()
            .ok_or(io::Error::other("Decoys had invalid commitment in ring"))?,
        ])
        .ok()
        .unwrap();
    }
    Decoys::new(&offsets, signer_index, &ring).ok_or_else(|| io::Error::other("invalid Decoys"))
  }
}
