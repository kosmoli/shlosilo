//! CBOR byte-string shell (keystone-ur Bytes semantics) — pure functions, zero-alloc.
//!
//! Wire convention (2026-10-12, Cake/monero_c alignment): a UR *message* may
//! carry one definite-length CBOR byte-string shell around the real container.
//! The real-capture xmr-output leg reassembles to `58 f0 4d6f6e6572...` —
//! monero_c `CborLite::encodeBytes` shape — while Cake's own xmr-txunsigned leg
//! is bare (`Monero unsigned tx set\x05...`), so both forms are legal inbound.
//!
//! - Inbound (`ur_message_content`): a **complete** definite byte-string
//!   (head + content length exactly consumes the message) is stripped to its
//!   content; anything else — bare containers, indefinite/foreign CBOR,
//!   truncated heads, non-exact lengths — passes through untouched.
//! - Outbound (`ur_message_wrap_into`): the container is wrapped in the short
//!   shell forms (`0x58` + 1-byte length / `0x59` + 2-byte length) before
//!   bytewords, so peers that decode with `CborLite::decodeBytes` (monero_c
//!   importKeyImagesUR / submitTransactionUR, Cupcake exportKeyImagesUR /
//!   signUR) receive the shape they expect.
//!
//! The exact-exhaustion criterion is what prevents misfiring on bare
//! containers: their magic starts with `0x4d` ('M' of the Monero magics),
//! which a naive head read would treat as an inline byte-string of length 13.

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

/// Parse the head of a definite-length CBOR byte-string item:
/// `Some((head_len, content_len))`, `None` for any other major type
/// (incl. indefinite `0x5f` and truncated heads).
fn definite_bytes_head(msg: &[u8]) -> Option<(usize, usize)> {
    let b0 = *msg.first()?;
    let (hlen, len) = match b0 {
        0x40..=0x57 => (1usize, (b0 - 0x40) as usize),
        0x58 => (2, *msg.get(1)? as usize),
        0x59 => (3, u16::from_be_bytes([*msg.get(1)?, *msg.get(2)?]) as usize),
        0x5a => (
            5,
            usize::try_from(u32::from_be_bytes([
                *msg.get(1)?,
                *msg.get(2)?,
                *msg.get(3)?,
                *msg.get(4)?,
            ]))
            .ok()?,
        ),
        0x5b => (
            9,
            usize::try_from(u64::from_be_bytes([
                *msg.get(1)?,
                *msg.get(2)?,
                *msg.get(3)?,
                *msg.get(4)?,
                *msg.get(5)?,
                *msg.get(6)?,
                *msg.get(7)?,
                *msg.get(8)?,
            ]))
            .ok()?,
        ),
        _ => return None,
    };
    Some((hlen, len))
}

/// Inbound payload semantics: the CBOR byte-string shell's content when `msg`
/// is one **complete** definite byte-string item (head + content length
/// exactly consumes `msg`); otherwise `msg` itself (bare fallback — Cake's
/// xmr-txunsigned quirk). Pure, zero-alloc.
pub fn ur_message_content(msg: &[u8]) -> &[u8] {
    match definite_bytes_head(msg) {
        Some((hlen, len)) if hlen.checked_add(len) == Some(msg.len()) => &msg[hlen..],
        _ => msg,
    }
}

/// Outbound shell head for `content_len` bytes: `0x58` + 1-byte length up to
/// 255 B, `0x59` + 2-byte length up to 65535 B; below 24 B the canonical
/// short head `0x40+len` (RFC 8949 §4.2 — the `44aabbccdd` shape minicbor,
/// ur-registry and monero_c `CborLite::encodeBytes` all emit).
pub(crate) fn shell_head(content_len: usize, out: &mut [u8; 3]) -> Result<usize> {
    // Canonical CBOR (RFC 8949 §4.2 minimal encoding) — matches what
    // minicbor/ur-registry emit (official vector `44aabbccdd`); the old
    // always-0x58 head was a non-minimal encoding some strict decoders refuse.
    if content_len < 24 {
        out[0] = 0x40 + content_len as u8;
        Ok(1)
    } else if content_len <= 0xff {
        out[0] = 0x58;
        out[1] = content_len as u8;
        Ok(2)
    } else if content_len <= 0xffff {
        out[0] = 0x59;
        out[1..3].copy_from_slice(&(content_len as u16).to_be_bytes());
        Ok(3)
    } else {
        Err(ShlosiloError::new(ShlosiloErrorKind::UrPayloadTooLarge))
    }
}

/// Total wire length of the shelled message (head + content).
pub fn ur_message_shell_len(content_len: usize) -> Result<usize> {
    let mut head = [0u8; 3];
    shell_head(content_len, &mut head).map(|hn| hn + content_len)
}

/// Outbound wrap: push the CBOR byte-string shell head and `content` into
/// `out` (must be empty / pre-sized to `ur_message_shell_len`). Overflow
/// raises BufferTooSmall — never silent truncation, never a panic.
pub fn ur_message_wrap_into<const N: usize>(
    content: &[u8],
    out: &mut heapless::Vec<u8, N>,
) -> Result<()> {
    let mut head = [0u8; 3];
    let hn = shell_head(content.len(), &mut head)?;
    for &b in head[..hn].iter().chain(content.iter()) {
        out.push(b)
            .map_err(|_| ShlosiloError::new(ShlosiloErrorKind::EncodingBufferOverflow))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Legacy non-minimal heads (the pre-canonical 0x58/0x59 wire that older
    /// fixtures and archived QR captures carry) must still strip — the shell
    /// decoder stays wide while the encoder emits canonical only.
    #[test]
    fn legacy_nonminimal_heads_still_strip() {
        assert_eq!(ur_message_content(&[0x58, 0x04, 1, 2, 3, 4]), &[1, 2, 3, 4]);
        assert_eq!(ur_message_content(&[0x44, 1, 2, 3, 4]), &[1, 2, 3, 4]);
    }

    /// Shelled message → content; bare message → itself.
    #[test]
    fn strip_shell_passthrough_bare() {
        let content = b"Monero output export\x04payload";
        let mut shelled = alloc::vec![0x58u8, content.len() as u8];
        shelled.extend_from_slice(content);
        assert_eq!(ur_message_content(&shelled), &content[..]);
        // bare: the container is handed on untouched
        assert_eq!(ur_message_content(content), &content[..]);
        assert_eq!(ur_message_content(&[]), &[][..]);
    }

    /// Exhaustion criterion: heads whose length does not exactly consume the
    /// message must NOT strip (bare containers start with `0x4d` = inline
    /// byte-string length 13).
    #[test]
    fn non_exact_length_is_not_stripped() {
        // 'M' (0x4d) head claims 13 bytes but the message is longer → bare
        let mut bare = alloc::vec![0x4du8];
        bare.extend_from_slice(b"onero unsigned tx set\x05"); // 22 more = 23 total
        assert_eq!(bare.len(), 23);
        assert_eq!(ur_message_content(&bare), &bare[..]);
        // trailing byte after a valid shell → not a complete item → bare
        let mut odd = alloc::vec![0x58u8, 0x02, 0x01, 0x02, 0xff];
        assert_eq!(ur_message_content(&odd), &odd[..]);
        odd.truncate(3); // 0x58 claims 2, only 1 present → bare
        assert_eq!(ur_message_content(&odd), &odd[..]);
    }

    /// Every definite head form strips when it exactly consumes the message.
    #[test]
    fn all_definite_head_forms_strip() {
        let c = b"xyz";
        // inline 0x40..0x57
        let mut m = alloc::vec![0x43u8];
        m.extend_from_slice(c);
        assert_eq!(ur_message_content(&m), &c[..]);
        // 0x58 + 1B length
        let mut m = alloc::vec![0x58u8, 0x03];
        m.extend_from_slice(c);
        assert_eq!(ur_message_content(&m), &c[..]);
        // 0x59 + 2B length
        let mut m = alloc::vec![0x59u8, 0x00, 0x03];
        m.extend_from_slice(c);
        assert_eq!(ur_message_content(&m), &c[..]);
        // 0x5a + 4B length
        let mut m = alloc::vec![0x5au8, 0x00, 0x00, 0x00, 0x03];
        m.extend_from_slice(c);
        assert_eq!(ur_message_content(&m), &c[..]);
        // 0x5b + 8B length
        let mut m = alloc::vec![0x5bu8, 0, 0, 0, 0, 0, 0, 0, 0x03];
        m.extend_from_slice(c);
        assert_eq!(ur_message_content(&m), &c[..]);
        // zero-length shell
        assert_eq!(ur_message_content(&[0x58, 0x00]), &[][..]);
        // indefinite / foreign majors → bare
        assert_eq!(
            ur_message_content(&[0x5f, 0x41, 0x61, 0xff]),
            &[0x5f, 0x41, 0x61, 0xff][..]
        );
        // foreign major (0x64 = text "data") → bare, must NOT strip (whole
        // item passes through unchanged)
        assert_eq!(
            ur_message_content(&[0x64, 0x64, 0x61, 0x74, 0x61]),
            &[0x64, 0x64, 0x61, 0x74, 0x61][..]
        );
    }

    /// Outbound wrap shape and round trip through the strip. Head is the
    /// canonical CBOR form (RFC 8949 §4.2): short head below 24 B.
    #[test]
    fn wrap_shapes_and_round_trip() {
        let mut out: heapless::Vec<u8, 64> = heapless::Vec::new();
        ur_message_wrap_into(b"data", &mut out).unwrap();
        assert_eq!(&out[..], &[0x44, 0x64, 0x61, 0x74, 0x61][..]);
        assert_eq!(ur_message_content(&out), &b"data"[..]);
        assert_eq!(ur_message_shell_len(4).unwrap(), 5);

        let big = [0xA5u8; 300];
        let mut out: heapless::Vec<u8, 320> = heapless::Vec::new();
        ur_message_wrap_into(&big, &mut out).unwrap();
        assert_eq!(&out[..3], &[0x59, 0x01, 0x2c][..]); // 300 = 0x012c
        assert_eq!(ur_message_content(&out), &big[..]);

        // too large for the short forms → explicit error, no truncation
        let mut out: heapless::Vec<u8, 8> = heapless::Vec::new();
        assert!(ur_message_wrap_into(&[0u8; 8], &mut out).is_err()); // capacity 8 < 2+8
        assert!(ur_message_shell_len(0x1_0000).is_err());
    }
}
