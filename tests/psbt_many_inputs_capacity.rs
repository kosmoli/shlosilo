//! B-7 capacity pin: a real 40-UTXO consolidation request must fit.
//!
//! ## Why this file exists
//!
//! On 2026-11-15 a real Sparrow spend (43 inputs, `Send Max`) failed on the device
//! with `request data not recognized` while the scan was still running. The request
//! was 61,138 B and hit three fixed caps at once:
//!
//! | cap | was | request needed |
//! |---|---|---|
//! | `BT_TX_INPUTS_MAX` | 16 | 43 |
//! | `PSBT_MAPS_MAX` | 82 (2+16+64) | 88 (2+43+43) |
//! | `MULTIPART_PAYLOAD_MAX_LEN` | 16 KiB | 61 KiB |
//! | `UR_WS_DECODED_SLOTS` | 256 (~16.6 KiB of parts) | ~941 parts |
//!
//! Worse, two of those refused with `EncodingInvalidFormat`, so a capacity failure
//! wore the "request data not recognized" wording - the operator was told the
//! wallet's request was malformed when the limit was ours.
//!
//! The caps now allow 64 inputs / 64 KiB / 1024 slots and capacity failures are
//! `BufferTooSmall` (`request too large`). This file pins both, using the wallet's
//! own bytes as the fixture rather than a synthesised stand-in, so the numbers
//! cannot drift away from reality.
//!
//! ## The ceiling that is still there (documented, not hidden)
//!
//! `forms/encoding/fountain.rs: MAX_SEQUENCE_COUNT = 256` caps a fountain message at
//! 256 parts, because the part index lives in the **u8** domain. The inbound ceiling
//! is therefore `256 x (sender's fragment size)`, not our payload budget: ~16.6 KiB
//! at the 65 B parts 130-character frames carry, 51.2 KiB at 200 B parts, 61.4 KiB
//! at 240 B parts. This request only fits with >= 239-byte parts. Widening the index
//! domain (u8 -> u16) in the fountain core is a separate change; the last two tests
//! below pin the boundary so the gap cannot go quiet.
#![cfg(feature = "alloc-fallback")]

use shlosilo::chain::btc::psbt::{parse_psbt_into, KvRec};
use shlosilo::error::ShlosiloErrorKind;
use shlosilo::ur::ur_multipart::{
    UrMultipartDecoder, UrMultipartEncoder, MULTIPART_PAYLOAD_MAX_LEN,
};

/// The request that failed in the field: 61,138 B, 43 inputs, one output.
const PSBT: &[u8] = include_bytes!("fixtures/psbt_43_inputs_signet.psbt");

/// Enough records for 2 globals + 64 inputs + 64 outputs with a few keys each.
const RECS: usize = 2048;

fn parse_with<const A: usize>(psbt: &[u8], recs: &mut [KvRec]) -> Result<usize, ShlosiloErrorKind> {
    let mut arena = std::vec![0u8; A];
    // Bind the result before the arena goes out of scope: the Psbt borrows it.
    let out = match parse_psbt_into(psbt, &mut arena, recs) {
        Ok(p) => Ok(p.unsigned_tx.inputs.len()),
        Err(e) => Err(e.kind),
    };
    out
}

#[test]
fn the_real_43_input_request_parses() {
    assert_eq!(PSBT.len(), 61138, "the fixture is the wallet's own request");
    let mut recs = std::vec![KvRec::EMPTY; RECS];
    let n_in = parse_with::<{ 256 * 1024 }>(PSBT, &mut recs).expect("43 inputs must parse");
    assert_eq!(n_in, 43);
}

#[test]
fn the_real_request_round_trips_when_the_sender_keeps_parts_within_the_domain() {
    // 240-byte parts put 61,138 B into 255 parts: one under the 256-part domain.
    let mut enc = UrMultipartEncoder::new("crypto-psbt", PSBT, 240).expect("encode");
    let frames = enc.fragment_count();
    assert!(
        frames <= 256,
        "{frames} parts must stay inside the u8 domain"
    );
    assert!(PSBT.len() <= MULTIPART_PAYLOAD_MAX_LEN);

    let mut dec = UrMultipartDecoder::new();
    for _ in 0..frames {
        let frame = enc.next_frame().expect("frame");
        assert!(dec.receive_frame(frame.as_str()).expect("frame accepted"));
    }
    assert!(dec.complete(), "the message must reassemble");
    let out = dec.payload().expect("payload").expect("complete");
    assert_eq!(out.len(), PSBT.len());
    assert_eq!(&out[..5], &[0x70, 0x73, 0x62, 0x74, 0xff], "PSBT magic");
}

#[test]
fn the_fragment_ceiling_covers_the_largest_payload_the_profile_accepts() {
    // Phase 6 raised the source-fragment ceiling to 1,024, so the 200-byte-part stream for
    // this 61 KB request (306 parts) is now inside the domain - the old pin here asserted
    // it was refused, which was pinning a ceiling that also made our own 64 KiB outbound
    // unencodable. The invariant that must hold instead: whatever payload the profile
    // accepts, the fragment count it implies fits the ceiling. build.rs enforces the same
    // inequality, so a profile cannot be internally inconsistent.
    let needed = shlosilo::limits::UR_PAYLOAD_MAX.div_ceil(200);
    assert!(
        needed <= shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX,
        "{needed} parts at 200 B exceeds the ceiling {}",
        shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX
    );
    // ...and a payload past the profile's own cap is still refused.
    let oversized = std::vec![0u8; shlosilo::limits::UR_PAYLOAD_MAX + 1];
    assert!(UrMultipartEncoder::new("crypto-psbt", &oversized, 200).is_err());
}

#[test]
fn an_over_capacity_input_count_is_a_capacity_error_not_a_format_error() {
    // 65 inputs: one past BT_TX_INPUTS_MAX (64). The PSBT shell only needs to be
    // structurally valid for the count check to fire, so it is built by hand.
    let mut psbt = std::vec![0x70, 0x73, 0x62, 0x74, 0xff];
    // global map: key 0x00 = unsigned tx
    psbt.extend_from_slice(&[0x01, 0x00]);
    let mut tx = std::vec![0x02, 0x00, 0x00, 0x00]; // version
    tx.push(65); // input count
    for _ in 0..65 {
        tx.extend_from_slice(&[0u8; 32]); // prevout hash
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // vout
        tx.push(0x00); // empty scriptSig
        tx.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // sequence
    }
    tx.push(0x01); // output count
    tx.extend_from_slice(&[0u8; 8]); // value
    tx.push(0x00); // empty script
    tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // locktime
                                                     // The unsigned-tx value length is a varint: 65 inputs x 41 B + trailer is
                                                     // > 0xfc, so it needs the 0xfd form.
    let tx_len = tx.len();
    if tx_len < 0xfd {
        psbt.push(tx_len as u8);
    } else {
        psbt.push(0xfd);
        psbt.extend_from_slice(&(tx_len as u16).to_le_bytes());
    }
    psbt.extend_from_slice(&tx);
    psbt.push(0x00); // end of global map

    let mut recs = std::vec![KvRec::EMPTY; RECS];
    let err = parse_with::<{ 64 * 1024 }>(&psbt, &mut recs).expect_err("65 inputs must be refused");
    assert_eq!(
        err,
        ShlosiloErrorKind::BufferTooSmall,
        "an oversized request is a capacity failure -> `request too large`, \
         never `request data not recognized`"
    );
}
