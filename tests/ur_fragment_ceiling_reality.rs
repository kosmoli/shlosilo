//! Does a real 61 KB request fit the *fragment* ceiling?
//!
//! B-7 raised the payload and part caps to 64 KiB / 1024 parts, but the fountain also has
//! a **source-fragment** ceiling (`ur_source_fragments_max`). A 61,138 B Sparrow PSBT cut
//! into 65 B fragments - the length Cake and Sparrow actually send - is ~941 fragments, so
//! the question is whether that ceiling blocks a request the payload cap accepts.
#![cfg(feature = "alloc-fallback")]

use shlosilo::ur::ur_multipart::UrMultipartEncoder;

const REAL_PSBT: &[u8] = include_bytes!("fixtures/psbt_43_inputs_signet.psbt");

#[test]
fn a_real_request_at_peer_fragment_length_fits_the_fragment_ceiling() {
    // 65 B is the fragment length Cake/Sparrow emit (130-char bytewords).
    let enc = UrMultipartEncoder::new("crypto-psbt", REAL_PSBT, 65);
    match enc {
        Ok(e) => {
            let n = e.fragment_count();
            println!("payload {} B -> {n} fragments", REAL_PSBT.len());
            assert!(
                n <= shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX,
                "{n} fragments exceeds the ceiling {} - the device cannot decode a real \
                 61 KB request regardless of the payload cap",
                shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX
            );
        }
        Err(e) => panic!(
            "encoder refused a {} B payload at 65 B fragments: {:?} (ceiling {})",
            REAL_PSBT.len(),
            e.kind,
            shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX
        ),
    }
}

#[test]
fn our_own_outbound_cap_is_encodable() {
    // 64 KiB at the 200 B fragment length we emit = 308 fragments.
    let needed =
        shlosilo::limits::UR_PAYLOAD_MAX.div_ceil(shlosilo::limits::UR_ENCODE_FRAGMENT_LEN);
    println!(
        "outbound needs {needed} fragments for {} B at {} B/fragment",
        shlosilo::limits::UR_PAYLOAD_MAX,
        shlosilo::limits::UR_ENCODE_FRAGMENT_LEN
    );
    assert!(
        needed <= shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX,
        "{needed} fragments to emit our own maximum payload exceeds the ceiling {}",
        shlosilo::limits::UR_SOURCE_FRAGMENTS_MAX
    );
}
