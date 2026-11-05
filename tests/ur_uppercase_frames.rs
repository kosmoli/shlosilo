//! BC-UR case insensitivity (regression pin over real Sparrow frames)
//!
//! Sparrow encodes signing QRs in QR **alphanumeric** mode (which has no lowercase
//! letters), so the whole UR string is uppercased: `UR:CRYPTO-PSBT/119-2/LPCSKT…`.
//! BC-UR requires the decode direction to be case-insensitive: an encoder may emit all
//! caps, a decoder must accept it.
//!
//! Everything received from Cake/Feather was lowercase (byte mode), so this surface was
//! never covered -- on the first on-device Sparrow run (2026-11-04) the device treated
//! `CRYPTO-PSBT` as an unknown type and printed
//! `collected: unknown code, not a sign request`.
//!
//! The frames below are the **real bytes** zbar extracted frame by frame from a
//! recorded Sparrow animation.

use shlosilo::ur::ur_encode::UrTypeTag;
use shlosilo::ur::ur_multipart::UrMultipartDecoder;

/// Four fountain frames decoded consecutively from the Sparrow animation
/// (seq-count = 119-2 / 121-2 / 124-2 / 126-2: 2 original fragments plus redundant
/// mixed frames).
const SPARROW_UPPER_FRAMES: &[&str] = &[
    "UR:CRYPTO-PSBT/119-2/LPCSKTAOCFADRNCYFPVYFZLGHDURHDCKSPNLKNIDJYZMADAEIOAOBBEYMTGDPFSEAMSTKNDRCMQZHFENMWLOZMLURNSNRDLNGOYNHPVDGHGLSSDNKOPAATRNOXTPGOFHVLVATPPYHPSNOYRLBSHFKTPKWYBKNTECIASSLNKGPSOSDPFRTAHSURAESTMDKKGWCALTLDRYLAJPTKESVDLDAEAEAEAEAXCMAEBBNNQDCEGOATJNEYFZBARSAMZTBGWENNLBWPENUTIMGSHLFEFMUYFWBDWLPFWSPLCLPKZSSEDNCSWFRHAEHNWSTKGTONDEYNFZCSAMWLFNOTASHSRELUTSDSTAJYBKPSVAJLCLWLQZPMDRUTMWCWGSPMJZBWGORYESTKDIBGHGFPBAMWTPNSBEPAVSWERTRTLSADCYSNUEMOROGYRKBEJKROMTBDTYAEAELALYADAELAAEADAELAAEADIATKJOBS",
    "UR:CRYPTO-PSBT/121-2/LPCSKKAOCFADRNCYFPVYFZLGHDURADCTJKWLASAEAEAEAEAECMAEBBEYMTGYAYHEDSVYJNBNSRMDRLHHCLVSGDTLIHEOCPADAXAAADAEAEAECPAMAOSNHTNSSNGWGOFHVLVATPHFOXEYHYREZOHGKTPKWYBKNTECKPSSMOOYFZSAECLKYNCSWFRHMTBDGHAEAELAADAEAELAAEAEAELAAEAEAEAEAXAEAEAEAECPAOAOAMNTMODKOSVDJTHYLYGEZCDSKEPSFGYNDLHPFZFMMWFXBSUOEMCXPMSNBDIYBBPYCSWFRHMTBDGHAEAELAADAEAELAAEAEAELAAEAEAEAEAAAEAEAEAECPAOAOPEGLDWNNATVLMSSTHEWZVEKNAMCMTIKEJTAEFRKKLRVOBNLYNDNTCKDITDTKTIFDCSWFRHMTBDGHAEAELAADAEAELAAEAEAELAADAEAEAEADAEAEAEAEWPNNADST",
    "UR:CRYPTO-PSBT/124-2/LPCSKEAOCFADRNCYFPVYFZLGHDURHKADRKJOJKIDJYZMADAEJSAOAEAEAEADRONNCXDSCHDSTLCLVYIMREHNPEHYUYZEMKLTHFWZHTVDGHGLVADPJYKEHLCPINMSAEAEAEAEAEZCZMZMZMAOWKADAEAEAEAEAEAECMAEBBTNWPIHCSRLDLKKDWRHGYNNDPGWCAATLORYLAWZTKESVDASAEAEAEAEAECMAEBBNNMECKHGADWTNBIEPTHDISOEMUOSIAHKMHNYNDNSIAAMAHAEGWADAAECLTTKAXWPOYNSTLLAAEAEAEMTJERKTKGTDADTYNFZMKAMWLFNCNASHSRELUTEDSTAJYBKMNVEJNMNOSMKEODPFMAXUOBWHELOINGUPYWLQDGABGJZETLEKOTYCALUDWYNSGBGBSGUGAAOFMIOAAQDAHRKBEWFRHMTBDGHAEAELAADAEAELAAEAEAELAAEADWNIABWWF",
    "UR:CRYPTO-PSBT/126-2/LPCSKBAOCFADRNCYFPVYFZLGHDURHDCKSPNLKNIDJYZMADAEIOAOBBEYMTGDPFSEAMSTKNDRCMQZHFENMWLOZMLURNSNRDLNGOYNHPVDGHGLSSDNKOPAATRNOXTPGOFHVLVATPPYHPSNOYRLBSHFKTPKWYBKNTECIASSLNKGPSOSDPFRTAHSURAESTMDKKGWCALTLDRYLAJPTKESVDLDAEAEAEAEAXCMAEBBNNQDCEGOATJNEYFZBARSAMZTBGWENNLBWPENUTIMGSHLFEFMUYFWBDWLPFWSPLCLPKZSSEDNCSWFRHAEHNWSTKGTONDEYNFZCSAMWLFNOTASHSRELUTSDSTAJYBKPSVAJLCLWLQZPMDRUTMWCWGSPMJZBWGORYESTKDIBGHGFPBAMWTPNSBEPAVSWERTRTLSADCYSNUEMOROGYRKBEJKROMTBDTYAEAELALYADAELAAEADAELAAEADKSZSWEYT",
];

const SCRATCH: usize = 4096;

/// Type-name matching must be case-insensitive.
#[test]
fn type_tag_lookup_is_case_insensitive() {
    assert_eq!(UrTypeTag::from_name("CRYPTO-PSBT"), UrTypeTag::CryptoPsbt);
    assert_eq!(
        UrTypeTag::from_name("ETH-SIGN-REQUEST"),
        UrTypeTag::EthSignRequest
    );
    assert_eq!(UrTypeTag::from_name("Crypto-Psbt"), UrTypeTag::CryptoPsbt);
}

/// Real Sparrow frames: the decoder must accept an uppercase frame header and
/// normalize the type to lowercase for upper layers.
///
/// The convenience constructor `UrMultipartDecoder::new()` exists only on the alloc
/// surface (it leaks its own workspace internally); the device surface goes through the
/// caller-workspace path, covered by `device_ffi_path_…` below -- both surfaces need a
/// pin, but the pins cannot compile across surfaces.
#[cfg(feature = "alloc-fallback")]
#[test]
fn sparrow_uppercase_frames_decode_to_crypto_psbt() {
    let mut dec = UrMultipartDecoder::new();
    let mut scratch = [0u8; SCRATCH];
    let mut accepted = 0usize;
    for f in SPARROW_UPPER_FRAMES {
        match dec.receive_frame_with(f, &mut scratch) {
            Ok(_) => accepted += 1,
            Err(e) => panic!("frame rejected: {e:?}\n  {f}"),
        }
    }
    assert!(accepted > 0, "at least one frame must be accepted");
    // The type string must be normalized to lowercase (the C side dispatches on the
    // lowercase name).
    assert_eq!(dec.ur_type(), Some("crypto-psbt"), "type normalization");

    // End to end: the four fountain frames must rebuild the whole message, and the
    // payload must be a PSBT.
    assert!(
        dec.complete(),
        "four fountain frames should rebuild the two-fragment message"
    );
    let mut out = [0u8; 8192];
    let n = dec
        .payload_into(&mut out)
        .expect("payload_into")
        .expect("complete payload");
    assert!(n > 100, "unexpected PSBT payload length: {n}");
    assert_eq!(
        &out[..5],
        b"psbt\xff",
        "payload is not a PSBT (magic mismatch)"
    );
}

/// Device-equivalent path (the exact FFI sequence the C side calls, with a caller
/// workspace): feed every frame decoded from the recording one by one; any rejected
/// frame must surface its return code.
/// Why this pin exists: the 2026-11-04 device run reported
/// `scan failed / code not recognized` while the same frames were green through the
/// `UrMultipartDecoder::new()` test path -- the test path and the device path
/// (caller-workspace carve) are not the same, so they must be pinned separately.
#[test]
fn device_ffi_path_accepts_every_sparrow_frame() {
    use core::ffi::c_uint;
    use shlosilo::ffi::c_abi;
    use std::ffi::CString;

    let all = include_str!("../tests/fixtures/sparrow_frames.txt");
    let frames: Vec<&str> = all.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        frames.len() >= 20,
        "unexpected fixture frame count: {}",
        frames.len()
    );

    let ws_need = shlosilo::ur::ur_multipart::ur_decode_ws_len();
    let mut ws = vec![0u8; ws_need];
    let dec = c_abi::r3::shlosilo_ur_decode_new(ws.as_mut_ptr(), ws_need as c_uint);
    assert!(!dec.is_null(), "decoder init failed");

    let mut accepted_total = 0u32;
    for (i, f) in frames.iter().enumerate() {
        let c = CString::new(*f).unwrap();
        let mut accepted: c_uint = 0;
        let rc = c_abi::r3::shlosilo_ur_decode_feed(dec, c.as_ptr(), &mut accepted);
        assert_eq!(
            rc,
            0,
            "frame #{} rejected rc={} len={} seq={}",
            i,
            rc,
            f.len(),
            f.split('/').nth(1).unwrap_or("?")
        );
        accepted_total += accepted;
    }
    assert!(accepted_total > 0, "no frame carried new information");
    assert_eq!(
        c_abi::r3::shlosilo_ur_decode_complete(dec),
        1,
        "all frames received but still not complete"
    );

    let mut tlen: c_uint = 0;
    let mut ty = [0u8; 32];
    assert_eq!(
        c_abi::r3::shlosilo_ur_decode_type(dec, ty.as_mut_ptr(), ty.len() as c_uint, &mut tlen),
        0
    );
    let t = core::str::from_utf8(&ty[..(tlen as usize).saturating_sub(1)]).unwrap();
    assert_eq!(t, "crypto-psbt", "type should be normalized to lowercase");

    c_abi::r3::shlosilo_ur_decode_free(dec);
}
