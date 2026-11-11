//! Single-part UR decoding must accept the uppercase form wallets actually emit.
//!
//! QR alphanumeric mode has no lowercase characters, so a wallet that puts a UR in a
//! QR writes it uppercase (`UR:ETH-SIGN-REQUEST/...`). The multipart intake path
//! folds case; the single-part FFI entry checked `strip_prefix("ur:")`, which is
//! case-sensitive, so an uppercase single-part UR was rejected as
//! "code not recognized" on the device while the identical lowercase string worked.
//!
//! These pins go through the C-ABI entry (`shlosilo_ur_decode_uri_ffi`) rather than
//! the Rust helper, because the defect was in the wrapper's own recognition step -
//! testing the helper alone would have stayed green.

use core::ffi::c_uint;

const ETH_SIGN_REQUEST_LOWER: &str = "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmaymwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxadaaadrpceaadt";

fn decode_through_ffi(uri: &str) -> (i32, String, Vec<u8>) {
    // NUL-terminated copy for the C ABI
    let mut text = uri.as_bytes().to_vec();
    text.push(0);
    let mut type_buf = [0u8; 64];
    let mut payload = vec![0u8; 4096];
    let mut actual: c_uint = 0;
    let rc = shlosilo::ffi::c_abi::r3::shlosilo_ur_decode_uri_ffi(
        text.as_ptr().cast(),
        type_buf.as_mut_ptr(),
        type_buf.len() as c_uint,
        payload.as_mut_ptr(),
        payload.len() as c_uint,
        &mut actual,
    );
    let type_out = {
        let end = type_buf.iter().position(|&b| b == 0).unwrap_or(0);
        String::from_utf8_lossy(&type_buf[..end]).to_string()
    };
    payload.truncate(actual as usize);
    (rc, type_out, payload)
}

#[test]
fn lowercase_single_part_ur_decodes() {
    let (rc, ty, payload) = decode_through_ffi(ETH_SIGN_REQUEST_LOWER);
    assert_eq!(rc, 0, "lowercase UR must decode");
    assert_eq!(ty, "eth-sign-request");
    assert!(!payload.is_empty());
}

#[test]
fn uppercase_single_part_ur_decodes_to_the_same_bytes() {
    let (rc_lo, ty_lo, lo) = decode_through_ffi(ETH_SIGN_REQUEST_LOWER);
    let upper = ETH_SIGN_REQUEST_LOWER.to_uppercase();
    let (rc_up, ty_up, up) = decode_through_ffi(&upper);

    assert_eq!(rc_lo, 0);
    assert_eq!(rc_up, 0, "uppercase (QR alphanumeric mode) must decode too");
    assert_eq!(ty_up.to_ascii_lowercase(), ty_lo, "same UR type either way");
    assert_eq!(lo, up, "case must not change the payload");
}

#[test]
fn a_non_ur_string_is_still_refused() {
    for s in ["not-a-ur", "ur:", "ur:/abc", "urXabc"] {
        let (rc, _, _) = decode_through_ffi(s);
        assert_ne!(rc, 0, "{s:?} must be refused");
    }
}
