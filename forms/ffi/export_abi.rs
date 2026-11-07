//! Account-export FFI: session handle + format id → the bytes a wallet scans.
//!
//! The device's "connect software wallet" screen lists six wire shapes (see
//! `business::export_format::ExportFormat`) and has to turn the one the operator
//! picked into a QR payload. This entry is that turn: it takes the live
//! `KeySession` (the seed stays inside the library, as everywhere else), the
//! format's listing index, and whatever metadata the chosen shape carries, and
//! writes the finished string into the caller's buffer.
//!
//! Numbers, not strings, cross the FFI for the format: the caller asks
//! `shlosilo_export_format_count()` for the list length and fills its menu from
//! `shlosilo_export_format_label(i)`, so the device cannot drift out of sync
//! with the library over a name it spells itself.
//!
//! Buffer contract: `shlosilo_export_format_max_len()` is the single source for
//! how large a caller buffer must be; anything smaller is refused with
//! `BufferTooSmall` (no truncation, no partial write).

use core::ffi::{c_char, c_int, c_uint};

use crate::business::export_format::{self, ExportLabels};
use crate::ffi::error_code::{to_ffi_code, ERR_NULL_POINTER, OK};
use crate::network::Network;
use crate::types::key_session::KeySession;

/// Largest export payload the six shapes can produce (a multi-account bundle at
/// ~5 entries is well under 1 KiB; the cap leaves room for long device strings).
const EXPORT_BUF_MAX: usize = 4096;

fn write_actual_len(p: *mut c_uint, v: usize) {
    if !p.is_null() {
        unsafe { *p = v as c_uint }
    }
}

/// Optional NUL-terminated ASCII parameter → `&str` (`None` for NULL).
fn optional_cstr<'a>(p: *const c_char, max: usize) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
            if len > max {
                return None;
            }
        }
        let bytes = core::slice::from_raw_parts(p.cast::<u8>(), len);
        core::str::from_utf8(bytes).ok()
    }
}

/// How many export shapes the library offers (the menu length).
#[no_mangle]
pub extern "C" fn shlosilo_export_format_count() -> c_uint {
    export_format::format_count() as c_uint
}

/// The label of shape `idx` (a NUL-terminated static string), or NULL when `idx`
/// is out of range. The label is the wire format itself, not a wallet brand.
#[no_mangle]
pub extern "C" fn shlosilo_export_format_label(idx: c_uint) -> *const c_char {
    match export_format::format_at(idx as usize) {
        // A `&'static CStr`, not a `&str`: string literals have no terminator,
        // so handing out a `str` pointer would let C read past the label.
        Some(f) => f.screen_label_cstr().as_ptr(),
        None => core::ptr::null(),
    }
}

/// Required caller-buffer length for any export shape (the runtime query, never
/// frozen into the ABI).
#[no_mangle]
pub extern "C" fn shlosilo_export_format_max_len() -> c_uint {
    EXPORT_BUF_MAX as c_uint
}

/// The UR type `format_id` is framed with, or NULL when the shape is plain text
/// (one static QR, no framing).
///
/// The device uses this to pick a renderer: a UR payload that needs more than one
/// 200-byte fragment animates in the frame carousel, one that fits - and every
/// text shape - is a single static QR. That split is the reference firmware's own
/// rule on the same hardware.
#[no_mangle]
pub extern "C" fn shlosilo_export_format_ur_type(format_id: c_uint) -> *const c_char {
    match export_format::format_at(format_id as usize) {
        Some(f) => match export_format::ur_type(f) {
            Some(tag) => tag.type_name_cstr().as_ptr(),
            None => core::ptr::null(),
        },
        None => core::ptr::null(),
    }
}

/// Session + format id + metadata → the shape's payload bytes (no UR wrapper).
///
/// For a UR shape this is the CBOR message the device fragments; for a text shape
/// it is the text, which is only ever shown as one static QR.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn shlosilo_export_format_payload_ffi(
    session: *const KeySession,
    format_id: c_uint,
    network: c_uint,
    label: *const c_char,
    device_type: *const c_char,
    device_id: *const c_char,
    device_version: *const c_char,
    restore_height: c_uint,
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0);
    let format = match export_format::format_at(format_id as usize) {
        Some(f) => f,
        None => {
            return to_ffi_code(&crate::error::ShlosiloError::new(
                crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
            ))
        }
    };
    let session = match unsafe { session.as_ref() } {
        Some(s) => s,
        None => return ERR_NULL_POINTER,
    };
    let net = match u8::try_from(network).ok().and_then(Network::try_from_u8) {
        Some(n) => n,
        None => {
            return to_ffi_code(&crate::error::ShlosiloError::new(
                crate::error::ShlosiloErrorKind::NetworkUnrecognized,
            ))
        }
    };
    // The frame encoder needs room for the whole payload plus its own work; the
    // payload cap is the same query the string entry uses.
    if output_buf.is_null() || (output_buf_len as usize) < EXPORT_BUF_MAX {
        return to_ffi_code(&crate::error::ShlosiloError::new(
            crate::error::ShlosiloErrorKind::BufferTooSmall,
        ));
    }
    let out = unsafe { core::slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };
    let labels = ExportLabels {
        label: optional_cstr(label, 64),
        key_name: optional_cstr(device_type, 64),
        device: optional_cstr(device_type, 64),
        device_id: optional_cstr(device_id, 64),
        device_version: optional_cstr(device_version, 64),
        restore_height: u64::from(restore_height),
    };
    match export_format::payload(format, session.seed().expose(), net, &labels, out) {
        Ok(n) => {
            write_actual_len(actual_len, n);
            OK
        }
        Err(e) => {
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
    }
}

/// Session + format id + metadata → the export string.
///
/// * `format_id` — the listing index from `shlosilo_export_format_count()`
/// * `network` — Bitcoin mainnet/testnet for the BTC shapes; the Monero shapes
///   always describe the Monero mainnet account and ignore it
/// * `label` / `device_type` / `device_id` / `device_version` — optional, used by
///   the shapes that carry them (pass NULL to omit)
/// * `restore_height` — used by the cupcake-shaped Monero JSON only
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: null-checked first, then from_raw_parts; the C side guarantees pointer validity
#[allow(clippy::too_many_arguments)] // the C-ABI shape: one flat call, no structs across the boundary
pub extern "C" fn shlosilo_export_format_session_ffi(
    session: *const KeySession,
    format_id: c_uint,
    network: c_uint,
    label: *const c_char,
    device_type: *const c_char,
    device_id: *const c_char,
    device_version: *const c_char,
    restore_height: c_uint,
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0);

    let format = match export_format::format_at(format_id as usize) {
        Some(f) => f,
        None => {
            return to_ffi_code(&crate::error::ShlosiloError::new(
                crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
            ))
        }
    };
    let session = match unsafe { session.as_ref() } {
        Some(s) => s,
        None => return ERR_NULL_POINTER,
    };
    let n8 = match u8::try_from(network) {
        Ok(v) => v,
        Err(_) => {
            return to_ffi_code(&crate::error::ShlosiloError::new(
                crate::error::ShlosiloErrorKind::NetworkUnrecognized,
            ))
        }
    };
    let net = match Network::try_from_u8(n8) {
        Some(n) => n,
        None => {
            return to_ffi_code(&crate::error::ShlosiloError::new(
                crate::error::ShlosiloErrorKind::NetworkUnrecognized,
            ))
        }
    };
    if output_buf.is_null() || (output_buf_len as usize) < EXPORT_BUF_MAX {
        return to_ffi_code(&crate::error::ShlosiloError::new(
            crate::error::ShlosiloErrorKind::BufferTooSmall,
        ));
    }
    let out = unsafe { core::slice::from_raw_parts_mut(output_buf, output_buf_len as usize) };

    let labels = ExportLabels {
        label: optional_cstr(label, 64),
        key_name: optional_cstr(device_type, 64),
        device: optional_cstr(device_type, 64),
        device_id: optional_cstr(device_id, 64),
        device_version: optional_cstr(device_version, 64),
        restore_height: u64::from(restore_height),
    };

    match export_format::build(format, session.seed().expose(), net, &labels, out) {
        Ok(n) => {
            write_actual_len(actual_len, n);
            OK
        }
        Err(e) => {
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use core::ffi::CStr;
    use core::mem::MaybeUninit;

    const ENTROPY: [u8; 16] = [
        0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2, 0x29,
        0x16,
    ];

    fn session_slot() -> (MaybeUninit<KeySession>, ()) {
        (MaybeUninit::uninit(), ())
    }

    fn place(slot: &mut MaybeUninit<KeySession>) -> *const KeySession {
        let s = KeySession::from_entropy(&ENTROPY, b"").expect("session");
        let p = slot.as_mut_ptr();
        unsafe { core::ptr::write(p, s) };
        p
    }

    fn export(session: *const KeySession, id: u32) -> (i32, String) {
        let mut out = vec![0u8; EXPORT_BUF_MAX];
        let mut actual: c_uint = 0;
        let label = c"test-wallet";
        let dev = c"TestDevice";
        let rc = shlosilo_export_format_session_ffi(
            session,
            id,
            0, // BitcoinMainnet
            label.as_ptr(),
            dev.as_ptr(),
            dev.as_ptr(),
            dev.as_ptr(),
            0,
            out.as_mut_ptr(),
            EXPORT_BUF_MAX as c_uint,
            &mut actual,
        );
        (
            rc,
            core::str::from_utf8(&out[..actual as usize])
                .map(String::from)
                .unwrap_or_default(),
        )
    }

    #[test]
    fn count_and_labels_come_from_one_source() {
        assert_eq!(shlosilo_export_format_count(), 6);
        let first = shlosilo_export_format_label(0);
        assert!(!first.is_null());
        let s = unsafe { CStr::from_ptr(first) }
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(s, "ur:crypto-account");
        assert!(shlosilo_export_format_label(6).is_null());
        assert_eq!(shlosilo_export_format_max_len() as usize, EXPORT_BUF_MAX);
    }

    #[test]
    fn every_format_round_trips_through_the_entry() {
        let (mut slot, _) = session_slot();
        let session = place(&mut slot);
        for id in 0..6u32 {
            let (rc, s) = export(session, id);
            assert_eq!(rc, OK, "format {id} failed");
            assert!(!s.is_empty(), "format {id} produced nothing");
        }
        unsafe { core::ptr::drop_in_place(slot.as_mut_ptr()) };
    }

    #[test]
    fn null_session_and_small_buffer_are_refused() {
        let mut out = [0u8; EXPORT_BUF_MAX];
        let mut actual: c_uint = 7;
        let rc = shlosilo_export_format_session_ffi(
            core::ptr::null(),
            0,
            0,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            EXPORT_BUF_MAX as c_uint,
            &mut actual,
        );
        assert_eq!(rc, ERR_NULL_POINTER);
        assert_eq!(actual, 0, "failure path zeroes actual_len");

        let (mut slot, _) = session_slot();
        let session = place(&mut slot);
        let (rc_small, s_small) = {
            let mut tiny = [0u8; 16];
            let mut a: c_uint = 0;
            let rc = shlosilo_export_format_session_ffi(
                session,
                0,
                0,
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null(),
                0,
                tiny.as_mut_ptr(),
                tiny.len() as c_uint,
                &mut a,
            );
            (rc, a)
        };
        assert_ne!(rc_small, OK, "a 16-byte buffer must be refused");
        assert_eq!(s_small, 0);
        unsafe { core::ptr::drop_in_place(slot.as_mut_ptr()) };
    }

    /// The device's renderer choice: UR shapes report a type, text shapes do not,
    /// and the payload lengths land where the reference firmware's fragment rule
    /// puts them (account 3 parts, ETH key 1 part, bundle 4 parts).
    #[test]
    fn ur_types_and_payload_sizes_drive_the_renderer() {
        let (mut slot, _) = session_slot();
        let session = place(&mut slot);
        let mut out = vec![0u8; EXPORT_BUF_MAX];
        let expected: [(u32, bool, u32); 6] = [
            (0, true, 3),  // crypto-account: 3 frames
            (1, false, 0), // xpub URI: text
            (2, true, 1),  // ETH hdkey: one frame
            (3, true, 4),  // multi-accounts: 4 frames
            (4, false, 0), // monero json (keystone): text
            (5, false, 0), // monero json (cupcake): text
        ];
        for (id, is_ur, parts) in expected {
            let tag = shlosilo_export_format_ur_type(id);
            assert_eq!(!tag.is_null(), is_ur, "format {id} UR-ness");
            if !is_ur {
                continue;
            }
            let mut actual: c_uint = 0;
            let dev = c"shlosilo";
            let rc = shlosilo_export_format_payload_ffi(
                session,
                id,
                0,
                dev.as_ptr(),
                dev.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                0,
                out.as_mut_ptr(),
                EXPORT_BUF_MAX as c_uint,
                &mut actual,
            );
            assert_eq!(rc, OK, "format {id} payload");
            let got_parts = (actual as usize).div_ceil(200);
            assert_eq!(got_parts, parts as usize, "format {id} fragment count");
        }
        unsafe { core::ptr::drop_in_place(slot.as_mut_ptr()) };
    }

    #[test]
    fn unknown_format_id_is_refused() {
        let (mut slot, _) = session_slot();
        let session = place(&mut slot);
        let mut out = [0u8; EXPORT_BUF_MAX];
        let mut actual: c_uint = 0;
        let rc = shlosilo_export_format_session_ffi(
            session,
            99,
            0,
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            EXPORT_BUF_MAX as c_uint,
            &mut actual,
        );
        assert_ne!(rc, OK);
        assert_eq!(actual, 0);
        unsafe { core::ptr::drop_in_place(slot.as_mut_ptr()) };
    }
}
