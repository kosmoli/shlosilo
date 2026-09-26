//! POSIX-host staticlib bundle for the host-sim appearance.
//!
//! Symmetric to flux/forgebox/staticlib: this is what turns the shlosilo
//! `forms` core into `libshlosilo.a` for a C host. What the host provides
//! differs from the firmware:
//! - allocator: the std System allocator (a dev machine has an OS heap; the
//!   firmware gets a FreeRTOS wrapper);
//! - panic: the std default handler - the workspace release profile uses
//!   panic = "abort", so a panic aborts with its message on stderr;
//! - critical-section: the core's host target dependency enables
//!   `critical-section/std`, which provides the impl - no shim code needed.
//!
//! So the only thing this crate must still carry by hand is the C-ABI
//! keep-table: under LTO a staticlib only retains reachable symbols, and
//! `extern "C"` declarations do NOT create reachability (they leave every
//! symbol undefined in the archive) - each entry point the C side links
//! against is referenced here through its real Rust path.

#[repr(transparent)]
struct Addr(*const ());
// SAFETY: the table is immutable and holds only code addresses.
unsafe impl Sync for Addr {}

// The simulator exercises the create_account / export_readonly / sign-UR flow
// plus the version and ABI probes. The R3 multipart UR codec entries are kept
// for scripts/test_carousel_ffi.py (the forgebox carousel's host regression:
// encoder -> frame stream -> decoder round-trip at the firmware's buffer
// size, plus the FRAME_BUF_MAX_LEN contract check).
#[used]
static KEEP_FFI: [Addr; 17] = [
    Addr(shlosilo::ffi::c_abi::shlosilo_create_account_ffi as *const ()),
    Addr(shlosilo::ffi::c_abi::shlosilo_export_readonly_ffi as *const ()),
    Addr(shlosilo::ffi::c_abi::shlosilo_sign_ur_ffi as *const ()),
    Addr(shlosilo::ffi::c_abi::shlosilo_sign_ws_len as *const ()),
    Addr(shlosilo::ffi::c_abi::shlosilo_gencache_table_sizes as *const ()),
    Addr(shlosilo::ffi::c_abi::shlosilo_gencache_provide_table as *const ()),
    Addr(shlosilo::ffi::version::shlosilo_version as *const ()),
    Addr(shlosilo::ffi::version::shlosilo_cabi_check as *const ()),
    Addr(shlosilo::ffi::c_abi::r3::shlosilo_ur_encode_begin as *const ()),
    Addr(shlosilo::ffi::c_abi::r3::shlosilo_ur_encode_next as *const ()),
    Addr(shlosilo::ffi::c_abi::r3::shlosilo_ur_encode_next_cyclic as *const ()),
    Addr(shlosilo::ffi::c_abi::r3::shlosilo_ur_encode_free as *const ()),
    Addr(shlosilo::ffi::c_abi::r3::shlosilo_ur_decode_new as *const ()),
    Addr(shlosilo::ffi::c_abi::r3::shlosilo_ur_decode_feed as *const ()),
    Addr(shlosilo::ffi::c_abi::r3::shlosilo_ur_decode_complete as *const ()),
    Addr(shlosilo::ffi::c_abi::r3::shlosilo_ur_decode_payload as *const ()),
    Addr(shlosilo::ffi::c_abi::r3::shlosilo_ur_decode_free as *const ()),
];
