//! Device-side BP+ generator cache FFI (feature `generator-cache-ffi`).
//!
//! Bridges the vendored monero-bulletproofs generator cache hooks to C callbacks
//! implementing a QSPI flash backend. T-04 contract: the callbacks cross the
//! boundary as typed nullable fn pointers (NULL unregisters the slot).
//!
//! ## Integrity boundary (audit #15 P2-02)
//!
//! The blob's integrity (magic, length, CRC32) is verified by the C backend's
//! `gc_load` and is deliberately NOT re-checked on the Rust side:
//! - the backend runs in the same trust domain (same firmware image, same
//!   process), so this is a backend contract rather than an untrusted-input
//!   boundary;
//! - re-computing the CRC in Rust would re-read the 256 KB blob on every boot
//!   (~120 ms on the device) for no additional guarantee;
//! - the device backend performs the full check (`xmr_gen_cache_flash.c`:
//!   magic `XGC1`, length bound, CRC32) and returns NULL on any mismatch, which
//!   routes the Rust side to the decompress-and-store path instead.
//!
//! A backend that violates this contract is a firmware bug, not hostile input;
//! the returned slice is additionally length-checked here before use.
//!
//! C side contract:
//! - load:  `const uint8_t *gc_load(const uint8_t *prefix, uint32_t prefix_len)`
//!   Returns a pointer to [len:u32 LE][crc32:u32 LE][blob] whose storage stays
//!   valid and immutable for the program lifetime (memory-mapped flash on the
//!   device). Returns NULL when the slot is absent/invalid.
//! - store: `uint32_t gc_store(const uint8_t *prefix, uint32_t prefix_len,
//!                             const uint8_t *blob, uint32_t blob_len)`
//!   Returns 0 on success, non-zero on failure (store failure is non-fatal: the cache
//!   simply re-decompresses on next boot).

#[cfg(feature = "generator-cache-ffi")]
mod imp {
    /// C-side load callback: returns [len:u32 LE][crc32:u32 LE][blob] or NULL.
    pub type LoadC = extern "C" fn(*const u8, u32) -> *const u8;
    /// C-side store callback: 0 on success, non-zero on failure.
    pub type StoreC = extern "C" fn(*const u8, u32, *const u8, u32) -> u32;

    #[allow(static_mut_refs)]
    static mut LOAD_FPTR: Option<LoadC> = None;
    #[allow(static_mut_refs)]
    static mut STORE_FPTR: Option<StoreC> = None;

    /// Register the flash-backend callbacks (T-04 contract: typed nullable fn
    /// pointers). Last registration wins; `None` unregisters that slot.
    pub fn set_hooks(load_fptr: Option<LoadC>, store_fptr: Option<StoreC>) {
        #[allow(static_mut_refs)]
        unsafe {
            LOAD_FPTR = load_fptr;
            STORE_FPTR = store_fptr;
        }
        let _ = monero_bulletproofs::register_generator_cache_hooks(load_adapter, store_adapter);
    }

    fn load_adapter(prefix: &'static [u8]) -> Option<&'static [u8]> {
        #[allow(static_mut_refs)]
        let fptr = unsafe { LOAD_FPTR }?;
        let hdr = fptr(prefix.as_ptr(), prefix.len() as u32);
        if hdr.is_null() {
            return None;
        }
        // Header: [len u32 LE][crc u32 LE] — C side guarantees CRC validity.
        let len = unsafe { u32::from_le_bytes(core::ptr::read(hdr as *const [u8; 4])) } as usize;
        // Sanity bound: blob must fit the known generator sizes; reject absurd values
        // before slicing device memory.
        if len == 0 || len > 4096 * 128 {
            return None;
        }
        // Zero-copy: the C backend returns a pointer into its own storage — the
        // firmware's memory-mapped flash region on the device (stable for the program
        // lifetime). Borrow it in place instead of copying 256 KB into an allocation
        // (a 256 KB copy means an alloc + zeroing + a PSRAM round trip on the device).
        Some(unsafe { core::slice::from_raw_parts(hdr.add(8), len) })
    }

    fn store_adapter(prefix: &'static [u8], blob: &[u8]) {
        #[allow(static_mut_refs)]
        let fptr = match unsafe { STORE_FPTR } {
            Some(f) => f,
            None => return,
        };
        // Best effort: a failed store only costs boot time on the next run.
        let _ = fptr(
            prefix.as_ptr(),
            prefix.len() as u32,
            blob.as_ptr(),
            blob.len() as u32,
        );
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use core::sync::atomic::{AtomicU32, Ordering};

        /// Deterministic fake flash blob: [len=5 u32 LE][crc u32 LE][b"hello"].
        static BLOB: [u8; 13] = [
            5, 0, 0, 0, 0xEF, 0xBE, 0xAD, 0xDE, b'h', b'e', b'l', b'l', b'o',
        ];
        static STORE_CALLS: AtomicU32 = AtomicU32::new(0);

        extern "C" fn test_load(_prefix: *const u8, _len: u32) -> *const u8 {
            BLOB.as_ptr()
        }

        extern "C" fn test_store(_p: *const u8, _l: u32, _b: *const u8, _bl: u32) -> u32 {
            STORE_CALLS.fetch_add(1, Ordering::Relaxed);
            0
        }

        /// T-04 pins (single test on purpose: the hook slots are `static mut`).
        ///
        /// inv2: real 64-bit function addresses survive the C-ABI round trip
        /// (`shlosilo_gen_cache_set_hooks`) and the adapters actually call them.
        /// inv3: NULL/None means unregistered — load yields None, store no-ops.
        #[test]
        fn inv2_inv3_hooks_roundtrip_and_null_sentinel() {
            // inv2: register through the C-ABI entry, exercise both adapters.
            crate::ffi::generator_cache_ffi::shlosilo_gen_cache_set_hooks(
                Some(test_load),
                Some(test_store),
            );
            let got = load_adapter(b"bulletproof_plus").expect("load via registered C fn");
            assert_eq!(
                got,
                &BLOB[8..],
                "inv2: blob must come back through the registered pointer"
            );
            store_adapter(b"bulletproof_plus", b"xy");
            assert_eq!(
                STORE_CALLS.load(Ordering::Relaxed),
                1,
                "inv2: store must run through the registered pointer"
            );

            // inv3: NULL unregisters both slots.
            crate::ffi::generator_cache_ffi::shlosilo_gen_cache_set_hooks(None, None);
            assert!(
                load_adapter(b"bulletproof_plus").is_none(),
                "inv3: unregistered load must yield None"
            );
            store_adapter(b"bulletproof_plus", b"xy");
            assert_eq!(
                STORE_CALLS.load(Ordering::Relaxed),
                1,
                "inv3: unregistered store must be a no-op"
            );
        }
    }
}

#[cfg(feature = "generator-cache-ffi")]
pub use imp::*;

/// C-ABI: register the flash-backend callbacks. Call once from C init (before the first
/// XMR sign). T-04 contract: typed nullable fn pointers — NULL unregisters the slot.
///
/// # Safety
/// Both pointers, when non-NULL, must be valid `extern "C"` functions with the
/// documented signatures.
///
/// Single definition with a cfg-split body (feature on: real hooks; off: no-op)
/// so the C host always links and cbindgen emits exactly one declaration.
#[cfg_attr(not(feature = "generator-cache-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_gen_cache_set_hooks(
    load_fptr: Option<extern "C" fn(*const u8, u32) -> *const u8>,
    store_fptr: Option<extern "C" fn(*const u8, u32, *const u8, u32) -> u32>,
) {
    #[cfg(feature = "generator-cache-ffi")]
    {
        imp::set_hooks(load_fptr, store_fptr);
    }
}
