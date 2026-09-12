//! Device-side BP+ generator cache FFI (feature `generator-cache-ffi`).
//!
//! Bridges the vendored monero-bulletproofs generator cache hooks to C callbacks
//! implementing a QSPI flash backend. Same fptr-as-u32 pattern as `device_timing`.
//!
//! C side contract:
//! - load:  `const uint8_t *gc_load(const uint8_t *prefix, uint32_t prefix_len)`
//!   Returns a pointer to [len:u32 LE][crc32:u32 LE][blob] with a valid CRC, or NULL.
//! - store: `uint32_t gc_store(const uint8_t *prefix, uint32_t prefix_len,
//!                             const uint8_t *blob, uint32_t blob_len)`
//!   Returns 0 on success, non-zero on failure (store failure is non-fatal: the cache
//!   simply re-decompresses on next boot).

#[cfg(feature = "generator-cache-ffi")]
mod imp {
    use core::sync::atomic::{AtomicU32, Ordering};

    static LOAD_FPTR: AtomicU32 = AtomicU32::new(0);
    static STORE_FPTR: AtomicU32 = AtomicU32::new(0);

    type LoadC = extern "C" fn(*const u8, u32) -> *const u8;
    type StoreC = extern "C" fn(*const u8, u32, *const u8, u32) -> u32;

    pub fn set_hooks(load_fptr: u32, store_fptr: u32) {
        LOAD_FPTR.store(load_fptr, Ordering::Relaxed);
        STORE_FPTR.store(store_fptr, Ordering::Relaxed);
        let _ = monero_bulletproofs::register_generator_cache_hooks(load_adapter, store_adapter);
    }

    fn load_adapter(prefix: &'static [u8]) -> Option<&'static [u8]> {
        let f = LOAD_FPTR.load(Ordering::Relaxed);
        if f == 0 {
            return None;
        }
        let fptr: LoadC = unsafe { core::mem::transmute(f as usize) };
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
        let f = STORE_FPTR.load(Ordering::Relaxed);
        if f == 0 {
            return;
        }
        let fptr: StoreC = unsafe { core::mem::transmute(f as usize) };
        // Best effort: a failed store only costs boot time on the next run.
        let _ = fptr(
            prefix.as_ptr(),
            prefix.len() as u32,
            blob.as_ptr(),
            blob.len() as u32,
        );
    }
}

#[cfg(feature = "generator-cache-ffi")]
pub use imp::*;

/// C-ABI: register the flash-backend callbacks. Call once from C init (before the first
/// XMR sign). `load_fptr`/`store_fptr` are ARM thumb addresses of the C functions.
///
/// # Safety
/// Both pointers must be valid `extern "C"` functions with the documented signatures.
#[cfg(feature = "generator-cache-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_gen_cache_set_hooks(load_fptr: u32, store_fptr: u32) {
    imp::set_hooks(load_fptr, store_fptr);
}

// Production no-op stubs (feature off) so the C side always links.
#[cfg(not(feature = "generator-cache-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_gen_cache_set_hooks(_load_fptr: u32, _store_fptr: u32) {}
