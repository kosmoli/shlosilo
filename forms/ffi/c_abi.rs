//! C-ABI shim functions for L3 imperative shell (v2 §3.5 + §7.3)
//!
//! **P6.0e finalized form**:
//! - Length-style functions carry an `actual_len: *mut c_uint` out-param (the return value is only a status code)
//! - null pointer → ERR_NULL_POINTER (no longer BufferTooSmall)
//! - catch_unwind kept (zero-cost fallback: under release panic = abort it is a no-op)
//!
//! **v2 §4.1 invariants**:
//! - ❌ seed never crosses the FFI — sign only accepts mnemonic indices
//! - ✅ FFI accepts public material and returns public output
//! - ✅ Task 3: `shlosilo_sign_session_ffi` signs from a `KeySession` handle —
//!   still no seed/mnemonic parameter (the session is flux-constructed in
//!   caller-owned storage; the handle is dropped in place via
//!   `shlosilo_session_free_ffi`)

#[cfg(feature = "std")]
extern crate std;

// Z6 (C1 remediation, 2026-10-07): `alloc` is gated again. Nothing on the
// production face allocates — the session handle reclaim is a plain
// `drop_in_place` over CALLER-owned storage (R3/Z3.3c caller-workspace
// contract, see `shlosilo_session_free_ffi`), so the crate graph carries no
// allocator lang item. Instruments: `scripts/z6_langitem_check.sh` must
// report GRAPH-CLEAN and `probes/noalloc/build.sh` must link the sign paths
// against a C main with NO allocator. The declaration below remains only for
// the alloc-fallback face and the test modules in this file.
#[cfg(any(feature = "alloc-fallback", test))]
extern crate alloc;

/// catch_unwind shim: actually catches panics under std; direct call under no_std (panic=abort)
#[cfg(feature = "std")]
macro_rules! ffi_catch_unwind {
    ($body:expr) => {
        std::panic::catch_unwind($body)
    };
}
#[cfg(not(feature = "std"))]
macro_rules! ffi_catch_unwind {
    ($body:expr) => {{
        let r: ::core::result::Result<_, ::core::convert::Infallible> =
            ::core::result::Result::Ok($body());
        r
    }};
}

use crate::business;
use crate::derivation::path::DerivationPath;
use crate::entropy::mnemonic::{Mnemonic, WordCount};
use crate::error::{ShlosiloError, ShlosiloErrorCode, ShlosiloErrorKind};
use crate::ffi::error_code::{to_ffi_code, ERR_BUFFER_TOO_SMALL, ERR_NULL_POINTER, ERR_PANIC, OK};
use crate::network::Network;
use crate::types::SecretBytes;
use core::ffi::{c_char, c_int, c_uint};
use core::slice;

fn err(kind: ShlosiloErrorKind) -> ShlosiloError {
    ShlosiloError::new(kind)
}

// --- P2-03: FFI entry resource caps (external payload budgets) ---
/// passphrase cap: BIP-39 has no protocol limit, BIP-32 practice is ≤ 256B; overlong input is treated as invalid
const PASSPHRASE_MAX_LEN: usize = 256;
/// dice rolls cap: 24 words = 256 bit entropy, a 6-sided die needs ≥ 99 rolls; 1024 already exceeds the margin
const ROLLS_MAX_COUNT: usize = 1024;
/// Legacy sign_ffi payload cap (aligned with UR_PSBT_MAX_LEN)
const LEGACY_PSBT_MAX_LEN: usize = 2048;
/// Audit #5 P0-03: output-side budget — signature output ≤ payload + 512 overhead (unified at the 16KiB scale)
const SIGN_OUTPUT_BUF_MAX_LEN: usize = crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN + 512;
/// export_readonly output upper bound (a CryptoHDKey UR is ≈ 500B; unified with sign output to guard against over-declared capacity)
const EXPORT_OUTPUT_BUF_MAX_LEN: usize = crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN + 512;
/// mnemonic output buffer (create_account: 24 words × 2B)
const MNEMONIC_BUF_MAX_LEN: usize = crate::entropy::mnemonic::MAX_MNEMONIC_WORDS * 2;
/// DerivationPath element count cap (path.rs MAX_DEPTH)
const PATH_ELEMS_MAX: usize = crate::derivation::path::MAX_DEPTH;

/// Writes the actual length back to the out-param; null pointer allowed (the caller may only query status)
fn write_actual_len(ptr: *mut c_uint, len: usize) {
    if !ptr.is_null() {
        unsafe {
            *ptr = len as c_uint;
        }
    }
}

/// Audit #5 P0-03: unified safe construction of FFI pointer/length pairs — **all validation happens before the single unsafe block**.
///
/// Validation order (all steps mandatory):
/// 1. `(NULL, 0)` / `(NULL, len>0)` combination rules (optional allows the former and forbids the latter; required rejects both)
/// 2. `len <= max_len` (business budget — each entry's MAX constant)
/// 3. `len <= isize::MAX / size_of::<T>()`（Rust `from_raw_parts` safety contract——
///    on 32-bit Thumb, `u32::MAX` for `u16` elements already exceeds the address space; undetectable on a 64-bit host, UB on real hardware)
///
/// Only when all conditions pass do we enter unsafe construction. Callers must not "validate later in business code" to patch up the proof.
fn checked_slice<'a, T>(
    p: *const T,
    len: usize,
    max_len: usize,
    optional: bool,
) -> Option<&'a [T]> {
    if p.is_null() {
        return if optional && len == 0 {
            Some(&[]) // (NULL,0): semantics "caller has no such parameter"
        } else {
            None // required always rejects; (NULL,len>0) always rejects
        };
    }
    if len == 0 {
        // non-null zero length: no deref, return an empty slice directly (legal: the C side may pass a valid pointer + 0)
        return Some(&[]);
    }
    if len > max_len {
        return None; // business budget exceeded
    }
    // from_raw_parts safety contract: total byte count must not exceed isize::MAX
    if len > (isize::MAX as usize) / core::mem::size_of::<T>() {
        return None; // address space overflow — a real risk on 32-bit Thumb
    }
    // SAFETY: p is non-null; len*size_of::<T>() ≤ isize::MAX and ≤ max_len*SIZE (verified);
    // pointer validity is the C ABI contract (L3 guarantees the passed buffer is reachable and the length is truthful)
    Some(unsafe { slice::from_raw_parts(p, len) })
}

/// Audit #5 P0-03: mutable-output version of `checked_slice` (output_buf / frame_buf etc.).
/// Extra out-param requirement: len (buffer capacity) is likewise bound by the business cap, preventing a caller from
/// declaring a huge capacity and causing an out-of-bounds write on the Rust side.
fn checked_slice_mut<'a, T>(p: *mut T, len: usize, max_len: usize) -> Option<&'a mut [T]> {
    if p.is_null() {
        return None; // output buffer must be provided
    }
    if len == 0 {
        return Some(&mut []);
    }
    if len > max_len {
        return None;
    }
    if len > (isize::MAX as usize) / core::mem::size_of::<T>() {
        return None;
    }
    // SAFETY: same as checked_slice; the mut version is for output writes
    Some(unsafe { slice::from_raw_parts_mut(p, len) })
}

/// P0-02: optional inputs (passphrase / entropy) — `(NULL,0)` allowed, everything else goes through `checked_slice`.
/// Budget is passed by the caller (passphrase=PASSPHRASE_MAX_LEN / entropy=the corresponding cap); no longer relies on comments as a backstop.
fn optional_bytes_in(p: *const u8, len: usize, max_len: usize) -> Option<&'static [u8]> {
    checked_slice(p, len, max_len, true)
}

/// P0-02: required inputs — null / over-budget / beyond address space are all rejected.
fn required_bytes_in(p: *const u8, len: usize, max_len: usize) -> Option<&'static [u8]> {
    checked_slice(p, len, max_len, false)
}

/// P0-02: safe read of c_int count parameters — negatives are always rejected, never zero-extended via `as usize`.
/// Returns None → the caller returns InvalidMnemonic (word-count domain error).
fn mnemonic_count_usize(count: c_int) -> Option<usize> {
    usize::try_from(count).ok()
}

/// shlosilo_sign_ffi — mnemonic + UR payload → signature
///
/// Returns 0 = Ok (length written to *actual_len), negative = error code.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: the entry null-checks first, then from_raw_parts; the C side guarantees pointer validity or accepts the NULL error code
pub extern "C" fn shlosilo_sign_ffi(
    mnemonic_indices: *const u16,
    mnemonic_count: c_int, // 12 / 15 / 18 / 21 / 24
    passphrase: *const u8,
    passphrase_len: c_uint,
    ur_payload: *const u8,
    ur_payload_len: c_uint,
    network: c_uint,
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
    ws: *mut u8,
    ws_len: c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // P0-02 #4: prologue zeroes the out-param (also covers the null early-return)
                                     // Z3.3b workspace contract (2026-09-25, Kosmo): ws == NULL is a PURE PROBE —
                                     // reports the workspace requirement and returns before input parsing, key
                                     // derivation, or any RNG use; no output side effects (output_buf untouched).
    if ws.is_null() {
        write_actual_len(actual_len, shlosilo_sign_ws_len() as usize);
        return OK;
    }
    // Capacity is validated BEFORE execution; under-capacity reports the
    // required length through actual_len (documented exception to the
    // zero-on-failure rule — the caller needs the number to resize).
    let ws_need = shlosilo_sign_ws_len() as usize;
    if (ws_len as usize) < ws_need {
        write_actual_len(actual_len, ws_need);
        return to_ffi_code(&ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(ws_need),
        ));
    }
    if mnemonic_indices.is_null() || ur_payload.is_null() || output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    // P0-02 #1: count domain validation happens **before** any unsafe construction — negatives/invalid word counts are rejected outright
    let word_count = match mnemonic_count_usize(mnemonic_count).and_then(WordCount::try_from_count)
    {
        Some(wc) => wc,
        None => return ShlosiloErrorCode::InvalidMnemonic as c_int,
    };
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        // P0-03: mnemonic goes through checked_slice (u16 elements, budget 24 = whitelist cap)
        let mnem_slice = checked_slice(mnemonic_indices, word_count as usize, 24, false)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
        if ur_payload_len as usize > LEGACY_PSBT_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // P0-03: payload goes through checked_slice (budget LEGACY_PSBT_MAX_LEN=2048, validated before allocation)
        let payload_slice = checked_slice(
            ur_payload,
            ur_payload_len as usize,
            LEGACY_PSBT_MAX_LEN,
            false,
        )
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        // P0-03: output buffer goes through checked_slice_mut (budget SIGN_OUTPUT_BUF_MAX_LEN, guards against over-declared capacity)
        let out_slice =
            checked_slice_mut(output_buf, output_buf_len as usize, SIGN_OUTPUT_BUF_MAX_LEN)
                .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        // P0-02 #2: (NULL, len>0) rejected — a wrong passphrase pointer must not silently become an empty passphrase
        let pass_slice = optional_bytes_in(passphrase, passphrase_len as usize, PASSPHRASE_MAX_LEN)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
        if pass_slice.len() > PASSPHRASE_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        let mnemonic = Mnemonic::from_indices(mnem_slice, word_count)
            .map_err(|_| err(ShlosiloErrorKind::MnemonicInvalidWord))?;

        // P0-02 #3: network `as u8` narrowing wraparound (256→0) replaced by full-value validation via u8::try_from
        let n8 = u8::try_from(network).map_err(|_| err(ShlosiloErrorKind::NetworkUnrecognized))?;
        let _network =
            Network::try_from_u8(n8).ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;

        let input = business::sign::SignInput::Mnemonic {
            mnemonic,
            passphrase: pass_slice,
        };
        // Legacy interface (no type tag): first-byte inference survives only in this FFI; new callers use shlosilo_sign_ur_ffi
        let legacy_tag = crate::ur::ur_encode::UrTypeTag::from_bytes(payload_slice);
        let ws_slice = unsafe { core::slice::from_raw_parts_mut(ws, ws_need) };
        let mut ws = crate::business::sign::carve_sign_ws(ws_slice).ok_or_else(|| {
            ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(ws_need),
            )
        })?;
        business::sign::sign_with_entropy_ws(
            input,
            legacy_tag,
            payload_slice,
            &[],
            &[],
            Some(&mut ws),
            out_slice,
        )
    });

    match result {
        Ok(Ok(length)) => {
            write_actual_len(actual_len, length);
            OK
        }
        Ok(Err(e)) => {
            // R2: failure path zeroes actual_len — the caller must never read a stale value
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// Z3.3b: sign workspace capacity query (C-ABI workspace contract v1 — the
/// capacity stays a RUNTIME query, never frozen into the ABI).
///
/// Pure: no RNG consumption, no secret derivation, no output side effects.
/// The value comes from `SignWsLayout::compute()` — the SAME computation the
/// workspace carve uses (contract 3: one layout source of truth).
#[no_mangle]
pub extern "C" fn shlosilo_sign_ws_len() -> c_uint {
    crate::business::sign::SignWsLayout::compute().total as c_uint
}

/// Z3.3c: encode-handle workspace capacity query (C-ABI workspace contract v1 —
/// runtime query, never frozen into the ABI). Pure: no state, no side effects.
#[no_mangle]
pub extern "C" fn shlosilo_ur_encode_ws_len() -> c_uint {
    crate::ur::ur_multipart::ur_encode_ws_len() as c_uint
}

/// Z3.3c: decode-handle workspace capacity query (pools + handle, alignment
/// slop included). Pure: no state, no side effects. Same layout source as the
/// placement carve (contract 3).
#[no_mangle]
pub extern "C" fn shlosilo_ur_decode_ws_len() -> c_uint {
    crate::ur::ur_multipart::ur_decode_ws_len() as c_uint
}

/// Task 5a (2026-10-07): seed-QR scan-flow probe — classify a scanned payload
/// WITHOUT producing any key material (v2 §4.1: zero key output).
///
/// Wraps `entropy::seed_qr::classify` — the pure classifier that mirrors
/// `seed_qr::decode`'s recognition order (`ur:` guard first, then the disjoint
/// compact / digit length domains) but runs NO decode. The 12/24 word-count
/// split the C scan flow routes on is recovered from those disjoint domains
/// (16/32 raw bytes vs. 48/96 ASCII digits) — no second parsing pass.
///
/// Return codes (non-negative = class):
/// - `0` NotSeed — not a steel-plate payload (wrong length / charset / empty)
/// - `1` Standard12 — SeedQR standard, 12 words (48 `%04d` digits)
/// - `2` Standard24 — SeedQR standard, 24 words (96 digits)
/// - `3` Compact12 — CompactSeedQR, 12 words (16 raw entropy bytes)
/// - `4` Compact24 — CompactSeedQR, 24 words (32 raw entropy bytes)
/// - `5` UrUnsupported — `ur:` transport (`ur:crypto-seed` is a v2 concern;
///   it is REJECTED, never silently misread as plate data)
/// - negative = error: `ERR_NULL_POINTER` (-2) for a NULL buffer,
///   `EncodingError` (-21) when `data_len` exceeds the scan budget.
///
/// **Zero-key invariant**: the probe only reads the payload to classify it —
/// no decode, no mnemonic, no session, no seed value in the signature or the
/// result. Safe to call before user confirmation; the full validation (word
/// index range + BIP-39 checksum) stays in `seed_qr::decode` and runs at
/// session-open time (the keysource QR glue).
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: null-checked first; bounded slice below (P0-03 discipline)
pub extern "C" fn shlosilo_seed_qr_probe_ffi(data: *const u8, data_len: c_uint) -> c_int {
    use crate::entropy::seed_qr::{classify, SeedQrClass};
    if data.is_null() {
        return ERR_NULL_POINTER;
    }
    // Scan-payload budget: larger than any QR symbol can deliver (a QR code
    // tops out around 3 KiB) and far above the biggest plate payload (96
    // digits). Over-budget = invalid scan input, same policy as every other
    // FFI entry's over-cap input (EncodingError).
    const SCAN_PAYLOAD_MAX_LEN: usize = 4096;
    let payload = match checked_slice(data, data_len as usize, SCAN_PAYLOAD_MAX_LEN, false) {
        Some(s) => s,
        None => return to_ffi_code(&err(ShlosiloErrorKind::EncodingInvalidFormat)),
    };
    match classify(payload) {
        SeedQrClass::NotSeed => 0,
        // classify only answers Standard for 48|96 bytes and Compact for
        // 16|32 bytes (disjoint domains), so the length alone carries the
        // word count.
        SeedQrClass::Standard => {
            if payload.len() == 48 {
                1
            } else {
                2
            }
        }
        SeedQrClass::Compact => {
            if payload.len() == 16 {
                3
            } else {
                4
            }
        }
        SeedQrClass::UrTransport => 5,
    }
}

/// Plate-export modes for [`shlosilo_seed_qr_encode_ffi`] (the C contract).
pub const SEED_QR_MODE_STANDARD: c_int = 1;
pub const SEED_QR_MODE_COMPACT: c_int = 2;

/// shlosilo_seed_qr_encode_ffi — wallet entropy → steel-plate QR payload
/// (Phase 4 acceptance ②: shlosilo builds a wallet, exports SeedQR, an
/// external SeedSigner scans it back to the same wallet).
///
/// The EXPORT face of the seed-QR codecs (interface-detail §2: export is a
/// deliberately separate face from the KeySource import trait — nothing here
/// can open a session). Input is the raw BIP-39 entropy (16 = 12 words /
/// 32 = 24 words); output is the exact bytes a SeedQR QR symbol must carry:
/// - `SEED_QR_MODE_STANDARD` (1): `%04d` word-index digits, 48/96 ASCII
///   bytes (SeedSigner `SeedQrEncoder`),
/// - `SEED_QR_MODE_COMPACT` (2): raw entropy bytes, 16/32
///   (SeedSigner `CompactSeedQrEncoder`).
///
/// Encoder: the stack-buffer forms `seed_qr::encode_standard_into` /
/// `encode_compact_into` — no-alloc device-safe (the `alloc-fallback`-gated
/// `encode_standard`/`encode_compact` are unavailable on the zero-heap Z6
/// face and would break the no-heap picture). Payload is pinned byte-exact
/// against the SeedSigner oracle goldens (tests/seed_qr_oracle.rs).
///
/// Contract:
/// - `out_buf` receives the payload; `actual_len` receives the written
///   length (zeroed first on every path — R2: never a stale value).
/// - entropy length must be 16 or 32 (the 12/24 steel-plate family) —
///   anything else `MnemonicInvalidEntropyLength`.
/// - `out_buf_len` budget: `seed_qr::STANDARD_MAX_LEN` (96) bytes.
/// - negative = error: `ERR_NULL_POINTER` (-2), `BufferTooSmall` (-20),
///   `EncodingInvalidFormat` (-21) for format-class failures, and
///   `MnemonicInvalidEntropyLength` (-31, `InvalidMnemonic`) for
///   entropy-length violations — the two classes are distinct codes —
///   or the mapped validation error.
///
/// **Secret hygiene (the plate IS the wallet)**: `out_buf` leaves this call
/// holding the plaintext-equivalent seed material — the caller MUST wipe it
/// after rendering (volatile walk, same as the scan flow's plate wipe), and
/// showing it on screen is a deliberate secret-exposure surface (steel-plate
/// threat model: anyone who photographs the plate owns the wallet).
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: null-checked first; bounded slices below (P0-03 discipline)
pub extern "C" fn shlosilo_seed_qr_encode_ffi(
    mode: c_int,
    entropy: *const u8,
    entropy_len: c_uint,
    out_buf: *mut u8,
    out_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    use crate::entropy::seed_qr::{encode_compact_into, encode_standard_into, STANDARD_MAX_LEN};
    write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front
    if entropy.is_null() || out_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        // Entropy budget: 32 bytes is the 24-word plate cap; the steel-plate
        // family is EXACTLY 16/32 (BIP-39 proper also has 15/18/21 words —
        // those have no plate representation and are refused here).
        let ent = checked_slice(entropy, entropy_len as usize, 32, false).ok_or(
            ShlosiloError::new(ShlosiloErrorKind::MnemonicInvalidEntropyLength),
        )?;
        if ent.len() != 16 && ent.len() != 32 {
            return Err(ShlosiloError::new(
                ShlosiloErrorKind::MnemonicInvalidEntropyLength,
            ));
        }
        let out = checked_slice_mut(out_buf, out_buf_len as usize, STANDARD_MAX_LEN)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        // Full validation on the way out too (BIP-39 checksum included):
        // a plate export always carries a scan-importable wallet.
        let m = Mnemonic::from_entropy(ent)?;
        match mode {
            SEED_QR_MODE_STANDARD => encode_standard_into(&m, out),
            SEED_QR_MODE_COMPACT => encode_compact_into(&m, out),
            _ => Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)),
        }
    });
    match result {
        Ok(Ok(length)) => {
            write_actual_len(actual_len, length);
            OK
        }
        Ok(Err(e)) => {
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// shlosilo_sign_ur_ffi — full UR string + mnemonic → signature (P6.1d)
///
/// L3 feeds `ur:crypto-psbt/...` / `ur:eth-sign-request/...` / `ur:xmr-txunsigned/...` directly;
/// UR decoding + type tag validation both happen inside the library (thin L3, thick L1).
///
/// **§B.5 RNG injection extension (2026-08-28)**: new entropy_ptr / entropy_len parameters —
/// REQUIRED for XMR signing (≥16B; L3 commits to the source and min-entropy); for BTC/ETH deterministic
/// backends, pass NULL/0. Same (keys, tx, entropy) → same signature (deterministic retry).
///
/// Returns 0 = Ok, negative = error code; signature bytes are written to output_buf.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: the entry null-checks first, then from_raw_parts; the C side guarantees pointer validity or accepts the NULL error code
pub extern "C" fn shlosilo_sign_ur_ffi(
    uri: *const c_char, // null-terminated C string
    mnemonic_indices: *const u16,
    mnemonic_count: c_int,
    passphrase: *const u8,
    passphrase_len: c_uint,
    network: c_uint,
    entropy_ptr: *const u8, // §B.5: may be NULL (BTC/ETH do not need it)
    entropy_len: c_uint,
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
    ws: *mut u8,
    ws_len: c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // P0-02 #4: prologue zeroes the out-param
                                     // Z3.3b workspace contract (2026-09-25, Kosmo): ws == NULL is a PURE PROBE —
                                     // reports the workspace requirement and returns before input parsing, key
                                     // derivation, or any RNG use; no output side effects (output_buf untouched).
    if ws.is_null() {
        write_actual_len(actual_len, shlosilo_sign_ws_len() as usize);
        return OK;
    }
    // Capacity is validated BEFORE execution; under-capacity reports the
    // required length through actual_len (documented exception to the
    // zero-on-failure rule — the caller needs the number to resize).
    let ws_need = shlosilo_sign_ws_len() as usize;
    if (ws_len as usize) < ws_need {
        write_actual_len(actual_len, ws_need);
        return to_ffi_code(&ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(ws_need),
        ));
    }
    if uri.is_null() || mnemonic_indices.is_null() || output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    // P0-02 #1: count domain validation precedes any unsafe construction
    let word_count = match mnemonic_count_usize(mnemonic_count).and_then(WordCount::try_from_count)
    {
        Some(wc) => wc,
        None => return ShlosiloErrorCode::InvalidMnemonic as c_int,
    };
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        // C string → &str (no alloc: scan directly to \0)
        let mut len = 0usize;
        unsafe {
            while *uri.add(len) != 0 {
                len += 1;
                if len > 4096 {
                    return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
                }
            }
        }
        let uri_slice = checked_slice(uri.cast::<u8>(), len, 4096, false)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
        let uri_str = core::str::from_utf8(uri_slice)
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;

        // UR decoding
        let t_ur = crate::device_timing::Mark::start(crate::device_timing::STAGE_UR_DECODE);
        let decoded = crate::ur::ur_decode::decode(uri_str)?;
        t_ur.end();

        // §B.5 entropy injection (NULL → empty slice; the XMR branch does an internal ≥16B misuse guard)
        // P0-02 #2: (NULL, len>0) rejected
        let entropy_slice = optional_bytes_in(
            entropy_ptr,
            entropy_len as usize,
            crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN,
        )
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;

        // P0-03: mnemonic goes through checked_slice
        let mnem_slice = checked_slice(mnemonic_indices, word_count as usize, 24, false)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
        // P0-03: output buffer goes through checked_slice_mut (budget SIGN_OUTPUT_BUF_MAX_LEN)
        let out_slice =
            checked_slice_mut(output_buf, output_buf_len as usize, SIGN_OUTPUT_BUF_MAX_LEN)
                .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        // P0-02 #2: (NULL, len>0) rejected
        let pass_slice = optional_bytes_in(passphrase, passphrase_len as usize, PASSPHRASE_MAX_LEN)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
        if pass_slice.len() > PASSPHRASE_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        let mnemonic = Mnemonic::from_indices(mnem_slice, word_count)
            .map_err(|_| err(ShlosiloErrorKind::MnemonicInvalidWord))?;

        // P0-02 #3: network narrowing wraparound replaced by full-value validation via u8::try_from
        let n8 = u8::try_from(network).map_err(|_| err(ShlosiloErrorKind::NetworkUnrecognized))?;
        let network_parsed =
            Network::try_from_u8(n8).ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;

        let input = business::sign::SignInput::Mnemonic {
            mnemonic,
            passphrase: pass_slice,
        };
        // P1-02: network enters the decision (BTC mainnet-only / ETH chain_id mapping validation)
        business::sign::check_network(decoded.type_tag(), decoded.as_ref(), network_parsed)?;
        // P1-01: UR type tag threaded through to the business layer (no longer inferred from the payload's first byte)
        // §B.5: entropy passthrough (XMR REQUIRED / BTC-ETH NOT REQUIRED)
        let ws_slice = unsafe { core::slice::from_raw_parts_mut(ws, ws_need) };
        let mut ws = crate::business::sign::carve_sign_ws(ws_slice).ok_or_else(|| {
            ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(ws_need),
            )
        })?;
        business::sign::sign_with_entropy_ws(
            input,
            decoded.type_tag(),
            decoded.as_ref(),
            &[],
            entropy_slice,
            Some(&mut ws),
            out_slice,
        )
    });

    match result {
        Ok(Ok(length)) => {
            write_actual_len(actual_len, length);
            OK
        }
        Ok(Err(e)) => {
            // R2: failure path zeroes actual_len — the caller must never read a stale value
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// shlosilo_export_readonly_ffi — mnemonic + path → read-only credential UR
///
/// **P1-04 (2026-08-29)**: seed no longer crosses the FFI. The entry takes mnemonic indices + passphrase,
/// restores the BIP-39 seed on the spot inside the library (stack buffer, `SecretBytes::take` takes over zeroing), discarded once export completes.
///
/// paths is a flat u32 array (hardened bit = 0x8000_0000),
/// `path_elem_count` is the element count of this one path (v1: single path).
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: the entry null-checks first, then from_raw_parts; the C side guarantees pointer validity or accepts the NULL error code
pub extern "C" fn shlosilo_export_readonly_ffi(
    mnemonic_indices: *const u16,
    mnemonic_count: c_int,
    passphrase: *const u8,
    passphrase_len: c_uint,
    network: c_uint,
    path_elems: *const u32,
    path_elem_count: c_uint,
    protocol: c_uint, // ExportProtocol as u32
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // P0-02 #4: prologue zeroes the out-param
    if mnemonic_indices.is_null() || path_elems.is_null() || output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    // P0-02 #1 (the main P0 finding of this item): count domain validation precedes any unsafe construction —
    // a negative mnemonic_count used to be zero-extended via `as usize` into usize::MAX and fed to from_raw_parts = UB
    let word_count = match mnemonic_count_usize(mnemonic_count).and_then(WordCount::try_from_count)
    {
        Some(wc) => wc,
        None => return ShlosiloErrorCode::InvalidMnemonic as c_int,
    };
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        // P0-03: mnemonic goes through checked_slice
        let mnem_slice = checked_slice(mnemonic_indices, word_count as usize, 24, false)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
        // P0-03: path_elems goes through checked_slice (u32 elements, budget MAX_DEPTH=16 — the direct path of the audit finding)
        let elem_slice = checked_slice(path_elems, path_elem_count as usize, PATH_ELEMS_MAX, false)
            .ok_or(ShlosiloError::new(
                ShlosiloErrorKind::DerivationPathInvalidSyntax,
            ))?;
        let path = DerivationPath::from_flat(elem_slice.iter().copied())
            .map_err(|_| err(ShlosiloErrorKind::DerivationPathInvalidSyntax))?;

        // P0-03: output buffer goes through checked_slice_mut (budget EXPORT_OUTPUT_BUF_MAX_LEN)
        let out_slice = checked_slice_mut(
            output_buf,
            output_buf_len as usize,
            EXPORT_OUTPUT_BUF_MAX_LEN,
        )
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        // P0-02 #2: (NULL, len>0) rejected
        let pass_slice = optional_bytes_in(passphrase, passphrase_len as usize, PASSPHRASE_MAX_LEN)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
        if pass_slice.len() > PASSPHRASE_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        // P0-02 #3: network narrowing wraparound replaced by full-value validation via u8::try_from
        let n8 = u8::try_from(network).map_err(|_| err(ShlosiloErrorKind::NetworkUnrecognized))?;
        let network =
            Network::try_from_u8(n8).ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;

        let protocol = match protocol {
            0 => business::export_readonly::ExportProtocol::CryptoHdKey,
            1 => business::export_readonly::ExportProtocol::CryptoAccount,
            2 => business::export_readonly::ExportProtocol::CryptoMultiAccounts,
            3 => business::export_readonly::ExportProtocol::JsonMoneroViewkey,
            4 => business::export_readonly::ExportProtocol::ArweaveCryptoAccount,
            _ => return Err(err(ShlosiloErrorKind::ExportProtocolUnimplemented)),
        };

        // on-the-spot seed restore: stack buffer → SecretBytes takes over (original copy zeroed) → export → ZeroizeOnDrop at scope end
        // P0-02: word_count already passed the whitelist in the prologue (this spot originally did a second `mnemonic_count as usize`)
        let wc = word_count;
        let mnemonic = Mnemonic::from_indices(mnem_slice, wc)
            .map_err(|_| err(ShlosiloErrorKind::MnemonicInvalidWord))?;
        let mut seed_buf = [0u8; 64];
        business::restore_seed::restore_seed(&mnemonic, pass_slice, &mut seed_buf)?;
        let seed = SecretBytes::take(&mut seed_buf);

        business::export_readonly::export_readonly(
            protocol,
            seed.expose(),
            network,
            &[path],
            out_slice,
        )
    });

    match result {
        Ok(Ok(length)) => {
            write_actual_len(actual_len, length);
            OK
        }
        Ok(Err(e)) => {
            // R2: failure path zeroes actual_len — the caller must never read a stale value
            write_actual_len(actual_len, 0);
            to_ffi_code(&e)
        }
        Err(_) => {
            write_actual_len(actual_len, 0);
            ERR_PANIC
        }
    }
}

/// shlosilo_create_account_ffi — dice entropy → mnemonic (u16 LE index pairs)
///
/// **P1-04 (2026-08-29)**: `seed_out` removed — seed does not cross the FFI (v2 security model).
/// dice → mnemonic is the sole output; later signing/export takes mnemonic directly (seed restored on the spot inside the library).
/// passphrase kept (metadata to be written into device storage on a future offline create); currently only length-cap validated.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: the entry null-checks first, then from_raw_parts; the C side guarantees pointer validity or accepts the NULL error code
pub extern "C" fn shlosilo_create_account_ffi(
    word_count: c_uint, // 12 / 15 / 18 / 21 / 24
    sides: c_uint,
    rolls: *const u8,
    rolls_count: c_uint,
    passphrase: *const u8,
    passphrase_len: c_uint,
    mnemonic_buf: *mut u8, // word_count × 2 bytes (u16 LE indices)
    mnemonic_buf_len: c_uint,
) -> c_int {
    if rolls.is_null() || mnemonic_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<(), ShlosiloError> {
        if rolls_count as usize > ROLLS_MAX_COUNT {
            return Err(err(ShlosiloErrorKind::DiceRollsInvalidCount));
        }
        // P0-03: rolls go through checked_slice (budget ROLLS_MAX_COUNT)
        let rolls_slice = checked_slice(rolls, rolls_count as usize, ROLLS_MAX_COUNT, false)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::DiceRollsInvalidCount))?;
        // SAFETY: mnemonic_buf is non-null (excluded in the prologue)
        // P0-03: mnemonic output goes through checked_slice_mut (budget 48B)
        let mnemonic_slice = checked_slice_mut(
            mnemonic_buf,
            mnemonic_buf_len as usize,
            MNEMONIC_BUF_MAX_LEN,
        )
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        // P0-02 #2: (NULL, len>0) rejected
        let pass_slice = optional_bytes_in(passphrase, passphrase_len as usize, PASSPHRASE_MAX_LEN)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
        if pass_slice.len() > PASSPHRASE_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }

        let wc = WordCount::try_from_count(word_count as usize)
            .ok_or_else(|| err(ShlosiloErrorKind::MnemonicInvalidWordCount))?;

        // P0-02 #3: sides `as u8` narrowing wraparound (262→6) replaced by full-value validation via u8::try_from
        let sides8 = u8::try_from(sides).map_err(|_| err(ShlosiloErrorKind::InvalidDiceConfig))?;

        business::create_account::create_account(
            wc,
            sides8,
            rolls_slice,
            pass_slice,
            mnemonic_slice,
        )
    });

    match result {
        Ok(Ok(())) => OK,
        Ok(Err(e)) => to_ffi_code(&e), // create_account has no actual_len out-param
        Err(_) => ERR_PANIC,
    }
}

// P1-04 (2026-08-29): shlosilo_restore_seed_ffi has been removed — once seed no longer crosses the FFI this entry
// has no reason to exist (Kosmo's call). Mnemonic validity checking is inlined in the sign/export entries.

/// List of supported Network u8 values (for UI dispatch at L3 startup)
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: the entry null-checks first, then from_raw_parts; the C side guarantees pointer validity or accepts the NULL error code
pub extern "C" fn shlosilo_supported_networks_ffi(
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front
    if output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let out_slice = checked_slice_mut(output_buf, output_buf_len as usize, 256)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        // Gate4 #1: the real matrix — only list networks the business entries can actually complete:
        // BTC crypto-psbt is mainnet only (check_network rejects the rest); ETH mainnet/sepolia/goerli;
        // XMR is fixed to MoneroPath::mainnet. testnet/signet/stagenet are unsupported and not claimed.
        const SUPPORTED: [u8; 5] = [
            0,  // BitcoinMainnet
            10, // EthereumMainnet
            11, // EthereumSepolia
            12, // EthereumGoerli
            90, // MoneroMainnet
        ];
        if out_slice.len() < SUPPORTED.len() {
            return Err(err(ShlosiloErrorKind::BufferTooSmall));
        }
        out_slice[..SUPPORTED.len()].copy_from_slice(&SUPPORTED);
        Ok(SUPPORTED.len())
    });

    match result {
        Ok(Ok(n)) => {
            write_actual_len(actual_len, n);
            OK
        }
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

/// List of supported ExportProtocol u8 values
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: the entry null-checks first, then from_raw_parts; the C side guarantees pointer validity or accepts the NULL error code
pub extern "C" fn shlosilo_supported_protocols_ffi(
    output_buf: *mut u8,
    output_buf_len: c_uint,
    actual_len: *mut c_uint,
) -> c_int {
    write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front
    if output_buf.is_null() {
        return ERR_NULL_POINTER;
    }
    let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
        let out_slice = checked_slice_mut(output_buf, output_buf_len as usize, 256)
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        // Gate4 #1 (re-reviewed 2026-09-01): capability may only claim items the business entries can actually complete.
        // export_readonly only implements CryptoHdKey (and mainnet only),
        // all other arms return ExportProtocolUnimplemented — they must not enter the capability list.
        let protocols = [0u8]; // CryptoHdKey
        if out_slice.len() < protocols.len() {
            return Err(err(ShlosiloErrorKind::BufferTooSmall));
        }
        out_slice[..protocols.len()].copy_from_slice(&protocols);
        Ok(protocols.len())
    });

    match result {
        Ok(Ok(n)) => {
            write_actual_len(actual_len, n);
            OK
        }
        Ok(Err(e)) => to_ffi_code(&e),
        Err(_) => ERR_PANIC,
    }
}

// Keep the constant referenced to avoid an unused warning
const _: c_int = ERR_NULL_POINTER;
const _: c_int = ERR_BUFFER_TOO_SMALL;

// --- R3 typed multipart FFI (2026-08-31) ---------------------------------
pub mod r3 {
    use super::*;
    use crate::types::key_session::KeySession;
    use crate::ur::ur_multipart::{
        UrMultipartDecoder, UrMultipartEncoder, MULTIPART_FRAME_MAX_LEN,
    };

    // --- R3: typed multipart FFI (finalized 2026-08-31 — replaces legacy first-byte type guessing) ---
    //
    // Dual-channel architecture (aligned with the keystone gui_model.c pattern):
    //   single large QR frame = existing shlosilo_sign_ur_ffi / ur_encode::encode (payload ≤ UR_PSBT_MAX_LEN)
    //   animated multipart     = this group of three functions (payload ≤ 16 KiB, frame stream `ur:<type>/<seq>-<count>/<bw>`)
    //
    // Handle contract:
    //   - encode_begin / decode_new place the handle in CALLER workspace (Z3.3c;
    //     constructed in place over the ws buffer, non-null = success) — never Box::into_raw
    //   - reusing the same handle / double-free is an L3 bug — debug_assert plus an error-code fallback
    //   - encode_free / decode_free release them; other functions return ERR_NULL_POINTER for a null handle

    /// Write cap for a single-frame string (L3 buffer; 200B fragment → frame ≈ 420 chars, 1024 suffices)
    const FRAME_BUF_MAX_LEN: usize = 1024;

    /// R3: create a multipart encoder. Returns a handle (non-null) on success, null on failure.
    /// type_name: ASCII alphanumeric + '-' (e.g. "xmr-txunsigned")
    /// L3 must call shlosilo_ur_encode_free when done.
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // P0-02: visible to clippy once mod r3 becomes pub; contract same as the main entries (null-check first)
    pub extern "C" fn shlosilo_ur_encode_begin(
        type_name: *const c_char,
        payload: *const u8,
        payload_len: c_uint,
        max_fragment_len: c_uint,
        ws: *mut u8,
        ws_len: c_uint,
    ) -> *mut UrMultipartEncoder<'static> {
        let result = ffi_catch_unwind!(|| -> Option<*mut UrMultipartEncoder> {
            // Z3.3c: caller-workspace contract — the capacity is queried via
            // shlosilo_ur_encode_ws_len (the pure probe); NULL ws or
            // under-capacity fails before any state is created.
            if ws.is_null() || (ws_len as usize) < crate::ur::ur_multipart::ur_encode_ws_len() {
                return None;
            }
            if type_name.is_null() || payload.is_null() {
                return None;
            }
            // type_name: C string → &str (scan to \0, cap 64)
            let mut tlen = 0usize;
            unsafe {
                while *type_name.add(tlen) != 0 {
                    tlen += 1;
                    if tlen > 64 {
                        return None;
                    }
                }
            }
            let tslice = checked_slice(type_name.cast::<u8>(), tlen, 64, false)?;
            let tname = core::str::from_utf8(tslice).ok()?;
            // P0-02 #2: payload is required — null is always rejected (even (NULL,0) is not allowed; encoding an empty payload is meaningless)
            let pslice = required_bytes_in(
                payload,
                payload_len as usize,
                crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN,
            )?;
            let enc = UrMultipartEncoder::new(tname, pslice, max_fragment_len as usize).ok()?;
            // SAFETY: ws_len >= ur_encode_ws_len() checked above; the workspace
            // stays at a stable address until shlosilo_ur_encode_free.
            let ws_slice = unsafe {
                core::slice::from_raw_parts_mut(ws, crate::ur::ur_multipart::ur_encode_ws_len())
            };
            crate::ur::ur_multipart::ur_encode_place(ws_slice, enc)
        });
        match result {
            Ok(Some(h)) => h,
            _ => core::ptr::null_mut(),
        }
    }

    /// R3: get the next frame URI string (written to frame_buf, NUL-terminated).
    /// Returns 0 = Ok; negative = error code. Repeated calls produce the fountain redundancy frame stream.
    ///
    /// frame_buf_len must be at least 1024 (FRAME_BUF_MAX_LEN); shorter buffers are
    /// rejected with BufferTooSmall even though a 200-byte-fragment frame is ~460 chars.
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_encode_next(
        handle: *mut UrMultipartEncoder<'static>,
        frame_buf: *mut u8,
        frame_buf_len: c_uint,
        actual_len: *mut c_uint,
    ) -> c_int {
        write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front

        if handle.is_null() || frame_buf.is_null() {
            return ERR_NULL_POINTER;
        }
        if frame_buf_len < FRAME_BUF_MAX_LEN as c_uint {
            // L3 must supply a large-enough buffer
            write_actual_len(actual_len, 0);
            return ERR_BUFFER_TOO_SMALL;
        }
        let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
            let enc = unsafe { &mut *handle };
            // Z2.4c: build the frame directly into the caller buffer (was String + copy)
            let mut scratch = [0u8; 1024]; // part CBOR intermediate (A-class; oversized parts error explicitly)
            let out = unsafe { core::slice::from_raw_parts_mut(frame_buf, frame_buf_len as usize) };
            let n = enc.next_frame_into(&mut scratch, &mut out[..frame_buf_len as usize - 1])?;
            out[n] = 0;
            Ok(n)
        });
        match result {
            Ok(Ok(n)) => {
                write_actual_len(actual_len, n);
                OK
            }
            Ok(Err(e)) => {
                write_actual_len(actual_len, 0);
                to_ffi_code(&e)
            }
            Err(_) => {
                write_actual_len(actual_len, 0);
                ERR_PANIC
            }
        }
    }

    /// R3: XMR cyclic catch-up frames (seq wraps back to 1 at the top, looping forever so software wallets can catch up)
    ///
    /// frame_buf_len must be at least 1024 (FRAME_BUF_MAX_LEN); shorter buffers are
    /// rejected with BufferTooSmall even though a 200-byte-fragment frame is ~460 chars.
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_encode_next_cyclic(
        handle: *mut UrMultipartEncoder<'static>,
        frame_buf: *mut u8,
        frame_buf_len: c_uint,
        actual_len: *mut c_uint,
    ) -> c_int {
        write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front

        if handle.is_null() || frame_buf.is_null() {
            return ERR_NULL_POINTER;
        }
        if frame_buf_len < FRAME_BUF_MAX_LEN as c_uint {
            write_actual_len(actual_len, 0);
            return ERR_BUFFER_TOO_SMALL;
        }
        let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
            let enc = unsafe { &mut *handle };
            // Z2.4c: build the frame directly into the caller buffer (was String + copy)
            let mut scratch = [0u8; 1024]; // part CBOR intermediate (A-class; oversized parts error explicitly)
            let out = unsafe { core::slice::from_raw_parts_mut(frame_buf, frame_buf_len as usize) };
            let n =
                enc.next_cyclic_frame_into(&mut scratch, &mut out[..frame_buf_len as usize - 1])?;
            out[n] = 0;
            Ok(n)
        });
        match result {
            Ok(Ok(n)) => {
                write_actual_len(actual_len, n);
                OK
            }
            Ok(Err(e)) => {
                write_actual_len(actual_len, 0);
                to_ffi_code(&e)
            }
            Err(_) => {
                write_actual_len(actual_len, 0);
                ERR_PANIC
            }
        }
    }

    /// R3: release the encoder handle. Null-safe (idempotent).
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // P0-02: visible to clippy once mod r3 becomes pub; free contract: single-owner
    pub extern "C" fn shlosilo_ur_encode_free(handle: *mut UrMultipartEncoder) {
        // Z3.3c: the handle lives in caller workspace — free only drops the
        // value in place (no deallocation; the memory returns to the caller).
        // Single-owner free contract unchanged: exactly one free per handle.
        if !handle.is_null() {
            unsafe { core::ptr::drop_in_place(handle) };
        }
    }

    // Z3.3a LEDGER CORRECTION (2026-09-25): the "ffi staging 4 sites" count from the
    // Z2.5 ledger conflated test conveniences with production staging. Production
    // heap at this seam is exactly the two opaque handle Boxes below (encode handle
    // + decode handle, paired with their _free) plus the decoder's leak-staging
    // pools inside `UrMultipartDecoder::new()`. The Vec<String>/indices.to_vec
    // sites are #[cfg(test)] fixtures. Handle memory moves to caller buffers at
    // Z3.3c (Z6 no-allocator pressure); the sign shell moves with the C-ABI
    // workspace at Z3.3b (proposed C shape in the Z3 design doc).
    /// R3: create a multipart decoder. Returns a handle on success, null on failure.
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: ws_len is checked
                                               // against shlosilo_ur_decode_ws_len() before from_raw_parts_mut; the
                                               // caller guarantees ws points to ws_len valid bytes kept at a stable
                                               // address until shlosilo_ur_decode_free (Z3.3c workspace contract).
    pub extern "C" fn shlosilo_ur_decode_new(
        ws: *mut u8,
        ws_len: c_uint,
    ) -> *mut UrMultipartDecoder<'static> {
        let result = ffi_catch_unwind!(|| -> *mut UrMultipartDecoder {
            // Z3.3c: caller-workspace contract — capacity via
            // shlosilo_ur_decode_ws_len (the pure probe); NULL ws or
            // under-capacity returns null before anything is created.
            if ws.is_null() {
                return core::ptr::null_mut();
            }
            let need = crate::ur::ur_multipart::ur_decode_ws_len();
            if (ws_len as usize) < need {
                return core::ptr::null_mut();
            }
            let ws_slice = unsafe { core::slice::from_raw_parts_mut(ws, need) };
            crate::ur::ur_multipart::ur_decode_ws_place(ws_slice).unwrap_or(core::ptr::null_mut())
        });
        match result {
            Ok(h) => h,
            Err(_) => core::ptr::null_mut(),
        }
    }

    /// R3: feed one frame URI (NUL-terminated C string).
    /// Returns 0 = Ok (accepted status written to *accepted_out: 1 = new information, 0 = duplicate frame)
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_decode_feed(
        handle: *mut UrMultipartDecoder<'static>,
        frame: *const c_char,
        accepted_out: *mut c_uint,
    ) -> c_int {
        if handle.is_null() || frame.is_null() {
            return ERR_NULL_POINTER;
        }
        // Gate4 #2: out-param zeroed up front — the C side reads a deterministic 0 on any later failure path
        if !accepted_out.is_null() {
            unsafe { *accepted_out = 0 };
        }
        let result = ffi_catch_unwind!(|| -> Result<bool, ShlosiloError> {
            let mut flen = 0usize;
            unsafe {
                while *frame.add(flen) != 0 {
                    flen += 1;
                    if flen > MULTIPART_FRAME_MAX_LEN {
                        return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
                    }
                }
            }
            let fslice = checked_slice(
                frame.cast::<u8>(),
                flen,
                crate::ur::ur_multipart::MULTIPART_FRAME_MAX_LEN,
                false,
            )
            .ok_or_else(|| ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat))?;
            let fstr = core::str::from_utf8(fslice)
                .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
            let dec = unsafe { &mut *handle };
            dec.receive_frame(fstr)
        });
        match result {
            Ok(Ok(accepted)) => {
                if !accepted_out.is_null() {
                    unsafe { *accepted_out = accepted as c_uint };
                }
                OK
            }
            Ok(Err(e)) => to_ffi_code(&e),
            Err(_) => ERR_PANIC,
        }
    }

    /// R3: decode progress 0..=99 (100 is expressed via complete)
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_decode_progress(handle: *mut UrMultipartDecoder) -> c_int {
        if handle.is_null() {
            return ERR_NULL_POINTER;
        }
        let result = ffi_catch_unwind!(|| -> u8 { unsafe { &*handle }.progress() });
        match result {
            Ok(p) => p as c_int,
            Err(_) => ERR_PANIC,
        }
    }

    /// R3: whether decoding is complete
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_decode_complete(handle: *mut UrMultipartDecoder) -> c_int {
        if handle.is_null() {
            return ERR_NULL_POINTER;
        }
        let result = ffi_catch_unwind!(|| -> bool { unsafe { &*handle }.complete() });
        match result {
            Ok(c) => c as c_int,
            Err(_) => ERR_PANIC,
        }
    }

    /// R3: get the complete payload (written to payload_buf; actual length written to actual_len).
    /// Payload semantics (2026-10-12): any complete CBOR byte-string shell is
    /// stripped from the reassembled message (bare messages pass through), so
    /// the delivered bytes are the container itself.
    /// Calling before completion → ERR_UNKNOWN; buffer smaller than the reassembled
    /// capacity (`fragment_length × sequence_count`, padding INCLUDED - not the
    /// delivered payload length) → ERR_BUFFER_TOO_SMALL with actual_len set to that
    /// capacity for the retry allocation. On success actual_len is the delivered
    /// payload length (padding excluded, CBOR shell stripped).
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_decode_payload(
        handle: *mut UrMultipartDecoder<'static>,
        payload_buf: *mut u8,
        payload_buf_len: c_uint,
        actual_len: *mut c_uint,
    ) -> c_int {
        write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front

        if handle.is_null() || payload_buf.is_null() {
            return ERR_NULL_POINTER;
        }
        let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
            let dec = unsafe { &*handle };
            // v1: payload goes straight into the caller buffer (no Vec).
            let out =
                unsafe { core::slice::from_raw_parts_mut(payload_buf, payload_buf_len as usize) };
            let n = dec.payload_into(out)?.ok_or_else(err_unknown)?;
            Ok(n)
        });
        // BufferTooSmall special case: actual_len gets the **required value** (L3 retries the allocation accordingly),
        // all other failure paths keep the R2 zeroing discipline.
        let required: usize = match &result {
            Ok(Err(e)) if e.kind == ShlosiloErrorKind::BufferTooSmall => {
                ffi_catch_unwind!(|| -> Option<usize> {
                    unsafe { &*handle }.payload_len().ok().flatten()
                })
                .ok()
                .flatten()
                .unwrap_or(0)
            }
            _ => 0,
        };
        match result {
            Ok(Ok(n)) => {
                write_actual_len(actual_len, n);
                OK
            }
            Ok(Err(e)) => {
                write_actual_len(actual_len, required);
                to_ffi_code(&e)
            }
            Err(_) => {
                write_actual_len(actual_len, 0);
                ERR_PANIC
            }
        }
    }

    fn err_type_name() -> ShlosiloError {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    }

    fn err_unknown() -> ShlosiloError {
        ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
    }

    /// R3/P0-C (2026-09-01): get the decoded UR type (written to type_buf as NUL-terminated ASCII).
    /// Before completion or with no frames → EncodingInvalidFormat; buffer too small → BufferTooSmall (actual_len gets the required value, including NUL).
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_decode_type(
        handle: *mut UrMultipartDecoder<'static>,
        type_buf: *mut u8,
        type_buf_len: c_uint,
        actual_len: *mut c_uint,
    ) -> c_int {
        write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front

        if handle.is_null() || type_buf.is_null() {
            return ERR_NULL_POINTER;
        }
        let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
            let dec = unsafe { &*handle };
            let t = dec.ur_type().ok_or_else(err_unknown)?;
            // +1 for NUL
            if t.len() + 1 > type_buf_len as usize {
                return Err(err(ShlosiloErrorKind::BufferTooSmall));
            }
            unsafe {
                core::ptr::copy_nonoverlapping(t.as_ptr(), type_buf, t.len());
                *type_buf.add(t.len()) = 0;
            }
            Ok(t.len() + 1)
        });
        // BufferTooSmall special case: actual_len gets the required value (including NUL); other failures zero it
        let required: usize = match &result {
            Ok(Err(e)) if e.kind == ShlosiloErrorKind::BufferTooSmall => {
                ffi_catch_unwind!(|| -> Option<usize> {
                    Some(unsafe { &*handle }.ur_type()?.len() + 1)
                })
                .ok()
                .flatten()
                .unwrap_or(0)
            }
            _ => 0,
        };
        match result {
            Ok(Ok(n)) => {
                write_actual_len(actual_len, n);
                OK
            }
            Ok(Err(e)) => {
                write_actual_len(actual_len, required);
                to_ffi_code(&e)
            }
            Err(_) => {
                write_actual_len(actual_len, 0);
                ERR_PANIC
            }
        }
    }

    /// Task 5b (2026-10-08): decode ONE single-fragment UR (`ur:<type>/<body>`)
    /// into the typed face's input pair — no key material anywhere in this
    /// entry (the payload is an unsigned request).
    ///
    /// Why a separate entry: the session sign face (`shlosilo_sign_session_ffi`)
    /// is typed-only, and the R3 fountain decoder deliberately rejects single
    /// frames ("single frames go through ur_decode::decode"). The C scan flow
    /// hits exactly that gap when a keysource QR session is live and a
    /// single-frame sign request is scanned — multipart frames keep using the
    /// fountain decoder entries.
    ///
    /// - `uri`: NUL-terminated `ur:<type>/<body>`; multipart shapes
    ///   (`ur:<type>/<seq>-<count>/<body>`) are REJECTED here (-21).
    /// - `type_buf` / `type_buf_len`: receive the NUL-terminated type name.
    /// - `payload` / `payload_len`: receive the payload bytes (2026-10-12
    ///   semantics: any complete CBOR byte-string shell is stripped — bare
    ///   messages pass through — so the delivered bytes are the container);
    ///   `actual_len` receives the delivered length on success and the
    ///   required payload length on `ERR_BUFFER_TOO_SMALL` (-20).
    ///
    /// Returns 0 = Ok, negative = error code (-2 NULL argument, -20 buffer
    /// too small, -21 malformed / multipart URI).
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: entry null-checks first
    pub extern "C" fn shlosilo_ur_decode_uri_ffi(
        uri: *const c_char,
        type_buf: *mut u8,
        type_buf_len: c_uint,
        payload: *mut u8,
        payload_len: c_uint,
        actual_len: *mut c_uint,
    ) -> c_int {
        write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front
        if uri.is_null() || type_buf.is_null() || payload.is_null() {
            return ERR_NULL_POINTER;
        }
        let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
            let mut ulen = 0usize;
            unsafe {
                while *uri.add(ulen) != 0 {
                    ulen += 1;
                    if ulen > MULTIPART_FRAME_MAX_LEN {
                        return Err(err_type_name());
                    }
                }
            }
            let uslice = checked_slice(uri.cast::<u8>(), ulen, MULTIPART_FRAME_MAX_LEN, false)
                .ok_or_else(err_type_name)?;
            let ustr = core::str::from_utf8(uslice).map_err(|_| err_type_name())?;
            // Same recognition order as `ur_decode::decode` (which this wraps),
            // with the type name extracted for the caller.
            let rest = ustr.strip_prefix("ur:").ok_or_else(err_type_name)?;
            let (type_name, body) = rest.split_once('/').ok_or_else(err_type_name)?;
            if type_name.is_empty()
                || !type_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
                || body.contains('/')
            {
                return Err(err_type_name());
            }
            if type_name.len() + 1 > type_buf_len as usize {
                return Err(err(ShlosiloErrorKind::BufferTooSmall));
            }
            let decoded = crate::ur::ur_decode::decode(ustr)?;
            let bytes = decoded.as_ref();
            if bytes.len() > payload_len as usize {
                write_actual_len(actual_len, bytes.len()); // required value for the retry
                return Err(err(ShlosiloErrorKind::BufferTooSmall));
            }
            unsafe {
                core::ptr::copy_nonoverlapping(type_name.as_ptr(), type_buf, type_name.len());
                *type_buf.add(type_name.len()) = 0;
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), payload, bytes.len());
            }
            Ok(bytes.len())
        });
        match result {
            Ok(Ok(n)) => {
                write_actual_len(actual_len, n);
                OK
            }
            Ok(Err(e)) => to_ffi_code(&e),
            Err(_) => ERR_PANIC,
        }
    }

    /// R3/P0-C (2026-09-01): typed sign — vertical pass-through signing of the (type, payload) reassembled from multipart.
    /// type_name must be a known signable UrTypeTag (Unknown/arbitrary strings are rejected);
    /// payload budget = MULTIPART_PAYLOAD_MAX_LEN (16 KiB, aligned with the multipart reassembly cap).
    ///
    /// **Deprecated (Task 3, 2026-10-07)** — kept for one deprecation cycle for
    /// existing C callers; new integrations use [`shlosilo_sign_session_ffi`]
    /// (seed-less `KeySession` handle). Behavior is byte-for-byte unchanged:
    /// the body now delegates to the shared sign core (`sign_typed_core`) that
    /// the session entry also uses.
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_sign_typed_ffi(
        type_name: *const c_char,
        payload: *const u8,
        payload_len: c_uint,
        mnemonic_indices: *const u16,
        mnemonic_count: c_int,
        passphrase: *const u8,
        passphrase_len: c_uint,
        network: c_uint,
        entropy_ptr: *const u8,
        entropy_len: c_uint,
        output_buf: *mut u8,
        output_buf_len: c_uint,
        actual_len: *mut c_uint,
        ws: *mut u8,
        ws_len: c_uint,
    ) -> c_int {
        write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front
                                         // Z3.3b workspace contract (2026-09-25, Kosmo): ws == NULL is a PURE PROBE —
                                         // reports the workspace requirement and returns before input parsing, key
                                         // derivation, or any RNG use; no output side effects (output_buf untouched).
        if ws.is_null() {
            write_actual_len(actual_len, shlosilo_sign_ws_len() as usize);
            return OK;
        }
        // Capacity is validated BEFORE execution; under-capacity reports the
        // required length through actual_len (documented exception to the
        // zero-on-failure rule — the caller needs the number to resize).
        let ws_need = shlosilo_sign_ws_len() as usize;
        if (ws_len as usize) < ws_need {
            write_actual_len(actual_len, ws_need);
            return to_ffi_code(&ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(ws_need),
            ));
        }

        if type_name.is_null()
            || payload.is_null()
            || mnemonic_indices.is_null()
            || output_buf.is_null()
        {
            return ERR_NULL_POINTER;
        }
        // P0-02 #1: count domain validation precedes any unsafe construction(same prologue discipline as the main sign family)
        let word_count =
            match mnemonic_count_usize(mnemonic_count).and_then(WordCount::try_from_count) {
                Some(wc) => wc,
                None => return ShlosiloErrorCode::InvalidMnemonic as c_int,
            };
        let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
            // Task 3 (2026-10-07): the deprecated entry delegates to the shared
            // sign core — the same core `shlosilo_sign_session_ffi` uses (one
            // signing implementation, no duplicated logic). `Legacy` keeps this
            // entry's historical validation order and error codes verbatim.
            sign_typed_core(
                SignKeySource::Legacy {
                    mnemonic_indices,
                    word_count,
                    passphrase,
                    passphrase_len,
                    network,
                },
                type_name,
                payload,
                payload_len,
                &[], // no pairing retention on the legacy fixture path
                entropy_ptr,
                entropy_len,
                output_buf,
                output_buf_len,
                ws,
                ws_need,
            )
        });
        finish_sign_ffi(result, actual_len)
    }

    /// Task 3: key face for the shared sign core (internal; not on the C-ABI surface).
    #[derive(Clone, Copy)]
    enum SignKeySource {
        /// A flux-constructed `KeySession` (the FFI side only holds the raw
        /// pointer). Signing borrows the session's stored BIP-39 seed — no
        /// seed/mnemonic parameter exists on the session entry (v2 §4.1).
        Session(*const KeySession),
        /// The deprecated typed entry's key face: indices + passphrase +
        /// network, reassembled per call (the old zero-storage flow).
        Legacy {
            mnemonic_indices: *const u16,
            word_count: WordCount,
            passphrase: *const u8,
            passphrase_len: c_uint,
            network: c_uint,
        },
    }

    /// Task 3: shared result mapping for the sign family (Gate4 out-param
    /// discipline: length on success, zeroed on every failure path).
    fn finish_sign_ffi<E>(
        result: Result<Result<usize, ShlosiloError>, E>,
        actual_len: *mut c_uint,
    ) -> c_int {
        match result {
            Ok(Ok(length)) => {
                write_actual_len(actual_len, length);
                OK
            }
            Ok(Err(e)) => {
                write_actual_len(actual_len, 0);
                to_ffi_code(&e)
            }
            Err(_) => {
                write_actual_len(actual_len, 0);
                ERR_PANIC
            }
        }
    }

    /// Task 3: the shared sign core — ONE signing implementation for
    /// `shlosilo_sign_session_ffi` and the deprecated `shlosilo_sign_typed_ffi`.
    ///
    /// The step order below is the typed entry's historical validation order,
    /// preserved verbatim (`SignKeySource::Legacy` runs the same steps at the
    /// same positions), so the deprecated entry's error precedence cannot move.
    /// The session face skips the legacy-only steps (5, 7-10): its key material
    /// is the session's stored seed, and the frozen session signature carries
    /// no network parameter (chain/network gating for the session path is the
    /// caller's policy, upstream of this entry).
    #[allow(clippy::too_many_arguments)] // mirrors the frozen C-ABI face 1:1 (the entries' param lists are fixed by contract)
    fn sign_typed_core(
        source: SignKeySource,
        type_name: *const c_char,
        payload: *const u8,
        payload_len: c_uint,
        ki_records: &[crate::business::sign::WalletKiRecord],
        entropy_ptr: *const u8,
        entropy_len: c_uint,
        output_buf: *mut u8,
        output_buf_len: c_uint,
        ws: *mut u8,
        ws_need: usize,
    ) -> Result<usize, ShlosiloError> {
        // (1) C string → &str (≤ 64 chars is enough for a type name)
        let mut tlen = 0usize;
        unsafe {
            while *type_name.add(tlen) != 0 {
                tlen += 1;
                if tlen > 64 {
                    return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
                }
            }
        }
        let t_slice =
            checked_slice(type_name.cast::<u8>(), tlen, 64, false).ok_or_else(err_type_name)?;
        let t_str = core::str::from_utf8(t_slice)
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        let tag = crate::ur::ur_encode::UrTypeTag::from_name(t_str);
        if matches!(tag, crate::ur::ur_encode::UrTypeTag::Unknown) {
            return Err(err(ShlosiloErrorKind::UrPayloadUnknownType));
        }
        // (2) payload budget, (3) payload slice
        if payload_len as usize > crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN {
            return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
        }
        let payload_slice = checked_slice(
            payload,
            payload_len as usize,
            crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN,
            false,
        )
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::UrPayloadTooLarge))?;
        // (4) P0-02 #2: (NULL, len>0) rejected
        let entropy_slice = optional_bytes_in(
            entropy_ptr,
            entropy_len as usize,
            crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN,
        )
        .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
        // (5, legacy only) mnemonic slice — kept BEFORE the output slice:
        // the deprecated entry's historical error precedence.
        let mnem_slice: Option<&[u16]> = match source {
            SignKeySource::Legacy {
                mnemonic_indices,
                word_count,
                ..
            } => Some(
                checked_slice(mnemonic_indices, word_count as usize, 24, false)
                    .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?,
            ),
            SignKeySource::Session(_) => None,
        };
        // SAFETY: output_buf is non-null (excluded in the entry prologue)
        // (6) P0-03: output buffer goes through checked_slice_mut
        let out_slice =
            checked_slice_mut(output_buf, output_buf_len as usize, SIGN_OUTPUT_BUF_MAX_LEN)
                .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
        // (7-10) key face → SignInput (+ the legacy network gate)
        let (sign_input, network): (business::sign::SignInput<'_>, Option<Network>) = match source {
            SignKeySource::Session(session) => {
                // SAFETY: the entry prologue excluded the null pointer; handle
                // validity is the caller's single-owner contract (same as the
                // R3 encode/decode handles).
                let session = unsafe { &*session };
                (
                    business::sign::SignInput::Seed {
                        seed: session.seed().expose(),
                    },
                    None,
                )
            }
            SignKeySource::Legacy {
                word_count,
                passphrase,
                passphrase_len,
                network,
                ..
            } => {
                // SAFETY: mnemonic_count has passed the whitelist, null pointer already excluded
                let mnem_slice =
                    mnem_slice.ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
                // (7) P0-02 #2: (NULL, len>0) rejected
                let pass_slice =
                    optional_bytes_in(passphrase, passphrase_len as usize, PASSPHRASE_MAX_LEN)
                        .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
                if pass_slice.len() > PASSPHRASE_MAX_LEN {
                    return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
                }
                // (8)
                let mnemonic = Mnemonic::from_indices(mnem_slice, word_count)
                    .map_err(|_| err(ShlosiloErrorKind::MnemonicInvalidWord))?;
                // (9) P0-02 #3: network narrowing wraparound replaced by full-value validation via u8::try_from
                let n8 = u8::try_from(network)
                    .map_err(|_| err(ShlosiloErrorKind::NetworkUnrecognized))?;
                let network_parsed = Network::try_from_u8(n8)
                    .ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;
                (
                    business::sign::SignInput::Mnemonic {
                        mnemonic,
                        passphrase: pass_slice,
                    },
                    Some(network_parsed),
                )
            }
        };
        // (10) network gate (legacy face only — see the doc note above)
        if let Some(network) = network {
            business::sign::check_network(tag, payload_slice, network)?;
        }
        // (11) workspace carve (Z3.3b: capacity validated in the entry prologue)
        let ws_slice = unsafe { core::slice::from_raw_parts_mut(ws, ws_need) };
        let mut ws = crate::business::sign::carve_sign_ws(ws_slice).ok_or_else(|| {
            ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(ws_need),
            )
        })?;
        // (12) sign — §B.5: entropy_slice feeds the XMR signing randomness stream
        business::sign::sign_with_entropy_ws(
            sign_input,
            tag,
            payload_slice,
            ki_records,
            entropy_slice,
            Some(&mut ws),
            out_slice,
        )
    }

    /// Task 3 (2026-10-07): session sign — the seed-less signing entry (v2 §4.1).
    ///
    /// Frozen signature (interface detail decides): the caller constructs a
    /// [`KeySession`] on the flux side and passes only the raw handle here —
    /// NO seed/mnemonic/passphrase parameter exists on this entry, so key
    /// material cannot cross the FFI boundary even by mistake.
    ///
    /// - `session`: flux-constructed `KeySession` handle (single-owner).
    ///   **Handle storage is the caller's** (R3/Z3.3c caller-workspace
    ///   contract): the session is constructed IN PLACE in caller memory —
    ///   Rust glue `ptr::write`s it into a static slot or caller workspace;
    ///   tests use `MaybeUninit` + `ptr::write` over a workspace buffer (never
    ///   `Box::into_raw`). Release with [`shlosilo_session_free_ffi`], which
    ///   drops the value in place and returns the storage to the caller.
    /// - **Lifetime rule**: the session must stay alive for the whole sign
    ///   call. While a sign is in flight on a handle, the caller must NOT free
    ///   it and must NOT use the same handle concurrently — including from
    ///   another thread or an interrupt (forgebox signs across interrupt
    ///   context). Free only after every sign call has returned.
    /// - `type_name` / `payload` / `payload_len`: the typed UR face — identical
    ///   budget + validation to the typed entry (payload ≤ 16 KiB)
    /// - `entropy_ptr` / `entropy_len`: §B.5 signing-randomness stream for the
    ///   XMR path (misuse guard unchanged; BTC/ETH ignore it)
    /// - `output_buf` / `output_buf_len` / `actual_len`: signature bytes out
    /// - `ws` / `ws_len`: caller workspace — `ws == NULL` is the PURE PROBE
    ///   (Z3.3b: reports the requirement, touches nothing else)
    ///
    /// Returns 0 = Ok (length in `actual_len`), negative = error code.
    /// The frozen signature carries no network parameter: chain/network gating
    /// is the caller's policy (the deprecated typed entry keeps its own).
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: the entry null-checks first, then from_raw_parts; the C side guarantees pointer validity or accepts the NULL error code
    pub extern "C" fn shlosilo_sign_session_ffi(
        session: *const KeySession, // flux-constructed; the FFI side only holds the pointer
        type_name: *const c_char,
        payload: *const u8,
        payload_len: c_uint,
        entropy_ptr: *const u8,
        entropy_len: c_uint,
        output_buf: *mut u8,
        output_buf_len: c_uint,
        actual_len: *mut c_uint,
        ws: *mut u8,
        ws_len: c_uint,
        // tx2 wire fix: the pairing-beat wallet key image retention
        // (repr(C) `WalletKiRecord` array), NULL/0 = none available. The sign
        // path fills the container's wallet-transfer-indexed `key_images` from
        // these; an uncovered position refuses the sign.
        ki_records: *const crate::business::sign::WalletKiRecord,
        ki_records_len: c_uint,
    ) -> c_int {
        write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front
                                         // Z3.3b workspace contract: ws == NULL is a PURE PROBE —
                                         // reports the workspace requirement and returns before any
                                         // key access, parsing, or RNG use; no output side effects.
        if ws.is_null() {
            write_actual_len(actual_len, shlosilo_sign_ws_len() as usize);
            return OK;
        }
        // Capacity is validated BEFORE execution; under-capacity reports the
        // required length through actual_len (documented exception to the
        // zero-on-failure rule — the caller needs the number to resize).
        let ws_need = shlosilo_sign_ws_len() as usize;
        if (ws_len as usize) < ws_need {
            write_actual_len(actual_len, ws_need);
            return to_ffi_code(&ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(ws_need),
            ));
        }
        // Gate4: required pointers rejected up front (same discipline as the
        // typed entry — the session handle takes the mnemonic_indices slot).
        if session.is_null() || type_name.is_null() || payload.is_null() || output_buf.is_null() {
            return ERR_NULL_POINTER;
        }
        let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
            // (13) wallet KI records: NULL/0 = no retention; a non-NULL
            // pointer with count 0 is likewise empty. Layout-compatible zero
            // copy (repr(C) WalletKiRecord); the sign path's span check bounds
            // what the records can cover (BufferTooSmall beyond ws.ki).
            if ki_records.is_null() && ki_records_len != 0 {
                return Err(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch));
            }
            let ki_slice: &[crate::business::sign::WalletKiRecord] = if ki_records.is_null() {
                &[]
            } else {
                // SAFETY: non-null (checked above) with the caller-supplied
                // count; the array is repr(C) WalletKiRecord (layout match).
                unsafe { core::slice::from_raw_parts(ki_records, ki_records_len as usize) }
            };
            sign_typed_core(
                SignKeySource::Session(session),
                type_name,
                payload,
                payload_len,
                ki_slice,
                entropy_ptr,
                entropy_len,
                output_buf,
                output_buf_len,
                ws,
                ws_need,
            )
        });
        finish_sign_ffi(result, actual_len)
    }

    /// Task 3 (2026-10-07): session reclaim — the handle lifecycle contract.
    ///
    /// `session` is a POINTER TO the caller's handle slot (C: `KeySession **`).
    /// **Handle storage is the caller's** (R3/Z3.3c caller-workspace contract):
    /// the session was constructed in place in caller memory (Rust glue
    /// `ptr::write` into a static slot / caller workspace; tests use
    /// `MaybeUninit` + `ptr::write` — never `Box::into_raw`), so this call
    /// drops the value IN PLACE (`core::ptr::drop_in_place`) and the storage
    /// returns to the caller — no allocator is involved anywhere in the handle
    /// lifecycle (Z6 zero-heap face).
    /// Contract:
    /// - success: the session is dropped in place — `KeySession: ZeroizeOnDrop`
    ///   wipes the seed/spend/view key bytes — and the caller's slot is set to
    ///   NULL;
    /// - a second free of the SAME slot sees the NULLed handle and returns
    ///   ERR_NULL_POINTER — the zeroizing drop runs exactly once, never UB;
    /// - a NULL slot pointer or a NULL handle is likewise ERR_NULL_POINTER.
    ///
    /// **Lifetime rule**: never call this while a sign call on the same handle
    /// is in flight (including from an interrupt or another thread) — the
    /// in-flight sign would read freed/zeroed key material. Free only after
    /// every sign call has returned.
    ///
    /// The slot is NULLed before the reclaim drop, so no exit path can leave
    /// the caller holding a stale handle.
    ///
    /// **Two-model boundary (Task 5a)**: this entry closes sessions from the
    /// CALLER-placement model only. A session obtained from the flux-side QR
    /// glue (`shlosilo_keysource_qr_open_ffi`, flux/keysource) is owned by its
    /// workspace slot through a live handle and MUST be closed by
    /// `shlosilo_keysource_qr_close_ffi` instead — freeing it here would drop
    /// the slot-owned session behind the handle's back and turn the glue's
    /// next close into a double drop.
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: null-checked first; single-owner handle (see below)
    pub extern "C" fn shlosilo_session_free_ffi(session: *mut *mut KeySession) -> c_int {
        if session.is_null() {
            return ERR_NULL_POINTER;
        }
        let handle = unsafe { *session };
        if handle.is_null() {
            return ERR_NULL_POINTER;
        }
        // SAFETY: single-owner handle contract (same as the R3 encoder/decoder
        // handles, Z3.3c caller-workspace): the handle points at a `KeySession`
        // the caller constructed in place in their own storage (static slot /
        // caller workspace; tests: MaybeUninit + ptr::write). This call drops
        // it IN PLACE — no `Box`, no allocator: the memory goes back to the
        // caller — and `KeySession`'s ZeroizeOnDrop wipes the seed/spend/view
        // key bytes on the way out. The slot is NULLed first, so a second call
        // (or re-entry) errors out instead of double-dropping.
        unsafe {
            *session = core::ptr::null_mut();
            core::ptr::drop_in_place(handle);
        }
        OK
    }

    /// Cake direct pairing (T6): the `xmr-output` receive leg — seed-less
    /// session entry, frozen signature shape mirroring [`shlosilo_sign_session_ffi`].
    ///
    /// Chain: decrypt the `Monero output export\x04` container → epee parse →
    /// pk1/pk2 ownership check → key image + signature per output → write the
    /// `Monero key image export\x03` container (`xmr-keyimage` UR payload) to
    /// `output_buf`. Encode it with `UrTypeTag::XmrKeyImage`.
    ///
    /// Contract (same discipline as the sign session entry):
    /// - `session`: flux-constructed `KeySession` handle (single-owner,
    ///   caller-workspace placement; see [`shlosilo_sign_session_ffi`]). Keys
    ///   are borrowed from the session's read port — **no seed or key parameter
    ///   exists on this entry**, so key material cannot cross the FFI boundary.
    ///   **Lifetime rule**: the session must stay alive for the whole call; no
    ///   concurrent free/use (including from interrupt context).
    /// - `payload` / `payload_len`: the `xmr-output` UR payload bytes (the
    ///   encrypted container as decoded from the UR), ≤ 16 KiB.
    /// - `entropy_ptr` / `entropy_len`: §B.5 signing-randomness stream for the
    ///   export envelope + key-image signatures — REQUIRED for the XMR pairing
    ///   path (< 16 B raises `EntropyInjectionInvalid` at the first RNG
    ///   derivation, same misuse guard as the XMR sign path).
    /// - `output_buf` / `output_buf_len` / `actual_len`: response container out.
    /// - `ws` / `ws_len`: caller workspace — the ws base address MUST be
    ///   **u128-aligned** (the carve places the CryptoNight scratch slot at
    ///   u128 alignment *relative to the base*; the CN core validates the
    ///   absolute address). `ws == NULL` is the PURE PROBE
    ///   (reports the workspace requirement in `actual_len`, touches nothing).
    ///
    /// Response wire: `magic ‖ nonce(8) ‖ ChaCha(u32le tag ‖ pk1 ‖ pk2 ‖
    /// count×96B records) ‖ sig(64)`; each record is `[32B image][64B sig]` —
    /// isomorphic to keystone `KeyImages::to_bytes` (the Cake pairing link's
    /// wire), NOT the boost-archive `wallet2::export_key_images_str` blob.
    ///
    /// Returns 0 = Ok (length in `actual_len`), negative = error code.
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // contract: the entry null-checks first, then from_raw_parts; the C side guarantees pointer validity or accepts the NULL error code
    pub extern "C" fn shlosilo_xmr_pairing_ffi(
        session: *const KeySession, // flux-constructed; the FFI side only holds the pointer
        payload: *const u8,
        payload_len: c_uint,
        entropy_ptr: *const u8,
        entropy_len: c_uint,
        output_buf: *mut u8,
        output_buf_len: c_uint,
        actual_len: *mut c_uint,
        ws: *mut u8,
        ws_len: c_uint,
        // tx2 wire fix: wallet key image retention out (repr(C)
        // `WalletKiRecord` array). NULL = no retention requested;
        // `ki_records_actual` (nullable) reports the record count the export
        // produced either way. Entry `i` is the TRUE key image of wallet
        // transfer `export offset + i` — the flow retains these for the sign
        // leg's wallet-transfer-indexed `key_images` fill.
        ki_records_out: *mut crate::business::sign::WalletKiRecord,
        ki_records_cap: c_uint,
        ki_records_actual: *mut c_uint,
    ) -> c_int {
        write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front
        let ws_need = crate::business::xmr_pairing::pairing_ws_len();
        // Z3.3b workspace contract: ws == NULL is a PURE PROBE — reports the
        // workspace requirement and returns before any key access or parsing.
        if ws.is_null() {
            write_actual_len(actual_len, ws_need);
            return OK;
        }
        // Capacity validated BEFORE execution; under-capacity reports the
        // required length through actual_len (documented exception to the
        // zero-on-failure rule).
        if (ws_len as usize) < ws_need {
            write_actual_len(actual_len, ws_need);
            return to_ffi_code(&ShlosiloError::with_context(
                ShlosiloErrorKind::BufferTooSmall,
                crate::error::ErrorContext::RequiredLength(ws_need),
            ));
        }
        if session.is_null() || payload.is_null() || output_buf.is_null() {
            return ERR_NULL_POINTER;
        }
        let result = ffi_catch_unwind!(|| -> Result<usize, ShlosiloError> {
            // (1) payload budget + slice (the xmr-output UR payload = container bytes)
            if payload_len as usize > crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN {
                return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
            }
            let payload_slice = checked_slice(
                payload,
                payload_len as usize,
                crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN,
                false,
            )
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::UrPayloadTooLarge))?;
            // (2) entropy (§B.5): the export randomness stream. (NULL,0) is
            // accepted here and rejected by the misuse guard below — same
            // behavior as the XMR sign path.
            let entropy_slice = optional_bytes_in(
                entropy_ptr,
                entropy_len as usize,
                crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN,
            )
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
            // (3) output buffer through the checked constructor
            let out_slice =
                checked_slice_mut(output_buf, output_buf_len as usize, SIGN_OUTPUT_BUF_MAX_LEN)
                    .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
            // SAFETY: ws is non-null (the probe returned above) and ws_len >=
            // ws_need (checked above) — the carve validates the exact size.
            let ws_slice = unsafe { core::slice::from_raw_parts_mut(ws, ws_need) };
            let mut pws =
                crate::business::xmr_pairing::carve_pairing_ws(ws_slice).ok_or_else(|| {
                    ShlosiloError::with_context(
                        ShlosiloErrorKind::BufferTooSmall,
                        crate::error::ErrorContext::RequiredLength(ws_need),
                    )
                })?;
            // (4) per-export RNG context: Keccak(EXPORT_CTX_DOMAIN ‖ request
            // container) — Z2.4d-3 derivation, bound to this exact request.
            let ctx = {
                use crate::types::push::Sink as _;
                let mut h = crate::encoding::keccak256::KeccakSink::new();
                h.put(crate::chain::xmr::signing_rng::EXPORT_CTX_DOMAIN)?;
                h.put(payload_slice)?;
                h.finalize()
            };
            let mut rng = crate::chain::xmr::signing_rng::export_encrypt_rng(entropy_slice, &ctx)?;
            // (5) key source: the KeySession read port — plaintext key bytes
            // never cross the boundary (v2 §4.1).
            // SAFETY: the entry prologue excluded the null pointer; handle
            // validity is the caller's single-owner contract (as above).
            let session_ref = unsafe { &*session };
            if ki_records_out.is_null() && ki_records_cap != 0 {
                return Err(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch));
            }
            let ki_slice: &mut [crate::business::sign::WalletKiRecord] = if ki_records_out.is_null()
            {
                &mut []
            } else {
                // SAFETY: non-null (checked above) with the caller-supplied
                // capacity; the array is repr(C) WalletKiRecord (layout match).
                unsafe { core::slice::from_raw_parts_mut(ki_records_out, ki_records_cap as usize) }
            };
            let mut ki_written = 0usize;
            let outcome = crate::business::xmr_pairing::process_output_export_session(
                session_ref,
                payload_slice,
                &mut pws,
                out_slice,
                &mut rng,
                ki_slice,
                &mut ki_written,
            )?;
            write_actual_len(ki_records_actual, outcome.output_count);
            Ok(outcome.written)
        });
        finish_sign_ffi(result, actual_len)
    }

    /// R3: release the decoder handle. Null-safe (idempotent).
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // P0-02: visible to clippy once mod r3 becomes pub; free contract: single-owner
    pub extern "C" fn shlosilo_ur_decode_free(handle: *mut UrMultipartDecoder<'static>) {
        // Z3.3c: caller-workspace handle — free drops the value in place (the
        // pools and handle memory return to the caller). Single-owner contract.
        // v1 contract 5: sensitive spans (decoded parts, buffers, received
        // bitsets, frame scratch) are zeroed before the drop.
        if !handle.is_null() {
            unsafe {
                crate::ur::ur_multipart::ur_decode_ws_zeroize((*handle).ws_base as *mut u8);
                core::ptr::drop_in_place(handle);
            }
        }
    }

    #[cfg(test)]
    mod r3_tests {
        use super::*;
        use alloc::string::String;
        use alloc::vec::Vec;

        /// R3 FFI end-to-end: encode_begin → next ×N → decode_new → feed → payload matches
        #[test]
        fn ffi_multipart_roundtrip() {
            let payload: alloc::vec::Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
            let tname = c"xmr-txunsigned".as_ptr();

            let mut enc_ws = alloc::vec![0u8; shlosilo_ur_encode_ws_len() as usize];
            let enc = shlosilo_ur_encode_begin(
                tname,
                payload.as_ptr(),
                payload.len() as c_uint,
                200,
                enc_ws.as_mut_ptr(),
                shlosilo_ur_encode_ws_len(),
            );
            assert!(!enc.is_null());

            let mut frame_buf = [0u8; FRAME_BUF_MAX_LEN];
            let mut actual: c_uint = 0;
            let mut frames: Vec<String> = Vec::new();
            loop {
                let rc = shlosilo_ur_encode_next(
                    enc,
                    frame_buf.as_mut_ptr(),
                    frame_buf.len() as c_uint,
                    &mut actual,
                );
                assert_eq!(rc, OK, "rc={rc}");
                let f = core::str::from_utf8(&frame_buf[..actual as usize]).unwrap();
                let done = f.contains("/11-"); // 1024/200 → 6 fragments; guard below
                frames.push(String::from(f));
                if frames.len() >= 6 {
                    break;
                }
                let _ = done;
            }
            // fragment count = div_ceil(1024,200)=6, fragment_len=171 (fragment_length formula)
            assert_eq!(frames.len(), 6);
            assert!(frames[0].starts_with("ur:xmr-txunsigned/1-6/"));

            let mut dec_ws = alloc::vec![0u8; shlosilo_ur_decode_ws_len() as usize];
            let dec = shlosilo_ur_decode_new(dec_ws.as_mut_ptr(), shlosilo_ur_decode_ws_len());
            assert!(!dec.is_null());
            for f in &frames {
                let cf = alloc::ffi::CString::new(f.as_str()).unwrap();
                let mut accepted: c_uint = 0;
                let rc = shlosilo_ur_decode_feed(dec, cf.as_ptr(), &mut accepted);
                assert_eq!(rc, OK);
            }
            assert_eq!(shlosilo_ur_decode_complete(dec), 1);

            let mut out = [0u8; 2048];
            let rc =
                shlosilo_ur_decode_payload(dec, out.as_mut_ptr(), out.len() as c_uint, &mut actual);
            assert_eq!(rc, OK);
            assert_eq!(actual as usize, payload.len());
            assert_eq!(&out[..payload.len()], &payload[..]);

            // cyclic frame: seq wraps back to 1
            let rc = shlosilo_ur_encode_next_cyclic(
                enc,
                frame_buf.as_mut_ptr(),
                frame_buf.len() as c_uint,
                &mut actual,
            );
            assert_eq!(rc, OK);
            let f = core::str::from_utf8(&frame_buf[..actual as usize]).unwrap();
            assert!(f.starts_with("ur:xmr-txunsigned/1-6/"), "cyclic={f}");

            shlosilo_ur_encode_free(enc);
            shlosilo_ur_decode_free(dec);
            // post-free double-free protection is guaranteed by the L3 contract (C side nulls it); the Rust side is null-safe
            shlosilo_ur_encode_free(core::ptr::null_mut());
            shlosilo_ur_decode_free(core::ptr::null_mut());
        }

        /// P0-C E2E (2026-09-01): multipart (real Sparrow signet PSBT ~12KB) → decode_type
        /// → shlosilo_sign_typed_ffi full chain. The peer emits the registry
        /// shape — message = CBOR bytes item wrapping the PSBT; since
        /// 2026-10-12 the decode exit strips the shell, so the delivered
        /// payload is the RAW PSBT (what sign_btc consumes either way).
        #[test]
        fn p0c_typed_sign_vertical_slice() {
            use alloc::ffi::CString;
            const PSBT: &[u8] = include_bytes!("../../tests/fixtures/sparrow_signet_12k.psbt");
            // The multipart encoder owns the CBOR shell (bytes-type UR
            // semantics) -- feed the RAW PSBT; the old manual pre-wrap would
            // double-shell the message (2026-10-12).
            let ur_payload = alloc::vec::Vec::from(PSBT);
            assert!(
                ur_payload.len() > 4096,
                "fixture must exceed single-frame legacy budget"
            );

            // mnemonic indices (same origin as p63: entropy f284fb... → 12 words)
            let ent: [u8; 16] = [
                0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2,
                0x29, 0x16,
            ];
            let mnem = crate::entropy::mnemonic::Mnemonic::from_entropy(&ent).unwrap();
            let idx: Vec<u16> = mnem.indices().to_vec();

            // multipart encode
            let tname = c"crypto-psbt".as_ptr();
            let mut enc_ws = alloc::vec![0u8; shlosilo_ur_encode_ws_len() as usize];
            let enc = shlosilo_ur_encode_begin(
                tname,
                ur_payload.as_ptr(),
                ur_payload.len() as c_uint,
                200,
                enc_ws.as_mut_ptr(),
                shlosilo_ur_encode_ws_len(),
            );
            assert!(!enc.is_null());
            let frag_count = ur_payload.len().div_ceil(200);
            let mut frame_buf = [0u8; FRAME_BUF_MAX_LEN];
            let mut flen: c_uint = 0;
            let mut dec_ws = alloc::vec![0u8; shlosilo_ur_decode_ws_len() as usize];
            let dec = shlosilo_ur_decode_new(dec_ws.as_mut_ptr(), shlosilo_ur_decode_ws_len());
            for _ in 0..frag_count {
                let rc = shlosilo_ur_encode_next(
                    enc,
                    frame_buf.as_mut_ptr(),
                    frame_buf.len() as c_uint,
                    &mut flen,
                );
                assert_eq!(rc, OK);
                let cf = CString::new(&frame_buf[..flen as usize]).unwrap();
                let mut accepted: c_uint = 0;
                let rc = shlosilo_ur_decode_feed(dec, cf.as_ptr(), &mut accepted);
                assert_eq!(rc, OK, "feed rc={rc}");
            }
            assert_eq!(shlosilo_ur_decode_complete(dec), 1);

            // type extraction
            let mut tbuf = [0u8; 64];
            let mut tlen: c_uint = 0;
            let rc =
                shlosilo_ur_decode_type(dec, tbuf.as_mut_ptr(), tbuf.len() as c_uint, &mut tlen);
            assert_eq!(rc, OK);
            assert_eq!(&tbuf[..tlen as usize - 1], b"crypto-psbt");

            // payload extraction — the reassembled message's byte-string shell
            // is stripped: the delivered bytes are the RAW PSBT
            let mut pbuf = [0u8; 16384];
            let mut plen: c_uint = 0;
            let rc =
                shlosilo_ur_decode_payload(dec, pbuf.as_mut_ptr(), pbuf.len() as c_uint, &mut plen);
            assert_eq!(rc, OK);
            assert_eq!(plen as usize, PSBT.len());
            assert_eq!(&pbuf[..plen as usize], PSBT);

            // typed sign: check_network requires BitcoinMainnet(u8=0) for crypto-psbt
            let tname_c = CString::new("crypto-psbt").unwrap();
            let mut out = [0u8; 16384 + 512];
            let mut olen: c_uint = 0;
            let mut ws_buf = alloc::vec![0u8; shlosilo_sign_ws_len() as usize];
            let rc = shlosilo_sign_typed_ffi(
                tname_c.as_ptr(),
                pbuf.as_ptr(),
                plen,
                idx.as_ptr(),
                idx.len() as c_int,
                core::ptr::null(), // passphrase
                0,
                0, // network: mainnet (PSBT fixture is signet — does check_network require mainnet for crypto-psbt?)
                core::ptr::null(),
                0, // entropy
                out.as_mut_ptr(),
                out.len() as c_uint,
                &mut olen,
                ws_buf.as_mut_ptr(),
                shlosilo_sign_ws_len(),
            );
            assert_eq!(rc, OK, "typed sign rc={rc}");
            assert!(
                olen as usize > PSBT.len(),
                "signed output larger than unsigned"
            );
            shlosilo_ur_encode_free(enc);
            shlosilo_ur_decode_free(dec);
        }

        /// P0-C: type buffer too small → BufferTooSmall with the required value
        #[test]
        fn p0c_type_buffer_too_small() {
            use alloc::ffi::CString;
            let payload = [7u8; 8];
            let mut enc_ws = alloc::vec![0u8; shlosilo_ur_encode_ws_len() as usize];
            let mut dec_ws = alloc::vec![0u8; shlosilo_ur_decode_ws_len() as usize];
            let enc = shlosilo_ur_encode_begin(
                c"crypto-psbt".as_ptr(),
                payload.as_ptr(),
                8,
                8,
                enc_ws.as_mut_ptr(),
                shlosilo_ur_encode_ws_len(),
            );
            let dec = shlosilo_ur_decode_new(dec_ws.as_mut_ptr(), shlosilo_ur_decode_ws_len());
            let mut frame_buf = [0u8; FRAME_BUF_MAX_LEN];
            let mut flen: c_uint = 0;
            let rc = shlosilo_ur_encode_next(
                enc,
                frame_buf.as_mut_ptr(),
                frame_buf.len() as c_uint,
                &mut flen,
            );
            assert_eq!(rc, OK);
            let cf = CString::new(&frame_buf[..flen as usize]).unwrap();
            let rc = shlosilo_ur_decode_feed(dec, cf.as_ptr(), core::ptr::null_mut());
            assert_eq!(rc, OK);

            let mut tbuf = [0u8; 4];
            let mut tlen: c_uint = 0;
            let rc =
                shlosilo_ur_decode_type(dec, tbuf.as_mut_ptr(), tbuf.len() as c_uint, &mut tlen);
            assert_eq!(rc, to_ffi_code(&err(ShlosiloErrorKind::BufferTooSmall)));
            assert!(tlen as usize > "crypto-psbt".len());
            shlosilo_ur_encode_free(enc);
            shlosilo_ur_decode_free(dec);
        }
        /// Z3.3c contract: free() drops the handle IN PLACE — the caller's
        /// workspace is reusable immediately (no deallocation involved).
        #[test]
        fn ffi_handle_ws_reusable_after_free() {
            let mut dec_ws = alloc::vec![0u8; shlosilo_ur_decode_ws_len() as usize];
            let d1 = shlosilo_ur_decode_new(dec_ws.as_mut_ptr(), shlosilo_ur_decode_ws_len());
            assert!(!d1.is_null());
            shlosilo_ur_decode_free(d1);
            // same workspace, second life
            let d2 = shlosilo_ur_decode_new(dec_ws.as_mut_ptr(), shlosilo_ur_decode_ws_len());
            assert!(!d2.is_null(), "workspace must be reusable after free");
            shlosilo_ur_decode_free(d2);
            // under-capacity: the whole-shape failure contract
            let tiny = shlosilo_ur_decode_ws_len() as usize - 1;
            let mut small = alloc::vec![0u8; tiny];
            assert!(shlosilo_ur_decode_new(small.as_mut_ptr(), tiny as c_uint).is_null());
        }

        /// null handle/pointer guards
        #[test]
        fn ffi_multipart_null_guards() {
            let mut enc_ws = alloc::vec![0u8; shlosilo_ur_encode_ws_len() as usize];
            let mut dec_ws = alloc::vec![0u8; shlosilo_ur_decode_ws_len() as usize];
            assert!(shlosilo_ur_encode_begin(
                core::ptr::null(),
                core::ptr::null(),
                0,
                200,
                enc_ws.as_mut_ptr(),
                shlosilo_ur_encode_ws_len(),
            )
            .is_null());
            assert!(
                !shlosilo_ur_decode_new(dec_ws.as_mut_ptr(), shlosilo_ur_decode_ws_len()).is_null()
            );
            let dec = shlosilo_ur_decode_new(dec_ws.as_mut_ptr(), shlosilo_ur_decode_ws_len());
            assert_eq!(
                shlosilo_ur_decode_feed(
                    core::ptr::null_mut(),
                    c"x".as_ptr(),
                    core::ptr::null_mut()
                ),
                ERR_NULL_POINTER
            );
            assert_eq!(
                shlosilo_ur_decode_progress(core::ptr::null_mut()),
                ERR_NULL_POINTER
            );
            assert_eq!(shlosilo_ur_decode_complete(dec), 0);
            shlosilo_ur_decode_free(dec);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Z5.2b: C-side decompressed generator table storage provisioning.
//
// Four ABI invariants (each pinned by a dedicated regression test in
// tests/ffi_gencache_provide.rs):
//
// INV-1 (pure probe): `shlosilo_gencache_table_sizes` has no side effects —
//       no RNG consumption, no secret derivation, no state change, repeatable;
//       its values come from the SAME source of truth the fill actually uses.
// INV-2 (capacity): any insufficiency fails BEFORE the first write/build and
//       reports the required lengths through the size out-params.
// INV-3 (topology): partial-NULL, misaligned, or overlapping buffers are
//       explicitly rejected (ERR_NULL_POINTER = invalid argument); the
//       used regions (first `required` bytes of each buffer) must be
//       pairwise disjoint.
// INV-4 (atomicity): a successful provide atomically moves the slot to
//       CONSUMED (terminal; later provides fail with ERR_SLOT_CONSUMED);
//       any failure leaves the state unchanged and the caller may retry
//       with corrected buffers.
//
// Buffer contract: `g`/`h` hold `ED25519` generator points of
// SHLOSILO_GENPOINT_SIZE bytes each (8-aligned); `blob` is the raw-blob
// scratch. Over-capacity is accepted (only the required prefix is used).
// The buffers must outlive every generator use — they are written ONCE at
// first generator use and read thereafter; free/unmap them only at
// end-of-life. Sizes: capacity in, required length out on ERR_BUFFER_TOO_SMALL.
// ─────────────────────────────────────────────────────────────────────────────

/// Curve25519-EdwardsPoint repr pin: the C buffer element size must track the
/// vendored dalek representation exactly (build breaks on divergence). The
/// C-side alignment contract is a UNIFORM 8 bytes on every target — stricter
/// than some targets need (thumbv7em's natural u64 alignment is 4, caught by
/// this pin when it asserted `== 8`), which keeps the ABI stable while the
/// in-Rust requirement (`align_of`) stays a subset of it.
const _: () = assert!(
    core::mem::size_of::<curve25519_dalek::EdwardsPoint>()
        == crate::types::caps::SHLOSILO_GENPOINT_SIZE
);
const _: () = assert!(core::mem::align_of::<curve25519_dalek::EdwardsPoint>() <= 8);

fn genset_from_c(set: i32) -> Option<monero_bulletproofs::GeneratorSet> {
    match set {
        0 => Some(monero_bulletproofs::GeneratorSet::Bulletproof),
        1 => Some(monero_bulletproofs::GeneratorSet::BulletproofPlus),
        _ => None,
    }
}

/// INV-1: pure probe — reports the required buffer sizes for a generator set.
/// No side effects: does not touch the registry slot, consumes no RNG, derives
/// no secrets. Values == what `shlosilo_gencache_provide_table` requires.
///
/// # Safety
/// All three out-pointers must be valid for writes of `u32` and non-aliased.
#[no_mangle]
pub unsafe extern "C" fn shlosilo_gencache_table_sizes(
    set: i32,
    g_bytes: *mut u32,
    h_bytes: *mut u32,
    blob_bytes: *mut u32,
) -> i32 {
    if g_bytes.is_null() || h_bytes.is_null() || blob_bytes.is_null() {
        return ERR_NULL_POINTER;
    }
    let Some(set) = genset_from_c(set) else {
        return ERR_NULL_POINTER;
    };
    let (g, h, b) = monero_bulletproofs::generator_table_sizes(set);
    *g_bytes = g as u32;
    *h_bytes = h as u32;
    *blob_bytes = b as u32;
    OK
}

/// INV-2/3/4: provide the decompressed-table storage for one generator set.
/// All validation happens before any state change or write; success commits
/// the slot atomically (CONSUMED); failure leaves state unchanged (retry OK).
///
/// # Safety
/// `g`/`h` must be 8-aligned and point to at least `*g_bytes`/`*h_bytes`
/// writable bytes; `blob` to at least `*blob_bytes`. The used regions must be
/// pairwise disjoint (enforced). The buffers must outlive every generator
/// use — they are written ONCE at first generator use and read thereafter.
/// Size out-pointers must be valid for read/write and non-aliased.
#[no_mangle]
pub unsafe extern "C" fn shlosilo_gencache_provide_table(
    set: i32,
    g: *mut u8,
    g_bytes: *mut u32,
    h: *mut u8,
    h_bytes: *mut u32,
    blob: *mut u8,
    blob_bytes: *mut u32,
) -> i32 {
    // INV-3: partial-NULL topology (buffers AND size out-params) = invalid.
    if g.is_null()
        || h.is_null()
        || blob.is_null()
        || g_bytes.is_null()
        || h_bytes.is_null()
        || blob_bytes.is_null()
    {
        return ERR_NULL_POINTER;
    }
    let Some(set) = genset_from_c(set) else {
        return ERR_NULL_POINTER;
    };
    let (req_g, req_h, req_b) = monero_bulletproofs::generator_table_sizes(set);

    // INV-2: capacity checked before anything else; required reported on fail.
    let (cap_g, cap_h, cap_b) = (*g_bytes, *h_bytes, *blob_bytes);
    if cap_g < req_g as u32 || cap_h < req_h as u32 || cap_b < req_b as u32 {
        *g_bytes = req_g as u32;
        *h_bytes = req_h as u32;
        *blob_bytes = req_b as u32;
        return ERR_BUFFER_TOO_SMALL;
    }

    // INV-3: alignment of the point tables.
    let align = core::mem::align_of::<curve25519_dalek::EdwardsPoint>();
    if !(g as usize).is_multiple_of(align) || !(h as usize).is_multiple_of(align) {
        return ERR_NULL_POINTER;
    }
    // INV-3: pairwise-disjoint used regions (first `required` bytes each).
    let regions = [
        (g as usize, req_g),
        (h as usize, req_h),
        (blob as usize, req_b),
    ];
    for i in 0..regions.len() {
        for j in (i + 1)..regions.len() {
            let (a, al) = regions[i];
            let (b, bl) = regions[j];
            if a < b.saturating_add(bl) && b < a.saturating_add(al) {
                return ERR_NULL_POINTER;
            }
        }
    }

    // Build the slices only after every check passed (INV-2: no write/build on
    // failure paths). Caller contract: buffers outlive every generator use.
    let pts_g = req_g / core::mem::size_of::<curve25519_dalek::EdwardsPoint>();
    let pts_h = req_h / core::mem::size_of::<curve25519_dalek::EdwardsPoint>();
    let g_slice: &'static mut [curve25519_dalek::EdwardsPoint] =
        core::slice::from_raw_parts_mut(g as *mut curve25519_dalek::EdwardsPoint, pts_g);
    let h_slice: &'static mut [curve25519_dalek::EdwardsPoint] =
        core::slice::from_raw_parts_mut(h as *mut curve25519_dalek::EdwardsPoint, pts_h);
    let blob_slice: &'static mut [u8] = core::slice::from_raw_parts_mut(blob, req_b);

    // INV-4: the registry commit is atomic (validate-then-insert, one lock).
    let ok = monero_bulletproofs::provide_generator_table_storage(
        set,
        monero_bulletproofs::GeneratorTableStorage {
            g: g_slice,
            h: h_slice,
            blob: blob_slice,
        },
    );
    if !ok {
        // slot already provided/consumed (terminal)
        return crate::ffi::error_code::ERR_SLOT_CONSUMED;
    }
    OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::ptr::{null, null_mut};

    /// Z3.3b contract 1 (Kosmo 2026-09-25): ws == NULL is a PURE PROBE —
    /// reports the workspace requirement and nothing else. Garbage in every
    /// other parameter proves the probe precedes input validation, key
    /// derivation, and any RNG use; the 0xAA sentinel proves output_buf is
    /// untouched (no output side effects).
    #[test]
    fn ffi_ws_probe_is_pure() {
        let mut out = [0xAAu8; 64];
        let mut actual: c_uint = 0xDEAD_BEEF;
        let rc = shlosilo_sign_ffi(
            core::ptr::null(), // invalid: null mnemonic — must NOT be validated in probe mode
            999,               // invalid word count
            core::ptr::null(),
            0,
            core::ptr::null(),
            0,
            999_999, // invalid network
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
            core::ptr::null_mut(), // ws == NULL → probe
            0,
        );
        assert_eq!(
            rc, OK,
            "probe returns OK regardless of the other parameters"
        );
        assert_eq!(
            actual,
            shlosilo_sign_ws_len(),
            "probe reports the required length"
        );
        assert!(
            out.iter().all(|&b| b == 0xAA),
            "probe must not touch output_buf"
        );
    }

    /// Z3.3b contract 2: capacity is validated BEFORE execution; under-capacity
    /// reports the required length through actual_len and never runs the flow.
    #[test]
    fn ffi_ws_under_capacity_reports_required() {
        let idx: [u16; 12] = [0; 12];
        let mut out = [0xAAu8; 64];
        let mut actual: c_uint = 0xDEAD_BEEF;
        let need = shlosilo_sign_ws_len();
        let mut ws_buf = alloc::vec![0u8; need as usize - 1];
        let rc = shlosilo_sign_ffi(
            idx.as_ptr(),
            12,
            core::ptr::null(),
            0,
            b"x".as_ptr(),
            1,
            0,
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
            ws_buf.as_mut_ptr(),
            need - 1,
        );
        assert_ne!(rc, OK, "under-capacity must fail");
        assert_eq!(actual, need, "required length must be reported");
        assert!(
            out.iter().all(|&b| b == 0xAA),
            "under-capacity must not touch output_buf"
        );
    }

    /// Z3.3b contract 3: the carve's requirement and the query's report come
    /// from one layout source of truth — carve(total) must succeed with exactly
    /// the declared capacities, and carve(total-1) must fail as a whole (never
    /// a partial workspace).
    #[test]
    fn sign_ws_layout_consistency() {
        use crate::business::sign::{carve_sign_ws, SignWsLayout};
        use crate::types::caps as c;
        let l = SignWsLayout::compute();
        assert_eq!(
            l.total as c_uint,
            shlosilo_sign_ws_len(),
            "query == layout (contract 3)"
        );
        let mut buf = alloc::vec![0u8; l.total];
        let ws = carve_sign_ws(&mut buf).expect("carve at exactly total must succeed");
        assert_eq!(ws.plain.len(), c::SIGN_WS_PLAIN);
        assert_eq!(ws.txes.len(), c::SIGN_WS_TXES);
        assert_eq!(ws.sources.len(), c::SIGN_WS_SOURCES);
        assert_eq!(ws.splitted_dsts.len(), c::SIGN_WS_SPLITS);
        assert_eq!(ws.selected_transfers.len(), c::SIGN_WS_SEL);
        assert_eq!(ws.extra.len(), c::SIGN_WS_EXTRA);
        assert_eq!(ws.dests.len(), c::SIGN_WS_DESTS);
        assert_eq!(ws.subaddr_indices.len(), c::SIGN_WS_SUBIDX);
        assert_eq!(ws.ptx.len(), c::SIGN_WS_PTX);
        assert_eq!(ws.tx_bytes.len(), c::SIGN_WS_TX_BYTES);
        assert_eq!(ws.ki.len(), c::SIGN_WS_KI);
        assert_eq!(ws.tki.len(), c::SIGN_WS_TKI);
        assert_eq!(ws.sel.len(), c::SIGN_WS_SEL_OUT);
        assert_eq!(ws.kstr.len(), c::SIGN_WS_KSTR);
        assert_eq!(ws.record_dests.len(), c::SIGN_WS_RECORD_DESTS);
        let mut small = alloc::vec![0u8; l.total - 1];
        assert!(
            carve_sign_ws(&mut small).is_none(),
            "carve(total-1) must fail as a whole"
        );
    }

    /// End-to-end through the workspace path: the C entry with a carved ws must
    /// produce byte-identical output to the ws-less shell path (the carve is
    /// behavior-transparent).
    #[test]
    #[cfg(feature = "alloc-fallback")]
    fn ffi_ws_path_matches_shell_path() {
        const PSBT: &[u8] = include_bytes!("../../tests/fixtures/sparrow_signet_12k.psbt");
        // the sign payload is the CBOR bytes-item wrapping the PSBT (P1-01: the
        // payload is the complete CBOR) — same semantics as p0c_typed_sign.
        let payload = crate::encoding::cbor::encode_bytes(PSBT);
        // the fixture's BIP32 derivations pin the p63 mnemonic (entropy f284fb...)
        let ent: [u8; 16] = [
            0xf2, 0x84, 0xfb, 0x6c, 0xa9, 0xf4, 0xd5, 0x83, 0x54, 0x55, 0xbe, 0x65, 0xe4, 0xb2,
            0x29, 0x16,
        ];
        let mnem = crate::entropy::mnemonic::Mnemonic::from_entropy(&ent).unwrap();
        let idx: alloc::vec::Vec<u16> = mnem.indices().to_vec();
        // legacy entry over the PSBT fixture keeps this independent of UR framing
        let mut out_ws = [0u8; 16384 + 512];
        let mut out_shell = [0u8; 16384 + 512];
        let mut a1: c_uint = 0;
        let need = shlosilo_sign_ws_len();
        let mut ws_buf = alloc::vec![0u8; need as usize];
        let tname = c"crypto-psbt";
        let rc1 = super::r3::shlosilo_sign_typed_ffi(
            tname.as_ptr(),
            payload.as_ptr(),
            payload.len() as c_uint,
            idx.as_ptr(),
            idx.len() as c_int,
            core::ptr::null(),
            0,
            0,
            core::ptr::null(),
            0,
            out_ws.as_mut_ptr(),
            out_ws.len() as c_uint,
            &mut a1,
            ws_buf.as_mut_ptr(),
            need,
        );
        assert_eq!(rc1, OK, "ws path must sign OK (rc1={rc1})");
        // shell path: business::sign directly (the ws == None branch)
        let n2 = crate::business::sign::sign(
            crate::business::sign::SignInput::Mnemonic {
                mnemonic: mnem,
                passphrase: b"",
            },
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &payload,
            &mut out_shell,
        )
        .unwrap();
        assert_eq!(a1 as usize, n2);
        assert_eq!(
            &out_ws[..a1 as usize],
            &out_shell[..n2],
            "ws path == shell path"
        );
    }

    #[test]
    fn ffi_sign_signature_exists() {
        const _: extern "C" fn(
            *const u16,
            c_int,
            *const u8,
            c_uint,
            *const u8,
            c_uint,
            c_uint,
            *mut u8,
            c_uint,
            *mut c_uint,
            *mut u8,
            c_uint,
        ) -> c_int = shlosilo_sign_ffi;
    }

    /// T6 signature pin: the Cake pairing entry's frozen C shape.
    #[test]
    fn ffi_xmr_pairing_signature_exists() {
        const _: extern "C" fn(
            *const crate::types::key_session::KeySession,
            *const u8,
            c_uint,
            *const u8,
            c_uint,
            *mut u8,
            c_uint,
            *mut c_uint,
            *mut u8,
            c_uint,
            *mut crate::business::sign::WalletKiRecord,
            c_uint,
            *mut c_uint,
        ) -> c_int = r3::shlosilo_xmr_pairing_ffi;
    }

    /// T6 end-to-end through the frozen entry: session handle + valid request
    /// container → response container decrypts to exactly one key-image record
    /// whose image matches the independent recomputation.
    #[cfg(any(feature = "alloc-fallback", test))]
    #[test]
    fn ffi_xmr_pairing_e2e() {
        use crate::types::key_session::KeySession;
        let session = KeySession::from_entropy(&[0x11u8; 16], b"").unwrap();
        let keys = session.monero();
        let view_sk = *keys.view_sk.expose();
        let spend_sk = *keys.spend_sk.expose();
        let (req, out_pub) =
            crate::business::xmr_pairing::tests::make_request_pub(&view_sk, &spend_sk, 7);
        let entropy = [7u8; 32];
        let mut out = alloc::vec![0u8; 8192];
        let mut ws = alloc::vec![0u8; crate::business::xmr_pairing::pairing_ws_len()];

        // PURE PROBE: ws == NULL reports the workspace requirement.
        let mut actual: c_uint = 0;
        let rc = r3::shlosilo_xmr_pairing_ffi(
            &session,
            req.as_ptr(),
            req.len() as c_uint,
            entropy.as_ptr(),
            entropy.len() as c_uint,
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
        );
        assert_eq!(rc, OK);
        assert_eq!(
            actual as usize,
            crate::business::xmr_pairing::pairing_ws_len()
        );

        // Real call (with the tx2 wire-fix records retention).
        let mut retained = [crate::business::sign::WalletKiRecord {
            transfer_idx: 0xFFFF_FFFF,
            wallet_fp: [0u8; 8],
            key_image: [0u8; 32],
        }; 8];
        let mut retained_n: c_uint = 0;
        let rc = r3::shlosilo_xmr_pairing_ffi(
            &session,
            req.as_ptr(),
            req.len() as c_uint,
            entropy.as_ptr(),
            entropy.len() as c_uint,
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
            ws.as_mut_ptr(),
            ws.len() as c_uint,
            retained.as_mut_ptr(),
            retained.len() as c_uint,
            &mut retained_n,
        );
        assert_eq!(rc, OK, "pairing entry must succeed");
        assert_eq!(retained_n, 1, "one record retained for one output");
        let n = actual as usize;
        assert!(n > 0);

        // Hot-side read-back + independent key image recomputation.
        let (_, _, plain) = crate::chain::xmr::key_image_export::decrypt_export_payload(
            &out[..n],
            crate::chain::xmr::key_image_export::KEY_IMAGE_EXPORT_MAGIC,
            &view_sk,
        )
        .unwrap();
        let mut recs = [([0u8; 32], [0u8; 64]); 8];
        let cnt = crate::chain::xmr::output_export::deserialize_key_images_into(&plain, &mut recs)
            .unwrap();
        assert_eq!(cnt, 1);
        use curve25519_dalek::scalar::Scalar;
        use monero_ed25519::Point;
        let offset =
            crate::chain::xmr::subaddress::calc_output_key_offset(&view_sk, &[0x22u8; 32], 0, 0, 0)
                .unwrap();
        let input_sk =
            Scalar::from_bytes_mod_order(spend_sk) + Scalar::from_bytes_mod_order(offset);
        let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(out_pub).into();
        assert_eq!(recs[0].0, (hp * input_sk).compress().to_bytes());
        // retention cross-check: the record handed to the flow is the same
        // true key image the response carries
        assert_eq!(
            retained[0].key_image, recs[0].0,
            "retained KI == response KI"
        );

        // Entropy misuse guard: short entropy raises EntropyInjectionInvalid.
        let mut actual2: c_uint = 0;
        let rc = r3::shlosilo_xmr_pairing_ffi(
            &session,
            req.as_ptr(),
            req.len() as c_uint,
            entropy.as_ptr(),
            4,
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual2,
            ws.as_mut_ptr(),
            ws.len() as c_uint,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
        );
        assert_ne!(rc, OK, "short entropy must be rejected");
    }

    #[test]
    fn ffi_export_signature_exists() {
        // P1-04：seed → mnemonic indices + passphrase
        const _: extern "C" fn(
            *const u16,
            c_int,
            *const u8,
            c_uint,
            c_uint,
            *const u32,
            c_uint,
            c_uint,
            *mut u8,
            c_uint,
            *mut c_uint,
        ) -> c_int = shlosilo_export_readonly_ffi;
    }

    #[test]
    fn ffi_create_signature_exists() {
        // P1-04: seed_out parameter removed
        const _: extern "C" fn(
            c_uint,
            c_uint,
            *const u8,
            c_uint,
            *const u8,
            c_uint,
            *mut u8,
            c_uint,
        ) -> c_int = shlosilo_create_account_ffi;
    }

    /// Real call: create_account via FFI yields mnemonic + seed
    #[test]
    fn ffi_create_account_smoke() {
        let rolls: [u8; 64] = {
            let mut r = [0u8; 64];
            for (i, v) in r.iter_mut().enumerate() {
                *v = (i % 6) as u8 + 1;
            }
            r
        };
        let mut mnemonic_buf = [0u8; 24];
        let rc = shlosilo_create_account_ffi(
            12,
            6,
            rolls.as_ptr(),
            rolls.len() as c_uint,
            null(),
            0,
            mnemonic_buf.as_mut_ptr(),
            mnemonic_buf.len() as c_uint,
        );
        assert_eq!(rc, OK, "rc={rc}");
        // The first word index should be a valid BIP-39 index
        let first = u16::from_le_bytes([mnemonic_buf[0], mnemonic_buf[1]]);
        assert!(first < 2048);
    }

    /// Real call: export_readonly(CryptoHdKey) yields ur:crypto-hdkey/
    #[test]
    fn ffi_export_hdkey_smoke() {
        // P1-04: the entry takes a mnemonic (official vector abandon×11 + about); seed restored inside the library
        let idx: [u16; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        // m/44'/0'/0'/0/0 flat: hardened bit 0x80000000
        let elems: [u32; 5] = [44 | 0x8000_0000, 0x8000_0000, 0x8000_0000, 0, 0];
        let mut buf = [0u8; 1024];
        let mut actual: c_uint = 0;
        let rc = shlosilo_export_readonly_ffi(
            idx.as_ptr(),
            idx.len() as c_int,
            null(), // passphrase
            0,
            0, // BitcoinMainnet
            elems.as_ptr(),
            elems.len() as c_uint,
            0, // CryptoHdKey
            buf.as_mut_ptr(),
            buf.len() as c_uint,
            &mut actual,
        );
        assert_eq!(rc, OK, "rc={rc}");
        let uri = core::str::from_utf8(&buf[..actual as usize]).unwrap();
        assert!(uri.starts_with("ur:crypto-hdkey/"));
    }

    /// supported_networks / supported_protocols out-param
    #[test]
    fn ffi_supported_lists() {
        let mut net_buf = [0u8; 200];
        let mut n: c_uint = 0;
        let rc =
            shlosilo_supported_networks_ffi(net_buf.as_mut_ptr(), net_buf.len() as c_uint, &mut n);
        assert_eq!(rc, OK);
        // Gate4 #1: real matrix = BTC mainnet / ETH mainnet+sepolia+goerli / XMR mainnet
        assert_eq!(n, 5);
        assert_eq!(&net_buf[..5], &[0u8, 10, 11, 12, 90]);

        let mut proto_buf = [0u8; 16];
        let mut p: c_uint = 0;
        let rc = shlosilo_supported_protocols_ffi(
            proto_buf.as_mut_ptr(),
            proto_buf.len() as c_uint,
            &mut p,
        );
        assert_eq!(rc, OK);
        assert_eq!(p, 1); // CryptoHdKey only (all other export arms are Unimplemented)
        assert_eq!(proto_buf[0], 0);

        // BufferTooSmall must also hold: 2 slots cannot fit 5
        let mut tiny = [0u8; 2];
        let mut t: c_uint = 0;
        let rc = shlosilo_supported_networks_ffi(tiny.as_mut_ptr(), 2, &mut t);
        assert_eq!(rc, ERR_BUFFER_TOO_SMALL);
    }

    // -- P2-03: FFI entry resource caps --

    /// passphrase over cap (>256B) → EncodingInvalidFormat
    #[test]
    fn ffi_passphrase_over_limit_rejected() {
        // P1-04: restore_seed_ffi removed — the passphrase cap is now verified via export_readonly_ffi
        let idx: [u16; 12] = [0; 12];
        let long_pass = [0x41u8; 257]; // 257 > 256
        let elems: [u32; 1] = [44 | 0x8000_0000];
        let mut buf = [0u8; 64];
        let mut actual: c_uint = 0;
        let rc = shlosilo_export_readonly_ffi(
            idx.as_ptr(),
            idx.len() as c_int,
            long_pass.as_ptr(),
            long_pass.len() as c_uint,
            0, // network
            elems.as_ptr(),
            elems.len() as c_uint,
            0, // protocol
            buf.as_mut_ptr(),
            buf.len() as c_uint,
            &mut actual,
        );
        // Audit #5 P0-03: a 257B over-budget is rejected at the helper layer (before unsafe construction) → InvalidArgument(-2),
        // no longer a business-layer EncodingError(-21) — moving budget validation earlier is exactly the remediation goal
        assert_eq!(rc, crate::error::ShlosiloErrorCode::InvalidArgument as i32);
        // 256 = within the cap → passes the passphrase check (the BIP-39 checksum later rejects the all-zero word set; not EncodingInvalidFormat)
        let ok_pass = [0x41u8; 256];
        let rc = shlosilo_export_readonly_ffi(
            idx.as_ptr(),
            idx.len() as c_int,
            ok_pass.as_ptr(),
            ok_pass.len() as c_uint,
            0,
            elems.as_ptr(),
            elems.len() as c_uint,
            0,
            buf.as_mut_ptr(),
            buf.len() as c_uint,
            &mut actual,
        );
        // all-zero word set has an invalid checksum → MnemonicInvalidChecksum (P1-05 behavior, not a passphrase cap error)
        assert_eq!(
            rc,
            crate::error::ShlosiloErrorCode::InvalidMnemonic as i32,
            "256B passphrase passes the limit check, rc={rc}"
        );
    }

    /// dice rolls over cap (>1024) → DiceRollsInvalidCount
    #[test]
    fn ffi_rolls_over_limit_rejected() {
        let rolls = [1u8; 1025];
        let mut mnemonic_buf = [0u8; 24];
        let rc = shlosilo_create_account_ffi(
            12,
            6,
            rolls.as_ptr(),
            rolls.len() as c_uint,
            null(),
            0,
            mnemonic_buf.as_mut_ptr(),
            mnemonic_buf.len() as c_uint,
        );
        assert_eq!(rc, crate::error::ShlosiloErrorCode::InvalidDiceRolls as i32);
    }

    /// legacy sign_ffi payload over cap (>2048B) → EncodingInvalidFormat
    #[test]
    fn ffi_legacy_payload_over_limit_rejected() {
        let idx: [u16; 12] = [0; 12];
        let big_payload = [0u8; 2049];
        let mut out = [0u8; 4096];
        let mut actual: c_uint = 0;
        let mut ws_buf = alloc::vec![0u8; shlosilo_sign_ws_len() as usize];
        let rc = shlosilo_sign_ffi(
            idx.as_ptr(),
            12,
            null(),
            0,
            big_payload.as_ptr(),
            big_payload.len() as c_uint,
            0, // network
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
            ws_buf.as_mut_ptr(),
            shlosilo_sign_ws_len(),
        );
        assert_eq!(rc, crate::error::ShlosiloErrorCode::EncodingError as i32);
    }

    #[test]
    fn ffi_version_strings_not_null() {
        use super::super::version::*;
        assert!(!shlosilo_version().is_null());
        assert!(!shlosilo_cabi_version().is_null());
    }

    // -- P6.1d: shlosilo_sign_ur_ffi (takes the full UR string) --

    #[test]
    fn ffi_sign_ur_signature_exists() {
        const _: extern "C" fn(
            *const c_char, // uri (null-terminated)
            *const u16,
            c_int,
            *const u8,
            c_uint,
            c_uint,
            *const u8, // entropy_ptr (§B.5)
            c_uint,    // entropy_len
            *mut u8,
            c_uint,
            *mut c_uint,
            *mut u8,
            c_uint,
        ) -> c_int = shlosilo_sign_ur_ffi;
    }

    /// End-to-end: ETH raw tx → ur:eth-sign-request/... → FFI signature = direct sign
    #[test]
    fn ffi_sign_ur_eth_end_to_end() {
        use crate::chain::eth::{eip1559, rlp};

        let tx = eip1559::Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x22u8; 20]),
            amount: 999,
            data: Vec::new().into(),
        };
        let list = rlp::encode_list(&[
            rlp::encode_uint(tx.chain_id as u128),
            rlp::encode_uint(tx.nonce as u128),
            rlp::encode_uint(tx.max_priority_fee_per_gas),
            rlp::encode_uint(tx.max_fee_per_gas),
            rlp::encode_uint(tx.gas_limit as u128),
            rlp::encode_bytes(&tx.destination.unwrap()),
            rlp::encode_uint(tx.amount),
            rlp::encode_bytes(&tx.data),
            rlp::encode_list(&[]),
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
        ]);
        let mut raw = Vec::new();
        raw.push(0x02u8);
        raw.extend_from_slice(&list);

        // P1-01: payload = a real eth-sign-request CBOR map (ur-registry shape)
        // {2: sign_data, 3: data_type=1, 4: chain_id=1}
        let pairs = alloc::vec![
            (
                crate::encoding::cbor::encode_uint(2),
                crate::encoding::cbor::encode_bytes(&raw)
            ),
            (
                crate::encoding::cbor::encode_uint(3),
                crate::encoding::cbor::encode_uint(1)
            ),
            (
                crate::encoding::cbor::encode_uint(4),
                crate::encoding::cbor::encode_uint(1)
            ),
        ];
        let payload = crate::encoding::cbor::encode_map(&pairs);
        let enc =
            crate::ur::ur_encode::encode(crate::ur::ur_encode::UrTypeTag::EthSignRequest, &payload)
                .unwrap();
        let uri = enc.as_str();

        // Direct-sign reference: mnemonic → seed via an L1 direct call (P1-04: restore_seed_ffi removed, seed does not cross the FFI)
        // P1-05: the mnemonic must have a valid checksum — use the official vector abandon×11 + about (idx[11]=3)
        let mut idx: [u16; 12] = [0; 12];
        idx[11] = 3;
        let m = Mnemonic::from_indices(&idx, WordCount::Words12).unwrap();
        let ff_seed = crate::entropy::bip39_passphrase::mnemonic_to_seed(&m, b"").unwrap();
        let path = crate::derivation::path::DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let sk =
            crate::derivation::bip32_secp256k1::derive_from_seed(ff_seed.as_ref(), &path).unwrap();
        let expected = eip1559::sign_eip1559(&eip1559::Eip1559SignInput {
            tx,
            private_key: crate::types::SecretBytes::new(
                crate::curve_primitive::secp256k1::scalar_to_bytes(&sk),
            ),
        })
        .unwrap();

        let uri_c = alloc::ffi::CString::new(uri).unwrap();
        let mut out = [0u8; 512];
        let mut actual: c_uint = 0;
        let mut ws_buf = alloc::vec![0u8; shlosilo_sign_ws_len() as usize];
        let rc = shlosilo_sign_ur_ffi(
            uri_c.as_ptr(),
            idx.as_ptr(),
            12,
            null(),
            0,
            10,     // network = EthereumMainnet (P1-02: matches ETH chain_id=1)
            null(), // entropy (§B.5)
            0,
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
            ws_buf.as_mut_ptr(),
            shlosilo_sign_ws_len(),
        );
        assert_eq!(rc, OK, "rc={rc}");
        assert_eq!(actual as usize, expected.tx_bytes.len());
        assert_eq!(&out[..actual as usize], &expected.tx_bytes[..]);
    }

    /// Non-UR string → error code, no crash
    #[test]
    fn ffi_sign_ur_invalid_uri_rejected() {
        let uri_c = alloc::ffi::CString::new("not-a-ur").unwrap();
        let idx: [u16; 12] = [0; 12];
        let mut out = [0u8; 64];
        let mut actual: c_uint = 0;
        let mut ws_buf = alloc::vec![0u8; shlosilo_sign_ws_len() as usize];
        let rc = shlosilo_sign_ur_ffi(
            uri_c.as_ptr(),
            idx.as_ptr(),
            12,
            null(),
            0,
            0,
            null(), // entropy (§B.5)
            0,
            out.as_mut_ptr(),
            out.len() as c_uint,
            &mut actual,
            ws_buf.as_mut_ptr(),
            shlosilo_sign_ws_len(),
        );
        assert_ne!(rc, OK);
    }

    /// null URI pointer rejected
    #[test]
    fn ffi_sign_ur_null_rejected() {
        let idx: [u16; 12] = [0; 12];
        let mut out = [0u8; 64];
        let mut ws_buf = alloc::vec![0u8; shlosilo_sign_ws_len() as usize];
        let rc = shlosilo_sign_ur_ffi(
            null(),
            idx.as_ptr(),
            12,
            null(),
            0,
            0,
            null(), // entropy (§B.5)
            0,
            out.as_mut_ptr(),
            out.len() as c_uint,
            null_mut(),
            ws_buf.as_mut_ptr(),
            shlosilo_sign_ws_len(),
        );
        assert_eq!(rc, ERR_NULL_POINTER);
    }
}
