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

#[cfg(feature = "std")]
extern crate std;

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
/// Legacy sign_ffi payload cap (aligned with UR_PAYLOAD_MAX_LEN)
const LEGACY_PAYLOAD_MAX_LEN: usize = 2048;
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
) -> c_int {
    write_actual_len(actual_len, 0); // P0-02 #4: prologue zeroes the out-param (also covers the null early-return)
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
        if ur_payload_len as usize > LEGACY_PAYLOAD_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // P0-03: payload goes through checked_slice (budget LEGACY_PAYLOAD_MAX_LEN=2048, validated before allocation)
        let payload_slice = checked_slice(
            ur_payload,
            ur_payload_len as usize,
            LEGACY_PAYLOAD_MAX_LEN,
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
        business::sign::sign(input, legacy_tag, payload_slice, out_slice)
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
) -> c_int {
    write_actual_len(actual_len, 0); // P0-02 #4: prologue zeroes the out-param
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
        business::sign::sign_with_entropy(
            input,
            decoded.type_tag(),
            decoded.as_ref(),
            entropy_slice,
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
    use crate::ur::ur_multipart::{
        UrMultipartDecoder, UrMultipartEncoder, MULTIPART_FRAME_MAX_LEN,
    };
    use alloc::boxed::Box;

    // --- R3: typed multipart FFI (finalized 2026-08-31 — replaces legacy first-byte type guessing) ---
    //
    // Dual-channel architecture (aligned with the keystone gui_model.c pattern):
    //   single large QR frame = existing shlosilo_sign_ur_ffi / ur_encode::encode (payload ≤ UR_PAYLOAD_MAX_LEN)
    //   animated multipart     = this group of three functions (payload ≤ 16 KiB, frame stream `ur:<type>/<seq>-<count>/<bw>`)
    //
    // Handle contract:
    //   - encode_begin / decode_new return handles (Box::into_raw raw pointers, non-null = success)
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
    ) -> *mut UrMultipartEncoder {
        let result = ffi_catch_unwind!(|| -> Option<*mut UrMultipartEncoder> {
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
            Some(Box::into_raw(Box::new(enc)))
        });
        match result {
            Ok(Some(h)) => h,
            _ => core::ptr::null_mut(),
        }
    }

    /// R3: get the next frame URI string (written to frame_buf, NUL-terminated).
    /// Returns 0 = Ok; negative = error code. Repeated calls produce the fountain redundancy frame stream.
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_encode_next(
        handle: *mut UrMultipartEncoder,
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
            let frame = enc.next_frame()?;
            let bytes = frame.as_bytes();
            if bytes.len() + 1 > frame_buf_len as usize {
                return Err(err(ShlosiloErrorKind::EncodingBufferOverflow));
            }
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), frame_buf, bytes.len());
                *frame_buf.add(bytes.len()) = 0;
            }
            Ok(bytes.len())
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
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_encode_next_cyclic(
        handle: *mut UrMultipartEncoder,
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
            let frame = enc.next_cyclic_frame()?;
            let bytes = frame.as_bytes();
            if bytes.len() + 1 > frame_buf_len as usize {
                return Err(err(ShlosiloErrorKind::EncodingBufferOverflow));
            }
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), frame_buf, bytes.len());
                *frame_buf.add(bytes.len()) = 0;
            }
            Ok(bytes.len())
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
        if !handle.is_null() {
            unsafe { drop(Box::from_raw(handle)) };
        }
    }

    /// R3: create a multipart decoder. Returns a handle on success, null on failure.
    #[no_mangle]
    pub extern "C" fn shlosilo_ur_decode_new() -> *mut UrMultipartDecoder {
        let result = ffi_catch_unwind!(|| -> *mut UrMultipartDecoder {
            Box::into_raw(Box::new(UrMultipartDecoder::new()))
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
        handle: *mut UrMultipartDecoder,
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
    /// Calling before completion → ERR_UNKNOWN; payload larger than buf → ERR_BUFFER_TOO_SMALL (actual_len gets the required value).
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn shlosilo_ur_decode_payload(
        handle: *mut UrMultipartDecoder,
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
            let payload = dec.payload()?.ok_or_else(err_unknown)?;
            if payload.len() > payload_buf_len as usize {
                return Err(err(ShlosiloErrorKind::BufferTooSmall));
            }
            unsafe {
                core::ptr::copy_nonoverlapping(payload.as_ptr(), payload_buf, payload.len());
            }
            Ok(payload.len())
        });
        // BufferTooSmall special case: actual_len gets the **required value** (L3 retries the allocation accordingly),
        // all other failure paths keep the R2 zeroing discipline.
        let required: usize = match &result {
            Ok(Err(e)) if e.kind == ShlosiloErrorKind::BufferTooSmall => {
                ffi_catch_unwind!(|| -> Option<usize> {
                    unsafe { &*handle }.payload().ok()?.map(|p| p.len())
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
        handle: *mut UrMultipartDecoder,
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

    /// R3/P0-C (2026-09-01): typed sign — vertical pass-through signing of the (type, payload) reassembled from multipart.
    /// type_name must be a known signable UrTypeTag (Unknown/arbitrary strings are rejected);
    /// payload budget = MULTIPART_PAYLOAD_MAX_LEN (16 KiB, aligned with the multipart reassembly cap).
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
    ) -> c_int {
        write_actual_len(actual_len, 0); // Gate4 #2: out-param zeroed up front

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
            // C string → &str (≤ 64 chars is enough for a type name)
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
            // P0-02 #2: (NULL, len>0) rejected
            let entropy_slice = optional_bytes_in(
                entropy_ptr,
                entropy_len as usize,
                crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN,
            )
            .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
            // SAFETY: mnemonic_count has passed the whitelist, null pointer already excluded
            // P0-03: mnemonic goes through checked_slice
            let mnem_slice = checked_slice(mnemonic_indices, word_count as usize, 24, false)
                .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
            // SAFETY: output_buf is non-null (excluded in the prologue)
            // P0-03: output buffer goes through checked_slice_mut
            let out_slice =
                checked_slice_mut(output_buf, output_buf_len as usize, SIGN_OUTPUT_BUF_MAX_LEN)
                    .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferTooSmall))?;
            // P0-02 #2: (NULL, len>0) rejected
            let pass_slice =
                optional_bytes_in(passphrase, passphrase_len as usize, PASSPHRASE_MAX_LEN)
                    .ok_or(ShlosiloError::new(ShlosiloErrorKind::BufferKindMismatch))?;
            if pass_slice.len() > PASSPHRASE_MAX_LEN {
                return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let mnemonic = Mnemonic::from_indices(mnem_slice, word_count)
                .map_err(|_| err(ShlosiloErrorKind::MnemonicInvalidWord))?;
            // P0-02 #3: network narrowing wraparound replaced by full-value validation via u8::try_from
            let n8 =
                u8::try_from(network).map_err(|_| err(ShlosiloErrorKind::NetworkUnrecognized))?;
            let network_parsed = Network::try_from_u8(n8)
                .ok_or_else(|| err(ShlosiloErrorKind::NetworkUnrecognized))?;
            let input = business::sign::SignInput::Mnemonic {
                mnemonic,
                passphrase: pass_slice,
            };
            business::sign::check_network(tag, payload_slice, network_parsed)?;
            business::sign::sign_with_entropy(input, tag, payload_slice, entropy_slice, out_slice)
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

    /// R3: release the decoder handle. Null-safe (idempotent).
    #[no_mangle]
    #[allow(clippy::not_unsafe_ptr_arg_deref)] // P0-02: visible to clippy once mod r3 becomes pub; free contract: single-owner
    pub extern "C" fn shlosilo_ur_decode_free(handle: *mut UrMultipartDecoder) {
        if !handle.is_null() {
            unsafe { drop(Box::from_raw(handle)) };
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

            let enc =
                shlosilo_ur_encode_begin(tname, payload.as_ptr(), payload.len() as c_uint, 200);
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

            let dec = shlosilo_ur_decode_new();
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
        /// → shlosilo_sign_typed_ffi full chain. payload = CBOR bytes item (same semantics as the single-frame UR).
        #[test]
        fn p0c_typed_sign_vertical_slice() {
            use alloc::ffi::CString;
            const PSBT: &[u8] = include_bytes!("../../tests/fixtures/sparrow_signet_12k.psbt");
            let ur_payload = crate::encoding::cbor::encode_bytes(PSBT);
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
            let enc = shlosilo_ur_encode_begin(
                tname,
                ur_payload.as_ptr(),
                ur_payload.len() as c_uint,
                200,
            );
            assert!(!enc.is_null());
            let frag_count = ur_payload.len().div_ceil(200);
            let mut frame_buf = [0u8; FRAME_BUF_MAX_LEN];
            let mut flen: c_uint = 0;
            let dec = shlosilo_ur_decode_new();
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

            // payload extraction
            let mut pbuf = [0u8; 16384];
            let mut plen: c_uint = 0;
            let rc =
                shlosilo_ur_decode_payload(dec, pbuf.as_mut_ptr(), pbuf.len() as c_uint, &mut plen);
            assert_eq!(rc, OK);
            assert_eq!(plen as usize, ur_payload.len());
            assert_eq!(&pbuf[..plen as usize], &ur_payload[..]);

            // typed sign: check_network requires BitcoinMainnet(u8=0) for crypto-psbt
            let tname_c = CString::new("crypto-psbt").unwrap();
            let mut out = [0u8; 16384 + 512];
            let mut olen: c_uint = 0;
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
            let enc = shlosilo_ur_encode_begin(c"crypto-psbt".as_ptr(), payload.as_ptr(), 8, 8);
            let dec = shlosilo_ur_decode_new();
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
        /// null handle/pointer guards
        #[test]
        fn ffi_multipart_null_guards() {
            assert!(
                shlosilo_ur_encode_begin(core::ptr::null(), core::ptr::null(), 0, 200).is_null()
            );
            assert!(!shlosilo_ur_decode_new().is_null());
            let dec = shlosilo_ur_decode_new();
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::ptr::{null, null_mut};

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
        ) -> c_int = shlosilo_sign_ffi;
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
            data: Vec::new(),
            access_list: Vec::new(),
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
        );
        assert_ne!(rc, OK);
    }

    /// null URI pointer rejected
    #[test]
    fn ffi_sign_ur_null_rejected() {
        let idx: [u16; 12] = [0; 12];
        let mut out = [0u8; 64];
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
        );
        assert_eq!(rc, ERR_NULL_POINTER);
    }
}
