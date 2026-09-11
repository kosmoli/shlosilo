//! Device primitive perf-bench FFI (feature `perf-bench-ffi`).
//!
//! Raw per-primitive costs on the target (field mul / square, CT table select,
//! mixed add, quadruple double, chunked CT Straus, vartime 2-term fold). The C
//! caller times each call with its own millisecond tick; every entry returns a
//! digest so nothing is eliminated downstream.
//!
//! Feature off -> zero-returning stubs so the C side always links.

#[cfg(feature = "perf-bench-ffi")]
use curve25519_dalek::perf_bench as pb;

#[cfg(feature = "perf-bench-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_perf_fmul(iters: u32) -> u64 {
    pb::fmul(iters)
}
#[cfg(not(feature = "perf-bench-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_fmul(_iters: u32) -> u64 {
    0
}

#[cfg(feature = "perf-bench-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_perf_fsq(iters: u32) -> u64 {
    pb::fsq(iters)
}
#[cfg(not(feature = "perf-bench-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_fsq(_iters: u32) -> u64 {
    0
}

#[cfg(feature = "perf-bench-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_perf_select(iters: u32) -> u64 {
    pb::select(iters)
}
#[cfg(not(feature = "perf-bench-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_select(_iters: u32) -> u64 {
    0
}

#[cfg(feature = "perf-bench-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_perf_madd(iters: u32) -> u64 {
    pb::madd(iters)
}
#[cfg(not(feature = "perf-bench-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_madd(_iters: u32) -> u64 {
    0
}

#[cfg(feature = "perf-bench-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_perf_quadruple(iters: u32) -> u64 {
    pb::quadruple(iters)
}
#[cfg(not(feature = "perf-bench-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_quadruple(_iters: u32) -> u64 {
    0
}

#[cfg(feature = "perf-bench-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_perf_ct_chunk(n: u32, iters: u32) -> u64 {
    pb::ct_chunk(n, iters)
}
#[cfg(not(feature = "perf-bench-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_ct_chunk(_n: u32, _iters: u32) -> u64 {
    0
}

#[cfg(feature = "perf-bench-ffi")]
#[no_mangle]
pub extern "C" fn shlosilo_perf_vartime_2term(iters: u32) -> u64 {
    pb::vartime_2term(iters)
}
#[cfg(not(feature = "perf-bench-ffi"))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_vartime_2term(_iters: u32) -> u64 {
    0
}
