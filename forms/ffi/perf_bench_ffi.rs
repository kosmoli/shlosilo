//! Device primitive perf-bench FFI (feature `perf-bench-ffi`).
//!
//! Raw per-primitive costs on the target (field mul / square, CT table select,
//! mixed add, quadruple double, chunked CT Straus, vartime 2-term fold). The C
//! caller times each call with its own millisecond tick; every entry returns a
//! digest so nothing is eliminated downstream.
//!
//! Each entry point has a SINGLE definition whose body is cfg-split: the real
//! implementation under the feature, a zero return otherwise, so the C host
//! always links. One definition also means cbindgen emits exactly one
//! declaration per function (dual `#[cfg]`-branches produced duplicates).

#[cfg(feature = "perf-bench-ffi")]
use curve25519_dalek::perf_bench as pb;

#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_fmul(iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::fmul(iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_fsq(iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::fsq(iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_select(iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::select(iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_madd(iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::madd(iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_quadruple(iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::quadruple(iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_ct_chunk(n: u32, iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::ct_chunk(n, iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_vartime_2term(iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::vartime_2term(iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_select_affine(iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::select_affine(iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_madd_affine(iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::madd_affine(iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

/// Chunked CT multiexp with full-width scalars (in-situ shape): n terms,
/// chunk terms per Straus call, `iters` repetitions.
#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_ct_chunked(n: u32, chunk: u32, iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::ct_chunked(n, chunk, iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}

/// Vartime 2-term multiexp with full-width scalars (the fold shape).
#[cfg_attr(not(feature = "perf-bench-ffi"), allow(unused_variables))]
#[no_mangle]
pub extern "C" fn shlosilo_perf_vartime_2term_fw(iters: u32) -> u64 {
    #[cfg(feature = "perf-bench-ffi")]
    {
        pb::vartime_2term_fullwidth(iters)
    }
    #[cfg(not(feature = "perf-bench-ffi"))]
    {
        0
    }
}
