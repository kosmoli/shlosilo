#![no_main]
// Audit #12 P2-03: multipart UR decoder fuzz — arbitrary URI strings must never
// panic/OOM/leak. The decoder runs the zero-alloc path (caller stack pools +
// with_ws, the production shape): the `new()` leak-staging constructor is ffi
// only and trips LeakSanitizer per iteration by design.
use libfuzzer_sys::fuzz_target;
use shlosilo::encoding::fountain::{FountainWs, IdxKey, IdxSet};
use shlosilo::ur::ur_multipart::UrMultipartDecoder;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    // Small pools on purpose: over-pool demands must surface as Err/budget
    // errors (they exercise the overload paths), never panics.
    // Phase 5b pools: metadata only, with the fragment bytes in two arenas.
    let mut decoded = core::array::from_fn::<Option<usize>, 8, _>(|_| None);
    let mut buffer = core::array::from_fn::<Option<(IdxSet, usize)>, 8, _>(|_| None);
    let mut queue = core::array::from_fn::<Option<usize>, 8, _>(|_| None);
    let mut received = core::array::from_fn::<Option<IdxKey>, 8, _>(|_| None);
    let mut message = [0u8; 512];
    let mut equations = [0u8; 8 * 64];
    let mut dec = UrMultipartDecoder::with_ws(FountainWs {
        decoded: &mut decoded,
        buffer: &mut buffer,
        queue: &mut queue,
        received: &mut received,
        message: &mut message,
        equations: &mut equations,
    });
    // Deliberate result discard: the fuzz invariant is "no panic/leak on any
    // input" — Err here is the overload/format contract, exactly what we want.
    let _ = dec.receive_frame(&s);
    dec.complete();
    let _ = dec.payload();
});
