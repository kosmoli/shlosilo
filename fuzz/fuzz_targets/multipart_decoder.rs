#![no_main]
// Audit #12 P2-03: multipart UR decoder fuzz — arbitrary URI strings must never
// panic/OOM/leak. The decoder runs the zero-alloc path (caller stack pools +
// with_ws, the production shape): the `new()` leak-staging constructor is ffi
// only and trips LeakSanitizer per iteration by design.
use libfuzzer_sys::fuzz_target;
use shlosilo::encoding::fountain::{FountainWs, IdxSet, Part};
use shlosilo::ur::ur_multipart::UrMultipartDecoder;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    // Small pools on purpose: over-pool demands must surface as Err/budget
    // errors (they exercise the overload paths), never panics.
    let mut decoded = core::array::from_fn::<Option<(usize, Part)>, 8, _>(|_| None);
    let mut buffer = core::array::from_fn::<Option<(IdxSet, Part)>, 8, _>(|_| None);
    let mut queue = core::array::from_fn::<Option<(usize, Part)>, 8, _>(|_| None);
    let mut received = core::array::from_fn::<Option<IdxSet>, 8, _>(|_| None);
    let mut dec = UrMultipartDecoder::with_ws(FountainWs {
        decoded: &mut decoded,
        buffer: &mut buffer,
        queue: &mut queue,
        received: &mut received,
    });
    // Deliberate result discard: the fuzz invariant is "no panic/leak on any
    // input" — Err here is the overload/format contract, exactly what we want.
    let _ = dec.receive_frame(&s);
    dec.complete();
    let _ = dec.payload();
});
