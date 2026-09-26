//! Z6 zero-heap link probe. `no_std` staticlib, no global allocator.
//!
//! `z6_probe_run` touches the production sign entries (XMR + typed FFI) with
//! dummy/static arguments purely for LINK REACHABILITY — the binary is never
//! executed. Link success against the C main (no allocator anywhere) is the
//! compile-level proof that the reachable sign paths allocate nothing.
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::alloc::{GlobalAlloc, Layout};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// TEMPORARY (Z6 enumeration phase): a forbidding allocator so the crate graph
// compiles while we collect the remaining alloc call sites via `nm`. It is
// REMOVED in the final state — the proof is the probe building with NO
// allocator definition at all.
struct ForbiddingAlloc;

unsafe impl GlobalAlloc for ForbiddingAlloc {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        panic!("Z6: allocation reached in the no-alloc probe")
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        panic!("Z6: deallocation reached in the no-alloc probe")
    }
}

#[global_allocator]
static ALLOC: ForbiddingAlloc = ForbiddingAlloc;

// Static scratch (the deploy shape: caller-owned memory everywhere).
static mut OUT: [u8; 16384] = [0u8; 16384];
static mut WS: [u8; 262144] = [0u8; 262144];

#[no_mangle]
pub extern "C" fn z6_probe_run() {
    // Link reachability for the PRODUCTION XMR sign path (the Z2-Z5 zero-heap
    // claim): the caller-buffer `_into` entry. Arguments are dummies — the
    // probe is never executed; the linker keeps the code and the
    // disassembly proves whether it may allocate.
    unsafe {
        static mut OUT: [u8; 4096] = [0u8; 4096];
        // A zeroed TxConstructionData is a valid EMPTY value (zero-length
        // slices; no dangling refs) — unlike an uninit reference, which is UB
        // and let LLVM elide the whole call (the first probe revision was
        // vacuous for exactly this reason).
        let txd: shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'static> =
            core::mem::MaybeUninit::zeroed().assume_init();
        let txd: &shlosilo::chain::xmr::unsigned_txset::TxConstructionData<'static> = &txd;
        let spend = [0u8; 32];
        let view = [0u8; 32];
        let r_bytes = zeroize::Zeroizing::new([0u8; 32]);
        let mut bp_rng = DummyRng;
        let mut clsag_rng = DummyRng;
        static mut TERMS: [(shlosilo::curve25519_dalek::Scalar, shlosilo::curve25519_dalek::EdwardsPoint); 2050] = [(
            shlosilo::curve25519_dalek::Scalar::ZERO,
            shlosilo::curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
        ); 2050];
        static mut STRAUS_STORAGE: [u8; 5772864] = [0u8; 5772864];
        // 2050 * 768 = WipScratch::storage_bytes(2050)
        static mut WIP_STORAGE: [u8; 1574400] = [0u8; 1574400];
        let mut straus = shlosilo::curve25519_dalek::scratch::StrausScratch::new(
            &mut STRAUS_STORAGE,
            2050,
        )
        .expect("static storage");
        let _ = shlosilo::chain::xmr::tx_signer::sign_tx_from_construction_with_rngs_into(
            txd,
            &spend,
            &view,
            &r_bytes,
            &mut bp_rng,
            &mut clsag_rng,
            &mut OUT,
            &mut TERMS,
            &mut straus,
            &mut shlosilo::monero_bulletproofs::WipScratch::new(&mut WIP_STORAGE, 2050).unwrap(),
        );
    }
}

/// Non-cryptographic dummy RNG for link reachability only (never run).
struct DummyRng;

impl rand_core::RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {}
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Ok(())
    }
}
impl rand_core::CryptoRng for DummyRng {}
