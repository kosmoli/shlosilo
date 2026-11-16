//! Z6 zero-heap link probe. `no_std` staticlib, no global allocator.
//!
//! `z6_probe_run` touches the production sign entries (XMR + typed FFI) with
//! dummy/static arguments purely for LINK REACHABILITY — the binary is never
//! executed. Link success against the C main (no allocator anywhere) is the
//! compile-level proof that the reachable sign paths allocate nothing.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Z6 finale: the lang-item stub is GONE. GRAPH-CLEAN (commit 68abad6)
// proved the crate graph links with no allocator, so the ForbiddingAlloc
// `#[global_allocator]` crutch — born as the compile-time requirement of
// the link proof — is retired. This probe now builds in the production
// shape and links against a C main with no allocator anywhere.

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
        // Phase 4a: the per-input tables are caller-owned now. Same static deploy shape
        // as the rest of the probe (never executed; the linker keeps the code and the
        // disassembly proves the reachable path allocates nothing).
        // A `static` cannot call `CompressedPoint::from`, so it is declared as raw bytes
        // and viewed as the ring row type: all-zero bytes ARE the zero point.
        static mut RINGS_BYTES: [u8; core::mem::size_of::<
            [(shlosilo::monero_ed25519::CompressedPoint, shlosilo::monero_ed25519::CompressedPoint);
                shlosilo::types::caps::RING_MAX]>()
            * shlosilo::limits::XMR_INPUTS_MAX] = [0u8; core::mem::size_of::<
            [(shlosilo::monero_ed25519::CompressedPoint, shlosilo::monero_ed25519::CompressedPoint);
                shlosilo::types::caps::RING_MAX]>()
            * shlosilo::limits::XMR_INPUTS_MAX];
        let rings: &mut [[(
            shlosilo::monero_ed25519::CompressedPoint,
            shlosilo::monero_ed25519::CompressedPoint,
        ); shlosilo::types::caps::RING_MAX]; shlosilo::limits::XMR_INPUTS_MAX] =
            core::slice::from_raw_parts_mut(
                RINGS_BYTES.as_mut_ptr().cast(),
                shlosilo::limits::XMR_INPUTS_MAX,
            )
            .try_into()
            .expect("rings view");
        static mut TX_INPUTS: [shlosilo::chain::xmr::transaction::TxInput;
            shlosilo::limits::XMR_INPUTS_MAX] = [shlosilo::chain::xmr::transaction::TxInput::EMPTY;
            shlosilo::limits::XMR_INPUTS_MAX];
        static mut RING_LENS: [usize; shlosilo::limits::XMR_INPUTS_MAX] =
            [0usize; shlosilo::limits::XMR_INPUTS_MAX];
        static mut STRAUS_STORAGE: [u8; 5772864] = [0u8; 5772864];
        // 2050 * 960 = WipScratch::storage_bytes(2050)
        static mut WIP_STORAGE: [u8; 1968000] = [0u8; 1968000];
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
            shlosilo::chain::xmr::tx_signer::InputTables {
                rings,
                tx_inputs: &mut TX_INPUTS,
                ring_lens: &mut RING_LENS,
            },
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
