//! allocator + panic handler for embedded (thumbv7em-none-eabihf) builds
//!
//! Compiles only under `--no-default-features` + the embedded target.
//! The L3 host (keystone firmware / ForgeBox) provides `shlosilo_embedded_malloc/free`
//! (FreeRTOS heap_4 wrappers); panics go to the firmware log.

#![cfg(not(feature = "std"))]

use core::alloc::{GlobalAlloc, Layout};
use core::fmt::Write as _;
use core::panic::PanicInfo;

use critical_section::RawRestoreState;

extern "C" {
    /// Provided by L3: FreeRTOS pvPortMalloc wrapper
    fn shlosilo_embedded_malloc(size: usize) -> *mut u8;
    /// Provided by L3: vPortFree wrapper
    fn shlosilo_embedded_free(ptr: *mut u8);
}

pub struct EmbeddedAllocator;

unsafe impl GlobalAlloc for EmbeddedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        shlosilo_embedded_malloc(layout.size())
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        shlosilo_embedded_free(ptr)
    }
}

#[global_allocator]
static EMBEDDED_ALLOCATOR: EmbeddedAllocator = EmbeddedAllocator;

// ── critical-section impl (single-core MCU: global interrupt disable/restore) ──
//
// critical-section 1.x on no_std requires the user to provide an implementation via set_impl!.
// On a single-core Cortex-M the simplest correct implementation is PRIMASK interrupt masking (cortex-m::interrupt::free semantics);
// we avoid the cortex-m dependency and inline CPSID/CPSIE directly.
struct SingleCoreInterrupts;

unsafe impl critical_section::Impl for SingleCoreInterrupts {
    unsafe fn acquire() -> RawRestoreState {
        let mut primask: u32;
        core::arch::asm!(
            "mrs {0}, primask",
            "cpsid i",
            out(reg) primask,
            options(nomem, nostack, preserves_flags)
        );
        primask != 0
    }

    unsafe fn release(restore_state: RawRestoreState) {
        if restore_state {
            core::arch::asm!("msr primask, {0}", in(reg) 1u32, options(nomem, nostack, preserves_flags));
        } else {
            core::arch::asm!("cpsie i", options(nomem, nostack, preserves_flags));
        }
    }
}

critical_section::set_impl!(SingleCoreInterrupts);

#[panic_handler]
fn shlosilo_panic(info: &PanicInfo) -> ! {
    // collect the panic message into a stack buffer and hand it to the C-side hook to display on the LCD (no serial port on device)
    let mut buf = [0u8; 160];
    let pos;
    {
        let mut w = PanicWriter {
            buf: &mut buf,
            pos: 0,
        };
        if let Some(msg_str) = info.message().as_str() {
            let _ = w.write_str(msg_str);
        } else {
            let _ = w.write_str("panic");
        }
        if let Some(loc) = info.location() {
            let _ = core::fmt::write(
                &mut w,
                core::format_args!(" @ {}:{}", loc.file(), loc.line()),
            );
        }
        pos = w.pos;
    } // w dropped, buf borrow ends
      // contract: the hook returns ! (LCD display + infinite loop keeps the system alive) and never returns
    unsafe {
        shlosilo_panic_hook(buf.as_ptr(), pos);
    }
}

struct PanicWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl core::fmt::Write for PanicWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = core::cmp::min(s.len(), self.buf.len() - self.pos);
        self.buf[self.pos..self.pos + n].copy_from_slice(&s.as_bytes()[..n]);
        self.pos += n;
        Ok(())
    }
}

extern "C" {
    /// Provided by L3: display panic info (LCD) + keep the system alive/refresh
    fn shlosilo_panic_hook(msg: *const u8, len: usize) -> !;
}
