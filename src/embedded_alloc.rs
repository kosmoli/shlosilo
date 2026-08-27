//! embedded（thumbv7em-none-eabihf）构建的 allocator + panic handler
//!
//! 仅在 `--no-default-features` + embedded target 下编译。
//! L3 宿主（keystone 固件 / ForgeBox）提供 `shlosilo_embedded_malloc/free`
//! （FreeRTOS heap_4 包装），panic 走固件日志。

#![cfg(not(feature = "std"))]

use core::alloc::{GlobalAlloc, Layout};
use core::fmt::Write as _;
use core::panic::PanicInfo;

use critical_section::RawRestoreState;

extern "C" {
    /// L3 提供：FreeRTOS pvPortMalloc 包装
    fn shlosilo_embedded_malloc(size: usize) -> *mut u8;
    /// L3 提供：vPortFree 包装
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

// ── critical-section Impl（单核 MCU：全局中断关闭/恢复）──
//
// critical-section 1.x 在 no_std 下要求使用者通过 set_impl! 提供实现。
// 单核 Cortex-M 上最简单的正确实现是 PRIMASK 关中断（cortex-m::interrupt::free 语义）；
// 这里不引 cortex-m 依赖，直接内联 CPSID/CPSIE。
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
    // 收集 panic 消息到栈 buffer，交 C 侧 hook 显示到 LCD（真机无串口）
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
    } // w drop，buf 借用结束
    unsafe {
        shlosilo_panic_hook(buf.as_ptr(), pos);
    }
    // 不应返回（hook 死循环）；防御性兜底
    loop {
        core::hint::spin_loop();
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
    /// L3 提供：panic 信息显示（LCD）+ 保持系统运行/刷新
    fn shlosilo_panic_hook(msg: *const u8, len: usize) -> !;
}
