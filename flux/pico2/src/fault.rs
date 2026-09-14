//! Crash capture: panics and hard faults survive a system reset and are
//! reported over the console on the next boot, so a crash is diagnosable
//! without a debug probe attached (the panic-probe/RTT path needs a probe;
//! this bench usually has none).
//!
//! Two storage channels with different survival profiles:
//!
//! - `.uninit.crash` SRAM: the full record. cortex-m-rt's startup does not
//!   zero `.uninit.*`, so it survives a soft reset (not a power cycle).
//! - Watchdog scratch registers: a compact mirror; the vendor-documented
//!   channel for passing values across resets.
//!
//! The handler issues a system reset after storing the record: the device
//! reboots into a working console where `[crash]` lines carry the record
//! until `faultclr`. A counter caps consecutive resets (a boot-time crash
//! then halts instead of looping forever); the counter is cleared once a
//! boot reaches the report task, so any crash that got as far as a running
//! shell gets the full retry budget after it.

use core::fmt::Write as _;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

/// Magic guarding both channels ("SOS2").
const MAGIC: u32 = 0x534F_5332;
/// Consecutive-reset cap before the handler halts instead of resetting.
const MAX_CONSECUTIVE_RESETS: u32 = 6;

const KIND_NONE: u32 = 0;
const KIND_PANIC: u32 = 1;
const KIND_FAULT: u32 = 2;

#[derive(Clone, Copy)]
#[repr(C)]
struct Record {
    magic: u32,
    kind: u32,
    /// panic: file ptr; fault: CFSR
    a: u32,
    /// panic: file len; fault: HFSR
    b: u32,
    /// panic: line; fault: BFAR
    c: u32,
    /// panic: message ptr; fault: MMFAR
    d: u32,
    /// panic: message len; fault: stacked PC
    e: u32,
    /// fault: stacked LR
    f: u32,
}

const EMPTY: Record = Record {
    magic: 0,
    kind: KIND_NONE,
    a: 0,
    b: 0,
    c: 0,
    d: 0,
    e: 0,
    f: 0,
};

/// Full record; survives a soft reset (see module docs).
#[unsafe(link_section = ".uninit.crash")]
static mut RECORD: MaybeUninit<Record> = MaybeUninit::uninit();

/// Rendered description of the pending record (filled by `init`).
static mut DISPLAY: [u8; 224] = [0; 224];
static mut DISPLAY_LEN: usize = 0;
/// A record is pending display (cleared by `clear`).
static HAVE_RECORD: AtomicBool = AtomicBool::new(false);

fn scratch_write(i: usize, v: u32) {
    let w = embassy_rp::pac::WATCHDOG;
    match i {
        0 => w.scratch0().write(|x| *x = v),
        1 => w.scratch1().write(|x| *x = v),
        2 => w.scratch2().write(|x| *x = v),
        3 => w.scratch3().write(|x| *x = v),
        4 => w.scratch4().write(|x| *x = v),
        5 => w.scratch5().write(|x| *x = v),
        6 => w.scratch6().write(|x| *x = v),
        _ => w.scratch7().write(|x| *x = v),
    }
}

fn scratch_read(i: usize) -> u32 {
    let w = embassy_rp::pac::WATCHDOG;
    match i {
        0 => w.scratch0().read(),
        1 => w.scratch1().read(),
        2 => w.scratch2().read(),
        3 => w.scratch3().read(),
        4 => w.scratch4().read(),
        5 => w.scratch5().read(),
        6 => w.scratch6().read(),
        _ => w.scratch7().read(),
    }
}

/// Store a record, mirror it to the scratch registers, and reset (or halt
/// once the retry budget is exhausted).
fn store_and_reset(rec: Record) -> ! {
    // Full record first (more fields than the scratch mirror holds).
    unsafe {
        ptr::write(ptr::addr_of_mut!(RECORD) as *mut Record, rec);
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    // Compact mirror: magic, kind, a, b, c, d (the fields every kind uses).
    scratch_write(0, MAGIC);
    scratch_write(1, rec.kind);
    scratch_write(2, rec.a);
    scratch_write(3, rec.b);
    scratch_write(4, rec.c);
    scratch_write(5, rec.d);
    let count = scratch_read(6).wrapping_add(1);
    scratch_write(6, count);
    scratch_write(7, MAGIC);
    if count < MAX_CONSECUTIVE_RESETS {
        // Ensure the writes land before the reset takes the core.
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        cortex_m::peripheral::SCB::sys_reset();
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Panic handler: capture the location (+ message when it is a plain string)
/// and reset.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let (file_p, file_n, line) = match info.location() {
        Some(l) => (l.file().as_ptr() as u32, l.file().len() as u32, l.line()),
        None => (0, 0, 0),
    };
    let (msg_p, msg_n) = match info.message().as_str() {
        Some(s) => (s.as_ptr() as u32, s.len() as u32),
        None => (0, 0),
    };
    store_and_reset(Record {
        magic: MAGIC,
        kind: KIND_PANIC,
        a: file_p,
        b: file_n,
        c: line,
        d: msg_p,
        e: msg_n,
        f: 0,
    })
}

/// Hard-fault handler: capture the fault status registers plus the stacked
/// PC/LR (the instructions that caused the fault) and reset.
#[cortex_m_rt::exception]
unsafe fn HardFault(frame: &cortex_m_rt::ExceptionFrame) -> ! {
    let scb = unsafe { &*cortex_m::peripheral::SCB::PTR };
    store_and_reset(Record {
        magic: MAGIC,
        kind: KIND_FAULT,
        a: scb.cfsr.read(),
        b: scb.hfsr.read(),
        c: scb.bfar.read(),
        d: scb.mmfar.read(),
        e: frame.pc(),
        f: frame.lr(),
    })
}

/// Render a raw pointer+len pair (a `&'static str` in the same firmware
/// image) into `out` at `pos`.
fn push_str(out: &mut [u8], pos: &mut usize, p: u32, n: u32) {
    if p == 0 || n == 0 || n as usize > 96 {
        return;
    }
    // SAFETY: this firmware wrote the pointer from a &'static str of the
    // same image (same addresses after a soft reset); bounds checked above.
    let s = unsafe { core::slice::from_raw_parts(p as *const u8, n as usize) };
    if let Ok(s) = core::str::from_utf8(s) {
        for &b in s.as_bytes() {
            if *pos >= out.len() {
                return;
            }
            out[*pos] = b;
            *pos += 1;
        }
    }
}

fn push_fmt(out: &mut [u8], pos: &mut usize, args: core::fmt::Arguments<'_>) {
    struct W<'a> {
        out: &'a mut [u8],
        pos: &'a mut usize,
    }
    impl core::fmt::Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for &b in s.as_bytes() {
                if *self.pos >= self.out.len() {
                    return core::fmt::Result::Err(core::fmt::Error);
                }
                self.out[*self.pos] = b;
                *self.pos += 1;
            }
            core::fmt::Result::Ok(())
        }
    }
    let _ = write!(W { out, pos }, "{args}");
}

/// Read the captured record (both channels), render it, and clear the
/// scratch channel. Call once early at boot, before the console exists.
pub fn init() {
    // Primary: the .uninit record; fall back to the scratch mirror.
    let raw = unsafe { ptr::read(ptr::addr_of!(RECORD) as *const Record) };
    let rec = if raw.magic == MAGIC {
        raw
    } else if scratch_read(0) == MAGIC && scratch_read(7) == MAGIC {
        Record {
            magic: MAGIC,
            kind: scratch_read(1),
            a: scratch_read(2),
            b: scratch_read(3),
            c: scratch_read(4),
            d: scratch_read(5),
            e: 0,
            f: 0,
        }
    } else {
        EMPTY
    };
    if rec.kind == KIND_NONE {
        return;
    }

    let mut out = [0u8; 224];
    let mut pos = 0usize;
    match rec.kind {
        KIND_PANIC => {
            push_fmt(&mut out, &mut pos, format_args!("[crash] panic at "));
            push_str(&mut out, &mut pos, rec.a, rec.b);
            push_fmt(&mut out, &mut pos, format_args!(":{}", rec.c));
            if rec.d != 0 {
                push_fmt(&mut out, &mut pos, format_args!(": "));
                push_str(&mut out, &mut pos, rec.d, rec.e);
            }
        }
        KIND_FAULT => {
            push_fmt(
                &mut out,
                &mut pos,
                format_args!(
                    "[crash] hardfault cfsr={:#010x} hfsr={:#010x} pc={:#010x} lr={:#010x} bfar={:#010x} mmfar={:#010x}",
                    rec.a, rec.b, rec.e, rec.f, rec.c, rec.d
                ),
            );
        }
        _ => {
            push_fmt(
                &mut out,
                &mut pos,
                format_args!("[crash] unknown kind {}", rec.kind),
            );
        }
    }

    unsafe {
        let d = ptr::addr_of_mut!(DISPLAY) as *mut u8;
        ptr::copy_nonoverlapping(out.as_ptr(), d, pos.min(224));
        DISPLAY_LEN = pos.min(224);
    }
    HAVE_RECORD.store(true, Ordering::Release);
    // Consume the record: both channels are cleared, the rendered text stays.
    unsafe {
        ptr::write(ptr::addr_of_mut!(RECORD) as *mut Record, EMPTY);
    }
    scratch_write(0, 0);
    scratch_write(7, 0);
}

/// The rendered crash line, while a record is pending display.
pub fn report() -> Option<&'static str> {
    if !HAVE_RECORD.load(Ordering::Acquire) {
        return None;
    }
    let len = unsafe { DISPLAY_LEN };
    let buf = unsafe { &*(ptr::addr_of!(DISPLAY) as *const [u8; 224]) };
    core::str::from_utf8(&buf[..len]).ok()
}

/// Drop the pending record (`faultclr`).
pub fn clear() {
    HAVE_RECORD.store(false, Ordering::Release);
}

/// A clean boot made it to the report task: re-arm the reset budget.
pub fn boot_ok() {
    scratch_write(6, 0);
}
