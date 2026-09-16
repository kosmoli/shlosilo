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
    /// failed allocation: layout size (0 = none recorded)
    g: u32,
    /// failed allocation: layout align
    h: u32,
    /// failed allocation: region (0 = SRAM heap, 1 = PSRAM heap)
    i: u32,
    /// SRAM heap live bytes at panic time
    j: u32,
    /// PSRAM heap live bytes at panic time
    k: u32,
    /// size of the last successful PSRAM-routed allocation
    l: u32,
    /// rendered panic-message length in MSG_BUF (survives reset)
    m: u32,
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
    g: 0,
    h: 0,
    i: 0,
    j: 0,
    k: 0,
    l: 0,
    m: 0,
};

/// Full record; survives a soft reset (see module docs).
#[unsafe(link_section = ".uninit.crash")]
static mut RECORD: MaybeUninit<Record> = MaybeUninit::uninit();

/// Rendered panic message ("memory allocation of N bytes failed", ...);
/// formatted at panic time (the args live in the panicking frame) and kept
/// for the next boot. Without this, format-args panics lose their payload -
/// and for an alloc failure the payload IS the number worth knowing.
#[unsafe(link_section = ".uninit.crash")]
static mut MSG_BUF: [u8; 160] = [0; 160];

/// Rendered description of the pending record (filled by `init`).
static mut DISPLAY: [u8; 320] = [0; 320];
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

/// Panic handler: capture the location and the formatted message (into a
/// reset-surviving buffer) and reset.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let (file_p, file_n, line) = match info.location() {
        Some(l) => (l.file().as_ptr() as u32, l.file().len() as u32, l.line()),
        None => (0, 0, 0),
    };
    // Render the message with Display: covers both `&'static str` and
    // format-args panics (the alloc-failure message carries its size only
    // as a formatted argument).
    let mut mpos = 0usize;
    unsafe {
        let buf: &mut [u8] = &mut *ptr::addr_of_mut!(MSG_BUF);
        let mut w = SliceWriter {
            out: buf,
            pos: &mut mpos,
        };
        let _ = write!(w, "{}", info.message());
    }
    let (sram_live, _, _) = crate::heap_stats();
    let (psram_live, _, _) = crate::psram_stats();
    store_and_reset(Record {
        magic: MAGIC,
        kind: KIND_PANIC,
        a: file_p,
        b: file_n,
        c: line,
        d: 0,
        e: 0,
        f: 0,
        g: crate::alloc_fail_size() as u32,
        h: crate::alloc_fail_align() as u32,
        i: crate::alloc_fail_region() as u32,
        j: sram_live as u32,
        k: psram_live as u32,
        l: crate::last_big_alloc() as u32,
        m: mpos as u32,
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
        g: crate::alloc_fail_size() as u32,
        h: crate::alloc_fail_align() as u32,
        i: crate::alloc_fail_region() as u32,
        j: 0,
        k: 0,
        l: crate::last_big_alloc() as u32,
        m: 0,
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

/// Bounded writer over a fixed slice (no allocation; usable in the panic
/// handler and on the next boot alike).
struct SliceWriter<'a> {
    out: &'a mut [u8],
    pos: &'a mut usize,
}

impl core::fmt::Write for SliceWriter<'_> {
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

fn push_fmt(out: &mut [u8], pos: &mut usize, args: core::fmt::Arguments<'_>) {
    let mut w = SliceWriter { out, pos };
    let _ = write!(w, "{args}");
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
            g: 0,
            h: 0,
            i: 0,
            j: 0,
            k: 0,
            l: 0,
            m: 0,
        }
    } else {
        EMPTY
    };
    if rec.kind == KIND_NONE {
        return;
    }

    let mut out = [0u8; 320];
    let mut pos = 0usize;
    match rec.kind {
        KIND_PANIC => {
            push_fmt(&mut out, &mut pos, format_args!("[crash] panic at "));
            push_str(&mut out, &mut pos, rec.a, rec.b);
            push_fmt(&mut out, &mut pos, format_args!(":{}", rec.c));
            if rec.m > 0 {
                // The rendered panic message (e.g. "memory allocation of
                // 2097152 bytes failed") - the payload a format-args panic
                // would otherwise lose.
                let msg = unsafe { &*ptr::addr_of!(MSG_BUF) };
                let n = (rec.m as usize).min(160);
                push_fmt(&mut out, &mut pos, format_args!(": "));
                if let Ok(s) = core::str::from_utf8(&msg[..n]) {
                    for &b in s.as_bytes() {
                        if pos < out.len() {
                            out[pos] = b;
                            pos += 1;
                        }
                    }
                }
            } else if rec.d != 0 {
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
    if rec.g != 0 {
        let region = if rec.i == 1 { "psram" } else { "sram" };
        push_fmt(
            &mut out,
            &mut pos,
            format_args!(
                " | allocfail size={} align={} region={region}",
                rec.g, rec.h
            ),
        );
    }
    if rec.kind == KIND_PANIC {
        push_fmt(
            &mut out,
            &mut pos,
            format_args!(" | live sram={} psram={} lastbig={}", rec.j, rec.k, rec.l),
        );
    }

    unsafe {
        let d = ptr::addr_of_mut!(DISPLAY) as *mut u8;
        ptr::copy_nonoverlapping(out.as_ptr(), d, pos.min(320));
        DISPLAY_LEN = pos.min(320);
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
    // Length clamped to the buffer on BOTH sides: the stored length can
    // never index past DISPLAY. (This exact spot once had a stale fixed-size
    // cast whose panic overwrote a real crash record - the reporter must
    // never be able to crash.)
    let len = unsafe { DISPLAY_LEN }.min(320);
    let buf = unsafe { core::slice::from_raw_parts(ptr::addr_of!(DISPLAY) as *const u8, len) };
    core::str::from_utf8(buf).ok()
}

/// Drop the pending record (`faultclr`).
pub fn clear() {
    HAVE_RECORD.store(false, Ordering::Release);
}

/// A clean boot made it to the report task: re-arm the reset budget.
pub fn boot_ok() {
    scratch_write(6, 0);
}
