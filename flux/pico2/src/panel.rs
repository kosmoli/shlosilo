//! Panel bring-up orchestration: shared reset + ST7796S + FT6236.
//!
//! The LCD and the touch controller share their reset line (GP16, via
//! separate 0R straps), so a full bring-up pulses it once and then inits
//! both - and the display is (re-)initialised and redrawn last, because
//! the shared pulse blanks it.
//!
//! The fitted panel: ST7796S display + FocalTech FT6236 touch (the
//! swapped-in larger panel; the vendor example targets the original 2"
//! panel with an ST7789V2 + CST816D - see lcd.rs / touch.rs notes).
//!
//! The panel is stored in a take-out slot (see `with_panel`): blocking I/O
//! runs with the driver taken OUT of the mutex, so interrupts stay enabled
//! for the duration.

use core::cell::RefCell;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use embassy_rp::gpio::Output;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::{Duration, block_for};

use crate::lcd::{self, St7796};
use crate::touch::{Chip, Touch};

/// Everything the panel bring-up owns: both drivers plus the shared reset.
pub struct Panel {
    pub lcd: St7796,
    pub touch: Touch,
    pub rst: Output<'static>,
}

static PANEL: Mutex<CriticalSectionRawMutex, RefCell<Option<Panel>>> =
    Mutex::new(RefCell::new(None));

static LCD_READY: AtomicBool = AtomicBool::new(false);
/// Chip id read at the last probe; 0x100 = not probed yet.
static TOUCH_ID: AtomicUsize = AtomicUsize::new(0x100);
/// 0 = unknown, 1 = FT6236, 2 = CST816D.
static TOUCH_CHIP: AtomicUsize = AtomicUsize::new(0);
static TOUCH_FAILED: AtomicBool = AtomicBool::new(false);

pub fn install(panel: Panel) {
    PANEL.lock(|c| *c.borrow_mut() = Some(panel));
}

/// Run `f` on the stored panel, or return None when not installed. The
/// panel is taken out of the slot for the duration (see the module docs).
pub fn with_panel<R>(f: impl FnOnce(&mut Panel) -> R) -> Option<R> {
    let mut slot = PANEL.lock(|c| c.borrow_mut().take());
    let r = slot.as_mut().map(f);
    PANEL.lock(|c| *c.borrow_mut() = slot);
    r
}

/// Full bring-up: shared reset pulse, touch probe + configure, LCD init,
/// test pattern. Runs at boot and backs the `panel` console command.
pub fn reinit() -> bool {
    with_panel(|p| {
        p.rst.set_high();
        block_for(Duration::from_millis(100));
        p.rst.set_low();
        block_for(Duration::from_millis(100));
        p.rst.set_high();
        // Post-reset settling: measured on this bench, probing the touch
        // controller immediately after the reset release does not work
        // (the FT6236 needs time to start answering I2C). Poll instead
        // of trusting one fixed delay - each retry is a cheap bit-bang
        // probe and cannot hang.
        let mut probed = p.touch.probe();
        for _ in 0..8 {
            if probed.is_ok() {
                break;
            }
            block_for(Duration::from_millis(50));
            probed = p.touch.probe();
        }
        match probed {
            Ok((chip, id)) => {
                TOUCH_ID.store(id as usize, Ordering::Relaxed);
                TOUCH_CHIP.store(
                    match chip {
                        Chip::Ft6236 => 1,
                        Chip::Cst816 => 2,
                    },
                    Ordering::Relaxed,
                );
                TOUCH_FAILED.store(false, Ordering::Relaxed);
                log::info!("[panel] touch {} detected (id=0x{id:02x})", chip.name());
                if let Err(e) = p.touch.configure() {
                    log::info!("[panel] touch configure failed: {e:?}");
                }
            }
            Err(()) => {
                TOUCH_FAILED.store(true, Ordering::Relaxed);
                log::info!("[panel] touch probe failed (no controller answered)");
            }
        }

        p.lcd.init();
        p.lcd.test_pattern();
        LCD_READY.store(true, Ordering::Relaxed);
        log::info!(
            "[panel] lcd init done; test pattern {}x{} (bands r/g/b/w + origin chip)",
            lcd::WIDTH,
            lcd::HEIGHT
        );
    })
    .is_some()
}

/// One-line panel status for the console report (read-only statics; call
/// from any context).
pub fn status_line(w: &mut impl Write) {
    let _ = write!(
        w,
        "[panel] lcd={}",
        if LCD_READY.load(Ordering::Relaxed) {
            "init"
        } else {
            "n/a"
        }
    );
    let id = TOUCH_ID.load(Ordering::Relaxed);
    if TOUCH_FAILED.load(Ordering::Relaxed) {
        let _ = write!(w, " touch=err");
    } else if id > 0xFF {
        let _ = write!(w, " touch=n/a");
    } else {
        let name = match TOUCH_CHIP.load(Ordering::Relaxed) {
            1 => "FT6236",
            2 => "CST816D",
            _ => "?",
        };
        let _ = write!(w, " touch={name}@0x{id:02x}");
    }
}
