//! Panel bring-up orchestration: shared reset + ST7789V2 + CST816D.
//!
//! The LCD and the touch controller share their reset line (GP16, via
//! separate 0R straps), so a full bring-up pulses it once and then inits
//! both - and the display is (re-)initialised and redrawn last, because
//! the shared pulse blanks it.
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

use crate::lcd::{self, St7789};
use crate::touch::{CHIP_ID, Cst816};

/// Everything the panel bring-up owns: both drivers plus the shared reset.
pub struct Panel {
    pub lcd: St7789,
    pub touch: Cst816,
    pub rst: Output<'static>,
}

static PANEL: Mutex<CriticalSectionRawMutex, RefCell<Option<Panel>>> =
    Mutex::new(RefCell::new(None));

static LCD_READY: AtomicBool = AtomicBool::new(false);
/// Chip id read at the last probe; 0x100 = not probed yet.
static TOUCH_ID: AtomicUsize = AtomicUsize::new(0x100);
static TOUCH_FW: AtomicUsize = AtomicUsize::new(0);
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
        block_for(Duration::from_millis(100));

        match p.touch.probe() {
            Ok((id, fw)) => {
                TOUCH_ID.store(id as usize, Ordering::Relaxed);
                TOUCH_FW.store(fw as usize, Ordering::Relaxed);
                TOUCH_FAILED.store(false, Ordering::Relaxed);
                log::info!(
                    "[panel] touch id=0x{id:02x} fw=0x{fw:02x}{}",
                    if id == CHIP_ID {
                        ""
                    } else {
                        " (unexpected id!)"
                    }
                );
                if let Err(e) = p.touch.configure() {
                    log::info!("[panel] touch configure failed: {e:?}");
                }
            }
            Err(e) => {
                TOUCH_FAILED.store(true, Ordering::Relaxed);
                log::info!("[panel] touch probe failed: {e:?}");
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
        let fw = TOUCH_FW.load(Ordering::Relaxed);
        let _ = write!(w, " touch=0x{id:02x}/fw{fw}");
    }
}
