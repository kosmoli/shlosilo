/* product_task.c - the product-UI boot task (product flavor, SMOKE_SCREEN=0).
 *
 * Carries the duties the LVGL display task handles in the smoke flavor:
 * panel ownership (via shlosilo_ui), touch init, power button (long press =
 * restart) and the watchdog feed. Initialization order replicates the proven
 * smoke chain: ExtInterruptInit() first, then the touch probe/init on the
 * I2CIO bit-bang bus (no hardware I2C controller for the touch IC at probe
 * time).
 *
 * D2: the QR scan session. Entering the scan page runs QrDecodeInit() with a
 * 410 KiB PSRAM pool and then pumps QrDecodeProcess() frame by frame. Bus
 * note (PB0/PB1 shares the camera SCCB with the touch IC): the touch probe
 * uses bit-banged GPIO, while runtime touch reads and the camera SCCB both go
 * through hardware I2C0 - and everything here runs in this single task, so
 * the two never overlap on the bus. On exit, I2cInit() restores the known-
 * good bus configuration for the touch.
 */
#include "product_task.h"
#include <stdio.h>
#include <string.h>
#include "cmsis_os.h"
#include "FreeRTOS.h"
#include "task.h"
#include "psram_heap_4.h"
#include "mhscpu.h"
#include "mhscpu_gpio.h"
#include "mhscpu_wdt.h"
#include "drv_exti.h"
#include "drv_i2c.h"
#include "drv_qrdecode.h"
#include "drv_ft6336.h"
#include "drv_battery.h"
#include "drv_aw32001.h"
#include "user_memory.h"
#include "hal_touch.h"
#include "shlosilo_ui.h"
#include "ui_layout.h"
#include "shlosilo.h"
#include "demo_payload.h"
#include "err_code.h"
#include "se_smoke.h"
#include "drv_trng.h"

/* SRAM window handoff (shared with the K2-D Rust pool; implemented in
 * shlosilo/embedded_alloc_glue.c - not part of the FFI surface). */
size_t shlosilo_sram_pool_live_bytes(void);
void shlosilo_sram_pool_reset(void);

#define UI_POLL_MS                40
#define WDT_FEED_INTERVAL_MS      100
#define BUTTON_CHECK_INTERVAL_MS  50
#define BUTTON_LONG_PRESS_MS      3000

#define BUTTON_INT_PORT           GPIOE
#define BUTTON_INT_PIN            GPIO_Pin_14

/* QR scan session */
#define QR_POOL_BYTES             (410 * 1024)
#define QR_RESULT_MAX             4096
#define SCAN_INFO_EVERY_FRAMES    4

/* UR carousel session (F3 output side) */
#define CAROUSEL_FRAME_MS         450
/* Frame buffer: the FFI contract (c_abi.rs FRAME_BUF_MAX_LEN=1024) REJECTS
 * frame buffers shorter than 1024 even though a 200B-fragment frame is only
 * ~460 chars. The first carousel build used 576 here and bounced straight
 * back to the welcome page (ERR_BUFFER_TOO_SMALL on the first frame); keep
 * this >= the FFI minimum - scripts/test_carousel_ffi.py cross-checks the
 * two constants and round-trips the real payload at this exact size. */
#define CAROUSEL_FRAME_MAX        1024

/* Touch sampling slice: the carousel dwell is split into slices with a touch
 * poll each. A single poll per ~600 ms cycle missed most taps on device
 * (reported as "touch intermittently dead, no pattern"). */
#define CAROUSEL_TOUCH_SLICE_MS   20

typedef enum {
    SCAN_IDLE = 0,      /* not on the scan page (or exited) */
    SCAN_ACTIVE,        /* camera initialized, scanning frames */
    SCAN_FAILED,        /* on the scan page, init failed (exit to retry) */
} ScanState;

static void ProductTask(void *argument);
static void scan_enter(void);
static void scan_step(void);
static void scan_exit(void);
static void seed_confirm_step(void);
static void key_session_close(void);
/* Task 5b seed-flow state (full definition below with the seed helpers;
 * tentative declaration here because ProductTask's exit leg consults it). */
static const struct KeySession *g_key_session;
/* Task 8: which source opened the live session (1 = SE password unlock). The
 * seed-flow exit leg only tears down PLATE sessions ("a live plate session
 * outside the flow pages means the flow exited"); an SE session lives until
 * `se lock` or the sign-done close (v1: session per sign). */
static int g_key_from_se;
/* Phase 4: console-created wallet session ('key new') — NOT flow-owned (same
 * lifetime as an SE unlock: lives until 'se lock' / sign-done close), so it
 * survives UI navigation and the plate-export flow can run against it. */
static int g_key_console;
/* T5 Cake pairing: the QR page is currently showing the FLOW-OWNED pairing
 * output (xmr-keyimage, beat 2 of the four-beat cold-sign flow). The seed-flow
 * exit gate must not kill the plate session underneath it -- the sign request
 * (beat 3) is still coming. Self-clearing invariant: only meaningful while
 * the QR page is up (the idle loop drops it the moment the page changes), so
 * a real exit (back to welcome, any other page) falls back to the default
 * teardown. */
static int g_pairing_qr;
static void seed_plate_wipe(void);
static void carousel_enter(void);
static void carousel_step(void);
static void carousel_exit(void);
static void power_button_init(void);
static void power_button_check(void);
static void product_status_tick(void);
static void product_charger_evt(void);

static uint32_t g_button_press_start = 0;
static bool g_button_pressed = false;

/* Charger insert/remove event latch: the PF15 EXTI (both edges, see
 * drv_exti.c) calls product_charger_evt in ISR context, which only sets a
 * flag; product_status_tick consumes it. Previously NOTHING consumed this
 * event (the callback was never registered), so "c" tracking relied on the
 * 5 s battery poll alone - up to 5 s late on plug/unplug. */
static volatile uint8_t g_charger_evt;

/* Scan session state */
static uint8_t *g_qr_pool = NULL;
static char g_qr_result[QR_RESULT_MAX];
static ScanState g_scan = SCAN_IDLE;
static uint32_t g_scan_frames = 0;

/* Carousel session state (F3 output side) */
typedef enum {
    CAROUSEL_IDLE = 0,
    CAROUSEL_ACTIVE,        /* encoding + animating UR frames */
    CAROUSEL_FAILED,        /* on the QR page but the session could not run */
} CarouselState;

static CarouselState g_carousel = CAROUSEL_IDLE;
static struct UrMultipartEncoder *g_ur_enc = NULL;
/* Z3.3c: encoder workspace (caller-owned; lives from begin to free) */
static uint8_t *g_ur_enc_ws = NULL;
static char g_ur_frame[CAROUSEL_FRAME_MAX];
static uint32_t g_ur_shown = 0;
static uint32_t g_ur_total = 0;

/* Shared input state: ONE press-edge tracker for every sampler (dwell
 * slices, band-flush waits, capture waits - the last two via the UiInputPoll
 * hook). Flags are consumed by the page loops. Sampling a press only from
 * the frame loop left ~200 ms blind windows per cycle (render + full flush),
 * which read as "touch intermittently dead" on device. */
static int g_touch_prev;
static int g_scan_abort_req;
static int g_ur_exit_req;
static int g_back_press_x;
static int g_back_press_y;

/* Sample touch once; record a fresh press on `back` for whichever session is
 * active. Safe to call at any point (task context only - the touch read is a
 * ~0.2 ms I2C0 transaction, and nothing else on the bus runs concurrently). */
static void product_touch_poll(void)
{
    TouchStatus_t st;
    int down;

    if (g_scan != SCAN_ACTIVE && g_carousel != CAROUSEL_ACTIVE) {
        return;
    }
    if (TouchGetStatus(&st) != 0) {
        return;
    }
    down = st.touch ? 1 : 0;
    if (down && !g_touch_prev && UiIsBackButton((int)st.x, (int)st.y)) {
        g_back_press_x = (int)st.x;
        g_back_press_y = (int)st.y;
        if (g_scan == SCAN_ACTIVE) {
            g_scan_abort_req = 1;
        }
        if (g_carousel == CAROUSEL_ACTIVE) {
            g_ur_exit_req = 1;
        }
    }
    g_touch_prev = down;
}

/* A (2026-10-02): the Z5.3 chunked BP+ path peaks at 148 KiB of stack
 * (smoke-battery measured `stk used 148K` on a 160 KiB task) and the product
 * task stacks the sign session on top of the UI loop - the old 16 KiB stack
 * smashed FreeRTOS heap neighbours on the first XMR sign. 192 KiB = measured
 * peak + headroom; the product flavor runs no LVGL so the 450 KiB SRAM heap
 * has room. Keep in sync with SHLOSILO_SMOKE_STACK_BYTES in
 * shlosilo_smoke_task.c when the sign stack shape changes. */
#define PRODUCT_TASK_STACK_BYTES  (192u * 1024u)

/* WDT feeder flag: see WdtGuardTask. */
static volatile uint8_t g_sign_busy;

/* A: watchdog feeder for the blocking sign call. The product task is this
 * flavor's only WDT feeder (the smoke flavor's display task plays that role),
 * and the ~18 s XMR sign blocks it in a compute-bound FFI call that never
 * yields - without this guard the 2 s WDT resets the board mid-sign.
 *
 * Priority is ABOVE product_ui on purpose (first device run, 2026-10-03:
 * the sign window reset the board): a lower/equal-priority feeder is not
 * deterministic - FreeRTOS never schedules a Normal task while the High
 * sign task stays runnable, and equal-priority time slicing is a config
 * accident (it is what saves the smoke flavor's feeder). Realtime
 * preempts every interval unconditionally. Gated on g_sign_busy: outside
 * a sign the product loop keeps feeding, so hangs still trip the watchdog.
 * The guard also keeps the power button's long-press restart live during
 * the sign (smoke parity). 4 KiB stack: the long-press path prints. */
static void WdtGuardTask(void *argument)
{
    (void)argument;
    for (;;) {
        if (g_sign_busy) {
            WDT_ReloadCounter();
            power_button_check();
        }
        osDelay(250);
    }
}

void CreateProductTask(void)
{
    static const osThreadAttr_t task_attr = {
        .name = "product_ui",
        .stack_size = PRODUCT_TASK_STACK_BYTES,
        .priority = osPriorityHigh,
    };
    static const osThreadAttr_t guard_attr = {
        .name = "wdt_guard",
        .stack_size = 4 * 1024,
        .priority = osPriorityRealtime,
    };
    osThreadNew(ProductTask, NULL, &task_attr);
    osThreadNew(WdtGuardTask, NULL, &guard_attr);
}

/* ---------------- boot fault-record replay (blackbox peek) ---------------- */

/* xmr_gen_cache_flash.c (flash persistence hooks, shared with the smoke task). */
extern void gc_flash_init(void);
extern const uint8_t *gc_load(const uint8_t *prefix, uint32_t prefix_len);
extern uint32_t gc_store(const uint8_t *prefix, uint32_t prefix_len,
                         const uint8_t *blob, uint32_t blob_len);

/* hardfault_diag.c persists a hard fault as an RSLT record ("FAULT cfsr=..
 * pc=.. lr=.. sp=..") at 0x01E42000 and then DELIBERATELY resets through
 * the shortest WDT window - so a plain "crash restart" is ambiguous between
 * a hard fault and a WDT starvation reset UNLESS this record is checked.
 * Peek at boot, read-and-erase (smoke parity: a stale record must not
 * impersonate the next crash). No record = the reset was not a hard fault. */
#define FAULT_REC_BASE        0x01E42000u

extern void FLASH_EraseSector(uint32_t addr);
extern void CACHE_CleanAll(CACHE_TypeDef *cache);

static void fault_record_peek(void)
{
    const volatile uint8_t *rec = (const volatile uint8_t *)FAULT_REC_BASE;
    char text[128];
    uint32_t len, i;

    /* QSPI write access first (smoke parity: its ckpt writes call
     * gc_flash_init before any erase/program - without it the erase below
     * can silently fail and stale records replay forever). */
    gc_flash_init();

    if (rec[0] != 'R' || rec[1] != 'S' || rec[2] != 'L' || rec[3] != 'T') {
        return;     /* erased sector: previous boot was clean */
    }
    len = (uint32_t)rec[4] | ((uint32_t)rec[5] << 8);
    if (len == 0 || len > sizeof(text) - 1) {
        len = sizeof(text) - 1;
    }
    for (i = 0; i < len; i++) {
        text[i] = (char)rec[8 + i];
    }
    text[len] = '\0';
    printf("PREV fault: %s\r\n", text);
    UiSetLast(text);

    __disable_irq();
    FLASH_EraseSector(FAULT_REC_BASE);
    CACHE_CleanAll(CACHE);
    __enable_irq();
    WDT_ReloadCounter();
}

static void ProductTask(void *argument)
{
    (void)argument;

    printf("product UI task started\r\n");
    WDT_ReloadCounter();
    fault_record_peek();

    ExtInterruptInit();
    /* PF15 (charger insert/remove) EXTI -> immediate "c" refresh; see
     * product_charger_evt / product_status_tick. */
    RegisterChangerInsertCallback(product_charger_evt);
    /* One patient init (official-boot parity): TouchInit does reset ->
     * 300 ms settle -> probe -> configure, with a write-and-verify config.
     * The extra TouchOpen() that used to run here added a second reset with
     * an immediate I2C config - inside the chip's post-reset init window -
     * matching the "first tap after boot is swallowed" report. TouchOpen is
     * the wake-path re-open (low_power.c upstream); boot needs one clean init. */
    TouchInit(NULL);
    printf("touch probe: addr=0x%02X ok=%d\r\n",
           g_touch_probe_addr, g_touch_probe_ok);

    power_button_init();

    UiInit();
    UiSetInputPoll(product_touch_poll);
    UiShow();
    printf("ui: welcome page shown\r\n");

    /* ~1 s after reset the chip is fully settled: last chance to catch a
     * config that lost the race with the chip's own init (re-applies and
     * verifies; see drv_ft6336.c). */
    Ft6336BootVerify();

    uint32_t last_wdt = osKernelGetTickCount();
    uint32_t last_btn = osKernelGetTickCount();

    while (1) {
        product_status_tick();

        if (g_scan == SCAN_ACTIVE) {
            WDT_ReloadCounter();
            scan_step();
            osDelay(5);
        } else if (g_carousel == CAROUSEL_ACTIVE) {
            carousel_step();
        } else {
            UiTick();

            /* Task 5b: a live plate session outside the flow pages (SCAN /
             * SIGN / CONFIRM) means the flow exited -- the key dies here
             * (the sign-done and confirm-reject legs close through the same
             * teardown). The page-set condition closes the same-tick
             * WELCOME->QR gap a page==WELCOME check would miss (a rapid
             * second tap could otherwise carry a live session into the
             * carousel); CONFIRM is exempt because the -23 recovery keeps
             * the old session live across a second plate's confirm page.
             * Task 8: this leg is for PLATE sessions only - an SE unlock is
             * not flow-owned (it lives until 'se lock' or the sign-done
             * close), so it survives UI navigation. Phase 4: a console
             * 'key new' wallet session is not flow-owned either (same
             * lifetime). */
            if (UiGetPage() != UI_PAGE_QR) {
                /* g_pairing_qr is only meaningful while the pairing output
                 * leg owns the QR page; drop it on any other page so a stale
                 * flag can never exempt a later non-pairing QR show. */
                g_pairing_qr = 0;
            }
            if (g_key_session != NULL && g_key_from_se == 0 && g_key_console == 0 &&
                UiGetPage() != UI_PAGE_SCAN &&
                UiGetPage() != UI_PAGE_SIGN && UiGetPage() != UI_PAGE_CONFIRM &&
                !(g_pairing_qr != 0 && UiGetPage() == UI_PAGE_QR)) {
                key_session_close();
                seed_plate_wipe();
                UiSetLast("key zeroized (exit)");
                UiGotoPage(UI_PAGE_WELCOME);    /* repaint the footer line */
            }
            if (UiGetPage() == UI_PAGE_SCAN && g_scan == SCAN_IDLE) {
                scan_enter();
            } else if (UiGetPage() == UI_PAGE_QR && g_carousel == CAROUSEL_IDLE) {
                carousel_enter();
            }
            if (UiGetPage() == UI_PAGE_CONFIRM) {
                seed_confirm_step();
            }
            if (UiGetPage() != UI_PAGE_SCAN && g_scan == SCAN_FAILED) {
                g_scan = SCAN_IDLE;     /* left the scan page; allow a retry */
            }
            if (UiGetPage() != UI_PAGE_QR && g_carousel == CAROUSEL_FAILED) {
                g_carousel = CAROUSEL_IDLE;     /* left the QR page; allow retry */
            }

            /* Task 8 dev console (se_smoke.c, UART0 line-buffered): 'se
             * unlock <password>' / 'se lock' drive the SE key session on the
             * g_key_session route. POLLED HERE ONLY (idle branch): the
             * scan/carousel loops are busy with hardware. The password
             * transits the serial console - development convenience; the
             * product entry is the P4 UI. */
            SeConsolePoll();

            osDelay(UI_POLL_MS);
        }

        uint32_t now = osKernelGetTickCount();
        if (now - last_btn >= BUTTON_CHECK_INTERVAL_MS) {
            last_btn = now;
            power_button_check();
        }
        if (now - last_wdt >= WDT_FEED_INTERVAL_MS) {
            last_wdt = now;
            WDT_ReloadCounter();
        }
    }
}

/* ---------------- gencache provisioning (BP+ generator tables) ---------------- */

/* The BP+ prove path needs the generator tables; on the device face
 * (no alloc-fallback) `BpPlusGenerators::new()` fails unless either the
 * persistence hook serves a flash blob or caller storage was provided
 * (shlosilo.h INV-2/3/4). Missing both makes PlusStatement::new return
 * None and lib.rs:265's expect panics - the 10-03 "signing crash" (the
 * panic task held the WDT feeder's CPU while High, so the watchdog also
 * reset the board; the hook replay now shows the panic instead).
 * Mirrors the smoke battery's provisioning (shlosilo_smoke_task.c):
 * gc hooks for the persisted blob (first sign pays the build+store,
 * later boots load it) + one emplacement storage set as the fallback. */

/* One provision per boot, before any sign. Buffers live forever (written
 * once at first generator use, read thereafter - the shlosilo.h contract). */
static uint8_t *g_gen_g;
static uint8_t *g_gen_h;
static uint8_t *g_gen_blob;

static void gencache_prepare(void)
{
    uint32_t g_sz = 0, h_sz = 0, b_sz = 0;

    if (g_gen_g != NULL) {
        return;     /* already provisioned this boot */
    }
    gc_flash_init();
    shlosilo_gen_cache_set_hooks(gc_load, gc_store);

    if (shlosilo_gencache_table_sizes(1, &g_sz, &h_sz, &b_sz) != 0 ||
        g_sz == 0 || g_sz > 2u * 1024u * 1024u ||
        h_sz == 0 || h_sz > 2u * 1024u * 1024u ||
        b_sz > 4u * 1024u * 1024u) {
        printf("gencache: sizes probe failed/insane (%u/%u/%u)\r\n",
               (unsigned)g_sz, (unsigned)h_sz, (unsigned)b_sz);
        return;     /* sign will fail with a diagnosable error */
    }
    g_gen_g = (uint8_t *)PsramMalloc(g_sz);
    g_gen_h = (uint8_t *)PsramMalloc(h_sz);
    g_gen_blob = (uint8_t *)PsramMalloc(b_sz);
    if (g_gen_g == NULL || g_gen_h == NULL || g_gen_blob == NULL) {
        printf("gencache: table alloc fail (%u/%u/%u)\r\n",
               (unsigned)g_sz, (unsigned)h_sz, (unsigned)b_sz);
        ExtFree(g_gen_g);
        ExtFree(g_gen_h);
        ExtFree(g_gen_blob);
        g_gen_g = g_gen_h = g_gen_blob = NULL;
        return;
    }
    int32_t rc = shlosilo_gencache_provide_table(1, g_gen_g, &g_sz,
                                                 g_gen_h, &h_sz,
                                                 g_gen_blob, &b_sz);
    printf("gencache: provide rc=%d (g=%u h=%u blob=%u)\r\n",
           (int)rc, (unsigned)g_sz, (unsigned)h_sz, (unsigned)b_sz);
}

/* ---------------- sign session (product XMR sign, A) ---------------- */

/* Verification key material: mirrors the smoke battery's idx12 fixture
 * (shlosilo_smoke_task.c; also xmr_device_peak_fixture.rs SMOKE_IDX12) and
 * the fixed 0x77x32 entropy, so the product-run signature is byte-comparable
 * with the smoke anchor. Real key provisioning + TRNG entropy are P4/P5. */
static const uint16_t k_sign_idx12[12] = {
    136, 1092, 546, 273, 136, 1092, 546, 273, 136, 1092, 546, 283
};
#define SIGN_ENTROPY_LEN          32
#define SIGN_OUT_MAX              (8 * 1024)
/* MULTIPART_PAYLOAD_MAX_LEN: the R3 reassembly budget. */
#define UR_PAYLOAD_MAX            (16 * 1024)

/* Multipart UR intake (QR flow into the sign page): the R3 decoder session
 * lives from the first scanned frame to completion/abort. */
static struct UrMultipartDecoder *g_ur_dec = NULL;
static uint8_t *g_ur_dec_ws = NULL;
static uint8_t *g_ur_payload = NULL;
static char g_ur_type[32];
/* Collection metrics for the real-wallet acceptance (pool 1-3: collect and
 * decode a real dynamic-UR animation within 15-20 s). Timed from the first
 * fed frame to reassembly complete; fed/dup counts expose the scan cadence. */
static uint32_t g_ur_t0_ms;
static unsigned g_ur_feed_cnt;
static unsigned g_ur_dup_cnt;
static unsigned g_ur_collect_ms;

/* Sign result (feeds the output carousel on the QR page). */
static uint8_t *g_sign_out = NULL;
static unsigned g_sign_out_len = 0;
static char g_sign_out_type[32] = "bytes";

/* ---------------- seed import (Task 5b): scan branch -> confirm -> key session ---------------- */

/* Seed-QR scan-flow classes (shlosilo_seed_qr_probe_ffi return codes). */
#define SEED_CLASS_NOTSEED        0
#define SEED_CLASS_STANDARD12     1
#define SEED_CLASS_STANDARD24     2
#define SEED_CLASS_COMPACT12      3
#define SEED_CLASS_COMPACT24      4
#define SEED_CLASS_UR             5
#define KEY_ERR_SLOT_OCCUPIED     (-23)
#define KEY_ERR_BUFFER_TOO_SMALL  (-20)
#define KEY_ERR_AUTH_FAILED       (-24)

/* The scanned plate bytes, held between scan and the confirmation decision
 * (the open call needs them; the plate itself is at most 96 bytes - the
 * budget here is pure slack). */
#define SEED_PLATE_MAX            1024
static uint8_t g_seed_plate[SEED_PLATE_MAX];
static unsigned g_seed_plate_len;

/* Wipe the staged plate bytes (they are raw entropy carriers). Called at
 * every terminal exit of the seed flow (confirm reject/continue, open
 * failure, flow exit) -- NOT from the -23 recovery leg, which re-reads the
 * plate for the reopen. Volatile walk defeats dead-store elimination. */
static void seed_plate_wipe(void)
{
    volatile uint8_t *p = g_seed_plate;
    unsigned i;
    for (i = 0; i < sizeof(g_seed_plate); i++) {
        p[i] = 0;
    }
    g_seed_plate_len = 0;
}

/* Key-source workspace (shlosilo_keysource_qr_ws_len() /
 * shlosilo_keysource_se_ws_len() bytes - one shared layout, Task 8): caller-
 * pinned static storage - BSS-zeroed at boot (the REQUIRED initial state),
 * stable address for the self-referential handle (shlosilo.h contract).
 * Sized generously at compile time and checked against the runtime query
 * before first use (contract 3: the query is the single layout source).
 * Shared by the QR plate flow and the SE unlock flow: one live session per
 * workspace (an open on a busy workspace answers -23). */
#define KEY_WS_MAX             4096
static uint8_t g_key_ws[KEY_WS_MAX];

/* ---- Phase 4 acceptance ②: wallet staging ('key new' / 'key plate') ----
 *
 * The dev-console wallet-create + SeedQR plate-export face (the product UI
 * face is P4). Interface detail §2: EXPORT is deliberately not part of the
 * KeySource trait (import-only) — this is a separate output face built on
 * the plate-export FFI (shlosilo_seed_qr_encode_ffi, stack-buffer encoders)
 * plus the QR display face (UiShowPlateQr).
 *
 * The staging area holds the generated wallet's raw BIP-39 entropy in the
 * clear — plaintext-equivalent key material. Zeroization discipline is the
 * same as the plate scan flow: volatile wipe at EVERY teardown leg
 * (key_session_close below covers se lock / sign-done / flow exit), and the
 * bytes are never printed except by the explicit 'se dump' forensics. */
#define KEY_WALLET_MAX         32
static uint8_t g_key_wallet[KEY_WALLET_MAX];
static unsigned g_key_wallet_len;

/* Volatile walk (dead-store-elimination-proof — seed_plate_wipe idiom). */
static void key_wallet_wipe(void)
{
    volatile uint8_t *p = g_key_wallet;
    unsigned i;
    for (i = 0; i < sizeof(g_key_wallet); i++) {
        p[i] = 0;
    }
    g_key_wallet_len = 0;
}
/* The live session pointer from shlosilo_keysource_qr_open_ffi /
 * shlosilo_keysource_se_open_ffi - valid until the matching close. NULL = no
 * session (old sign path runs). SE sessions and QR sessions ride this SAME
 * sign route. */
static const struct KeySession *g_key_session = NULL;

static const char *seed_class_name(int cls)
{
    switch (cls) {
    case SEED_CLASS_STANDARD12: return "standard seed - 12 words";
    case SEED_CLASS_STANDARD24: return "standard seed - 24 words";
    case SEED_CLASS_COMPACT12:  return "compact seed - 12 words";
    case SEED_CLASS_COMPACT24:  return "compact seed - 24 words";
    default:                    return "seed plate";
    }
}

/* Close (zeroize) the live key session, whichever source opened it (Task 8:
 * the QR and SE glue entries share ONE teardown - see flux/keysource
 * ws.rs). The glue's close is total and idempotent, so calling it on a quiet
 * workspace is a defined no-op - it is also the single teardown used by every
 * exit leg (sign done, confirm reject, flow exit to welcome, se lock). Both
 * close entries run over the shared workspace: they are the same function
 * inside, the second call is the idempotent no-op. */
static void key_session_close(void)
{
    if (g_key_session != NULL) {
        printf("seed: key session closed (zeroized)\r\n");
    }
    /* The glue's close is total for a non-NULL ws (only ws==NULL errs), so
     * the pointer dies unconditionally -- never keep a stale session. */
    (void)shlosilo_keysource_qr_close_ffi(g_key_ws);
    (void)shlosilo_keysource_se_close_ffi(g_key_ws);
    g_key_session = NULL;
    g_key_from_se = 0;
    g_key_console = 0;
    /* The plate QR scratch regions are plaintext-equivalent carriers too:
     * the single teardown funnel wipes them on every exit leg. */
    UiWipePlateQr();
    /* Phase 4: the generated wallet dies with the session (same teardown
     * discipline — one key-bearing state, one close). */
    key_wallet_wipe();
}

/* ---- Task 8: SE password unlock -> signing session ----
 *
 * v1 entry is the dev console ('se unlock <password>', se_smoke.c): the
 * password transits the serial console - DEVELOPMENT CONVENIENCE ONLY, the
 * product entry is the P4 UI. The unlocked session rides the SAME
 * g_key_session sign route as the plate flow (one route, two sources).
 * v1 account scope: account 0 (FindAccountByPassword is not ported yet -
 * multi-account unlock rides that port). */

/* err_code.h ERR_KEYSTORE_AUTH pins the Rust-side constant in
 * flux/keysource/src/keysource/se.rs (the AuthFailed mapping). */
_Static_assert(ERR_KEYSTORE_AUTH == 20, "se.rs ERR_KEYSTORE_AUTH drift");

int ProductKeySeUnlock(const char *password)
{
    unsigned ws_need;
    int rc;

    if (password == NULL || password[0] == '\0') {
        return KEY_ERR_AUTH_FAILED;
    }
    if (g_key_session != NULL) {
        /* Unlock while unlocked = Capacity (-23): refused BEFORE any
         * credential attempt. Close first ('se lock' or the flow close). */
        printf("se unlock: refused, session already live (se lock first)\r\n");
        return KEY_ERR_SLOT_OCCUPIED;
    }
    ws_need = shlosilo_keysource_se_ws_len();
    if (ws_need > KEY_WS_MAX) {
        printf("se unlock: ws query %u > static %u\r\n",
               ws_need, (unsigned)KEY_WS_MAX);
        return KEY_ERR_BUFFER_TOO_SMALL;
    }
    rc = shlosilo_keysource_se_open_ffi(g_key_ws, (unsigned)sizeof(g_key_ws),
                                        (const uint8_t *)password,
                                        (unsigned)strlen(password),
                                        &g_key_session);
    if (rc != 0 || g_key_session == NULL) {
        /* Wrong password is a plain refusal (rc=-24, one shot - the glue
         * never retries): report and leave no session behind. */
        printf("se unlock: FAIL rc=%d\r\n", rc);
        key_session_close();
        return rc;
    }
    g_key_from_se = 1;
    printf("se unlock: key session live (account 0)\r\n");
    return 0;
}

/* Console 'se lock': close (zeroize) the live session, whichever source
 * opened it - the shared teardown above. */
void ProductKeyLock(void)
{
    key_session_close();
}

/* ---- Phase 4 acceptance ②: 'key new' / 'key plate' (dev console) ---- */

/* 'key new [12|24]': generate a fresh wallet from the on-chip TRNG.
 * Entropy (16/32 bytes) -> BIP-39 Mnemonic derivation + validation through
 * the plate-export FFI (forms 件; the checksum is derived at from_entropy and
 * re-verified on encode), staged in g_key_wallet, then round-tripped through
 * the SAME import path a scanned plate takes (shlosilo_keysource_qr_open_ffi)
 * so the wallet is immediately sign-capable and the export->import loop is
 * exercised on device. Returns 0 ok, -1 usage, -2 ws too small, else FFI rc. */
int ProductKeyNew(const char *arg)
{
    unsigned ws_need, ent_len = 32, plate_len = 0;
    uint8_t plate[96];
    int rc;

    if (arg != NULL && arg[0] != '\0') {
        if (strcmp(arg, "12") == 0) {
            ent_len = 16;
        } else if (strcmp(arg, "24") == 0) {
            ent_len = 32;
        } else {
            return -1;
        }
    }
    /* One wallet at a time: whatever was live dies first (zeroized). */
    key_session_close();

    TrngGet(g_key_wallet, ent_len);
    g_key_wallet_len = ent_len;

    /* Derive + validate through the export FFI (full BIP-39 path): a
     * generated wallet is proven plate-exportable from the start. The plate
     * bytes are transient here - wiped below at every exit. */
    rc = shlosilo_seed_qr_encode_ffi(SEED_QR_MODE_STANDARD,
                                     g_key_wallet, g_key_wallet_len,
                                     plate, sizeof(plate), &plate_len);
    if (rc != 0) {
        key_wallet_wipe();
        {
            volatile uint8_t *p = plate;
            unsigned i;
            for (i = 0; i < sizeof(plate); i++) {
                p[i] = 0;
            }
        }
        return rc;
    }
    ws_need = shlosilo_keysource_qr_ws_len();
    if (ws_need > KEY_WS_MAX) {
        printf("key new: ws query %u > static %u\r\n", ws_need, (unsigned)KEY_WS_MAX);
        {
            volatile uint8_t *p = plate;
            unsigned i;
            for (i = 0; i < sizeof(plate); i++) {
                p[i] = 0;
            }
        }
        key_wallet_wipe();
        return -2;
    }
    /* Round-trip import: the generated plate goes through the same validated
     * open a scanned plate takes (the -23 recovery cannot trigger here - the
     * close above guarantees a free workspace). */
    rc = shlosilo_keysource_qr_open_ffi(g_key_ws, (unsigned)sizeof(g_key_ws),
                                        plate, plate_len, &g_key_session);
    {
        /* Transient plate copy dies here (volatile walk). */
        volatile uint8_t *p = plate;
        unsigned i;
        for (i = 0; i < sizeof(plate); i++) {
            p[i] = 0;
        }
    }
    if (rc != 0 || g_key_session == NULL) {
        printf("key new: open failed rc=%d\r\n", rc);
        key_wallet_wipe();
        return (rc != 0) ? rc : -3;
    }
    g_key_from_se = 0;
    g_key_console = 1;
    printf("key new: wallet live (%u words), session open\r\n",
           (ent_len == 16) ? 12u : 24u);
    return 0;
}

/* 'key plate [standard|compact]': render the staged wallet as a SeedQR QR on
 * the screen (standard = 48/96 %04d digits, compact = 16/32 raw entropy -
 * the SeedSigner plate family). Returns 0 ok, -1 usage, -2 no wallet, else
 * FFI rc. The payload is wiped after render; the SCREEN is the exposure. */
int ProductKeyPlate(const char *mode)
{
    uint8_t payload[96];
    unsigned len = 0;
    int compact = 0;
    int rc;

    if (mode != NULL && mode[0] != '\0') {
        if (strcmp(mode, "compact") == 0) {
            compact = 1;
        } else if (strcmp(mode, "standard") != 0) {
            return -1;
        }
    }
    if (g_key_wallet_len != 16 && g_key_wallet_len != 32) {
        return -2;
    }
    rc = shlosilo_seed_qr_encode_ffi(compact ? SEED_QR_MODE_COMPACT
                                             : SEED_QR_MODE_STANDARD,
                                     g_key_wallet, g_key_wallet_len,
                                     payload, sizeof(payload), &len);
    if (rc != 0) {
        /* Belt: the FFI writes nothing on error, but every terminal leg
         * wipes the payload buffer (same discipline as the success leg). */
        volatile uint8_t *p = payload;
        unsigned i;
        for (i = 0; i < sizeof(payload); i++) {
            p[i] = 0;
        }
        return rc;
    }
    UiShowPlateQr(payload, len);
    /* The QR symbol is on screen now - the payload copy dies here. */
    {
        volatile uint8_t *p = payload;
        unsigned i;
        for (i = 0; i < sizeof(payload); i++) {
            p[i] = 0;
        }
    }
    printf("key plate: %s SeedQR shown (%u bytes)\r\n",
           compact ? "compact" : "standard", len);
    return 0;
}

/* 'se dump' forensics (Phase 4 acceptance ③): hexdump the keysource ws
 * window - the raw bytes the workspace holds. BEFORE close the window shows
 * live key bytes; AFTER close it must read ALL ZERO (ws.rs ws_close wipes
 * the whole window). Prints key material to the serial console BY DESIGN -
 * the warning is in RunDump (se_smoke.c), and the dump is the acceptance
 * evidence for the zeroization claim. */
void ProductKeyWsDump(void)
{
    static const char hexd[] = "0123456789ABCDEF";
    unsigned n = shlosilo_keysource_qr_ws_len();
    unsigned i;

    if (n > KEY_WS_MAX) {
        n = KEY_WS_MAX;
    }
    printf("se dump: ws window %u bytes, session %s\r\n", n,
           (g_key_session != NULL) ? "LIVE" : "closed");
    for (i = 0; i < n; i += 16) {
        char hex[2 * 16 + 1];
        unsigned chunk = (n - i < 16) ? (n - i) : 16;
        unsigned j;
        for (j = 0; j < chunk; j++) {
            hex[2 * j] = hexd[g_key_ws[i + j] >> 4];
            hex[2 * j + 1] = hexd[g_key_ws[i + j] & 0xF];
        }
        hex[2 * chunk] = '\0';
        printf("  %04X: %s\r\n", i, hex);
    }
    printf("se dump: wallet staging %u bytes%s\r\n", g_key_wallet_len,
           (g_key_wallet_len == 0) ? " (wiped)" : "");
    for (i = 0; i < g_key_wallet_len; i += 16) {
        char hex[2 * 16 + 1];
        unsigned chunk = (g_key_wallet_len - i < 16) ? (g_key_wallet_len - i) : 16;
        unsigned j;
        for (j = 0; j < chunk; j++) {
            hex[2 * j] = hexd[g_key_wallet[i + j] >> 4];
            hex[2 * j + 1] = hexd[g_key_wallet[i + j] & 0xF];
        }
        hex[2 * chunk] = '\0';
        printf("  %04X: %s\r\n", i, hex);
    }
    /* Acceptance forensics: the plate QR scratch regions (payload buffer,
     * codeword buffer, framebuffer) were the blind spot of the ws-only view.
     * Count only -- the bytes themselves never print. Expect 0 after close. */
    printf("qr scratch residue: %u nonzero bytes\r\n",
           (unsigned)UiPlateQrResidueCount());
}

/* Confirm-page handler (product loop, while the page is up):
 * continue -> open the key session from the scanned bytes and resume
 * scanning; back -> reject (close if any) and resume scanning. */
static void seed_confirm_step(void)
{
    char msg[48];
    unsigned ws_need;
    int rc;

    rc = UiConfirmDecision();
    if (rc == 0) {
        return;
    }
    if (rc < 0) {
        /* back / reject: close ANY live session (idempotent) + rescan. */
        printf("seed: rejected -> close + rescan\r\n");
        key_session_close();
        seed_plate_wipe();
        UiSetLast("seed rejected");
        UiGotoPage(UI_PAGE_SCAN);
        return;
    }

    /* continue: open the session from the plate bytes still in hand (no
     * re-scan needed - the open runs full validation + BIP-39 checksum). */
    ws_need = shlosilo_keysource_qr_ws_len();
    if (ws_need > KEY_WS_MAX) {
        printf("seed: ws query %u > static %u\r\n",
               ws_need, (unsigned)KEY_WS_MAX);
        /* Same teardown semantics as reject: no session survives this leg. */
        key_session_close();
        seed_plate_wipe();
        UiSetLast("key ws too small");
        UiGotoPage(UI_PAGE_SCAN);
        return;
    }
    rc = shlosilo_keysource_qr_open_ffi(g_key_ws, (unsigned)sizeof(g_key_ws),
                                        g_seed_plate, g_seed_plate_len,
                                        &g_key_session);
    if (rc == KEY_ERR_SLOT_OCCUPIED) {
        /* Re-entry with a live session (confirm-continue on a second plate):
         * close the old session (zeroize) and reopen from the new scan
         * bytes - the sequence pinned by qr_ffi.rs
         * slot_occupied_recovery_close_then_reopen_yields_new_scan_keys. */
        printf("seed: slot occupied (-23) -> close old + reopen\r\n");
        key_session_close();
        rc = shlosilo_keysource_qr_open_ffi(g_key_ws, (unsigned)sizeof(g_key_ws),
                                            g_seed_plate, g_seed_plate_len,
                                            &g_key_session);
    }
    if (rc != 0 || g_key_session == NULL) {
        snprintf(msg, sizeof(msg), "seed open FAIL rc=%d", rc);
        printf("seed: open failed rc=%d\r\n", rc);
        key_session_close();
        seed_plate_wipe();
        UiSetLast(msg);
        UiGotoPage(UI_PAGE_SCAN);
        return;
    }
    printf("seed: key session live (plate %u bytes)\r\n", g_seed_plate_len);
    /* Plate consumed: the session holds the derived keys now. */
    seed_plate_wipe();
    UiSetLast("key session live");
    UiGotoPage(UI_PAGE_SCAN);
}

/* Seed-class scan hit (class 1-4): leave the scan session and put the
 * confirmation page in front of the key work (the probe is zero-key; the
 * decode + session only run on confirm-continue). */
static void scan_seed_confirm(int cls, unsigned n)
{
    scan_exit();
    if (n > sizeof(g_seed_plate)) {
        n = sizeof(g_seed_plate);   /* defensive; plates are <= 96 bytes */
    }
    memcpy(g_seed_plate, g_qr_result, n);
    g_seed_plate_len = n;
    /* The QR result buffer is the second plaintext copy of the plate: it
     * dies here (the staging buffer is the only copy from now on). Same
     * volatile walk as seed_plate_wipe -- a bare memset could in principle
     * be removed by whole-program DSE. */
    {
        volatile char *q = g_qr_result;
        unsigned qi;
        for (qi = 0; qi < sizeof(g_qr_result); qi++) {
            q[qi] = 0;
        }
    }
    printf("seed: class %d (%s), %u bytes -> confirm page\r\n",
           cls, seed_class_name(cls), n);
    UiSeedConfirmInfo(seed_class_name(cls), UI_TXT_CONFIRM_SRC);
    UiGotoPage(UI_PAGE_CONFIRM);
    /* The entry tap's contact may still be resting: need a fresh press. */
    g_touch_prev = 1;
}

static void ur_intake_reset(void)
{
    if (g_ur_dec != NULL) {
        shlosilo_ur_decode_free(g_ur_dec);
        g_ur_dec = NULL;
    }
    ExtFree(g_ur_dec_ws);
    g_ur_dec_ws = NULL;
    ExtFree(g_ur_payload);
    g_ur_payload = NULL;
}

/* Map the signed set to its output UR type: XMR travels back as the official
 * registry type (8304), everything else as opaque bytes. T5: the pairing
 * receive leg reuses the same mapping face -- an `xmr-output` request is
 * answered with the `xmr-keyimage` container (registry type for the key-image
 * export). */
static void sign_out_type_for(const char *in_type)
{
    if (strcmp(in_type, "xmr-output") == 0) {
        snprintf(g_sign_out_type, sizeof(g_sign_out_type), "xmr-keyimage");
    } else if (strcmp(in_type, "xmr-txunsigned") == 0 ||
        strcmp(in_type, "crypto-monero-tx") == 0) {
        snprintf(g_sign_out_type, sizeof(g_sign_out_type), "xmr-txsigned");
    } else if (strcmp(in_type, "crypto-psbt") == 0) {
        snprintf(g_sign_out_type, sizeof(g_sign_out_type), "crypto-psbt");
    } else {
        snprintf(g_sign_out_type, sizeof(g_sign_out_type), "bytes");
    }
}

/* device-timing clock callback (smoke parity: registers the ms source for
 * the Rust-side stage counters; weak no-op outside device-timing builds). */
static uint32_t product_tick_ms(void)
{
    return osKernelGetTickCount();
}

/* Run one sign on this task's stack: uri != NULL is the single-frame path
 * (shlosilo_sign_ur_ffi), otherwise the multipart path
 * (shlosilo_sign_typed_ffi over the reassembled (type, payload)). */
static void sign_run(const char *uri, const char *type,
                     const uint8_t *payload, unsigned plen)
{
    char l1[48], l2[48], l3[48], result[256];
    uint8_t entropy[SIGN_ENTROPY_LEN];
    unsigned ws_need = shlosilo_sign_ws_len();
    unsigned out_len = 0;
    uint32_t t0, dt;
    int rc;

    memset(entropy, 0x77, sizeof(entropy));

    if (g_sign_out != NULL) {
        ExtFree(g_sign_out);
        g_sign_out = NULL;
        g_sign_out_len = 0;
    }
    g_sign_out = (uint8_t *)ExtMalloc(SIGN_OUT_MAX);
    uint8_t *ws = (uint8_t *)ExtMalloc(ws_need);
    if (g_sign_out == NULL || ws == NULL) {
        printf("sign: ws alloc fail (out=%u ws=%u)\r\n",
               (unsigned)SIGN_OUT_MAX, ws_need);
        UiSetLast("sign: ws alloc fail");
        ExtFree(g_sign_out);
        g_sign_out = NULL;
        ExtFree(ws);
        UiGotoPage(UI_PAGE_WELCOME);
        return;
    }

    if (uri != NULL) {
        snprintf(l1, sizeof(l1), "single-frame ur");
        snprintf(l2, sizeof(l2), "request %u chars", (unsigned)strlen(uri));
    } else {
        snprintf(l1, sizeof(l1), "%s", type);
        snprintf(l2, sizeof(l2), "payload %u bytes", plen);
    }
    if (g_key_session != NULL) {
        snprintf(l3, sizeof(l3), "key: %s",
                 (g_key_from_se != 0) ? "se unlock"
                                      : ((g_key_console != 0) ? "key new" : "plate scan"));
    } else {
        snprintf(l3, sizeof(l3), "key: fixture idx12");
    }
    UiSignInfo(l1, l2, l3);
    UiGotoPage(UI_PAGE_SIGN);

    /* BP+ generator tables must be ready before the prove path runs
     * (missing storage = the lib.rs:265 statement panic, 10-03). */
    gencache_prepare();

    /* device-timing (smoke parity): register the ms clock + reset counters
     * so the stage readouts have a time source on device-timing builds. */
    shlosilo_timing_reset();
    shlosilo_timing_set_clock_fn(product_tick_ms);

    printf("sign: start (ws=%u) key=%s\r\n", ws_need,
           (g_key_session != NULL)
               ? ((g_key_from_se != 0) ? "se unlock"
                                       : ((g_key_console != 0) ? "key new" : "plate session"))
               : "fixture idx12");
    g_sign_busy = 1;
    t0 = osKernelGetTickCount();
    if (g_key_session != NULL) {
        /* Task 5b: live plate session -> the seed-less session entry (the
         * scanned key never crosses the FFI again). Routing guarantees a
         * typed (type, payload) pair here; a NULL type would be refused by
         * the entry itself (-2), never signed with a fallback key. */
        rc = shlosilo_sign_session_ffi(g_key_session, type, payload, plen,
                                      entropy, sizeof(entropy),
                                      g_sign_out, SIGN_OUT_MAX, &out_len,
                                      ws, ws_need);
    } else if (uri != NULL) {
        rc = shlosilo_sign_ur_ffi(uri, k_sign_idx12, 12, NULL, 0, 0,
                                  entropy, sizeof(entropy),
                                  g_sign_out, SIGN_OUT_MAX, &out_len,
                                  ws, ws_need);
    } else {
        rc = shlosilo_sign_typed_ffi(type, payload, plen,
                                     k_sign_idx12, 12, NULL, 0, 0,
                                     entropy, sizeof(entropy),
                                     g_sign_out, SIGN_OUT_MAX, &out_len,
                                     ws, ws_need);
    }
    dt = osKernelGetTickCount() - t0;
    g_sign_busy = 0;
    ExtFree(ws);

    /* Diagnostic footnote: stack high-water mark across the sign (the A
     * acceptance reading). HWM = minimum ever free stack in words. */
    {
        unsigned hwm_w = (unsigned)uxTaskGetStackHighWaterMark(NULL);
        unsigned used_k =
            (PRODUCT_TASK_STACK_BYTES - hwm_w * (unsigned)sizeof(StackType_t))
            / 1024u;
        printf("sign: rc=%d out=%u dt=%ums stk used ~%uK (hwm %uW)\r\n",
               rc, out_len, (unsigned)dt, used_k, hwm_w);
        if (rc == 0 && out_len > 0) {
            const char *in_type = type;
            char it_buf[32];
            if (uri != NULL) {
                /* "ur:<type>/..." -> <type> */
                const char *start = uri + 3;
                const char *end = strchr(start, '/');
                unsigned n = (end != NULL)
                    ? (unsigned)(end - start)
                    : (unsigned)strlen(start);
                if (n >= sizeof(it_buf)) {
                    n = sizeof(it_buf) - 1;
                }
                memcpy(it_buf, start, n);
                it_buf[n] = '\0';
                in_type = it_buf;
            }
            g_sign_out_len = out_len;
            sign_out_type_for(in_type);
            snprintf(result, sizeof(result),
                     "sign ok: %u bytes in %ums\nout type: %s\n"
                     "ur collect: %u fr (%u dup) in %u.%us\n"
                     "stk used ~%uK (hwm %uW of %uK)",
                     out_len, (unsigned)dt, g_sign_out_type,
                     g_ur_feed_cnt, g_ur_dup_cnt,
                     (unsigned)(g_ur_collect_ms / 1000u),
                     (unsigned)((g_ur_collect_ms / 100u) % 10u),
                     used_k, hwm_w,
                     (unsigned)(PRODUCT_TASK_STACK_BYTES / 1024u));
        } else {
            g_sign_out_len = 0;
            snprintf(result, sizeof(result),
                     "sign FAIL: rc=%d\ntype: %.16s len %u\n"
                     "head: %02x%02x%02x%02x %02x%02x%02x%02x\n"
                     "ur collect: %u fr (%u dup) in %u.%us\n"
                     "stk used ~%uK (hwm %uW of %uK)",
                     rc,
                     (uri != NULL) ? "single-frame" : g_ur_type,
                     plen,
                     (plen > 0) ? g_ur_payload[0] : 0u,
                     (plen > 1) ? g_ur_payload[1] : 0u,
                     (plen > 2) ? g_ur_payload[2] : 0u,
                     (plen > 3) ? g_ur_payload[3] : 0u,
                     (plen > 4) ? g_ur_payload[4] : 0u,
                     (plen > 5) ? g_ur_payload[5] : 0u,
                     (plen > 6) ? g_ur_payload[6] : 0u,
                     (plen > 7) ? g_ur_payload[7] : 0u,
                     g_ur_feed_cnt, g_ur_dup_cnt,
                     (unsigned)(g_ur_collect_ms / 1000u),
                     (unsigned)((g_ur_collect_ms / 100u) % 10u),
                     used_k, hwm_w,
                     (unsigned)(PRODUCT_TASK_STACK_BYTES / 1024u));
        }
        snprintf(l3, sizeof(l3), "stk used ~%uK", used_k);
        UiSetLast(l3);
    }

    /* Task 5b: sign done -> close (zeroize) -> back to the scan flow. The
     * plate key's job ends with the sign; the same teardown runs on every
     * exit leg (confirm reject / welcome housekeeping). */
    key_session_close();
    ur_intake_reset();
    if (g_sign_out_len > 0 &&
        strcmp(g_sign_out_type, "xmr-txsigned") == 0) {
        /* T5 beat 4: an XMR signed set goes straight to the QR carousel --
         * Cake's "scan QR code" step collects it (the rc/out/dt diagnostics
         * already went to the console above). The session is already closed
         * above, so the carousel's exit leg is a plain return to welcome. */
        printf("sign: done -> xmr-txsigned qr (result page skipped)\r\n");
        UiSetLast("signed - scan with Cake");
        UiGotoPage(UI_PAGE_QR);
        return;
    }
    printf("sign: done -> result page\r\n");
    UiSetPayload(result, (uint32_t)strlen(result));
}

/* ---------------- Cake pairing leg (T5): xmr-output -> xmr-keyimage ---------------- */

/* Beat 1->2 of the four-beat cold-sign flow: the Cake `xmr-output` receive
 * leg. The device answers Cake DIRECTLY -- key images + accompanying
 * signatures are computed through the seed-less session entry
 * (shlosilo_xmr_pairing_ffi; keys are borrowed from the live session, never
 * across the FFI), and the `xmr-keyimage` container goes onto the F3 QR
 * carousel for Cake's "scan QR code" step.
 *
 *   (1) scan Cake's xmr-output animation -> this function;
 *   (2) xmr-keyimage QR on the carousel (back tap -> back to scanning);
 *   (3) scan Cake's xmr-txunsigned animation -> sign_run;
 *   (4) xmr-txsigned QR on the carousel.
 *
 * Failure (any kind) = prompt + KEEP SCANNING: the frames cycle, so the next
 * animation round retries. There is NO fixture-key fallback on this leg (unlike
 * the sign face) -- a keyless device must not answer Cake at all. */
static void pairing_run(const uint8_t *payload, unsigned plen)
{
    char l3[40];
    uint8_t entropy[SIGN_ENTROPY_LEN];
    uint8_t *ws_raw = NULL;
    uint8_t *ws = NULL;
    unsigned ws_need = 0;
    unsigned out_len = 0;
    uint32_t t0, dt;
    int rc;

    if (g_key_session == NULL) {
        printf("pairing: no key session (payload %u), keep scanning\r\n", plen);
        UiScanInfo("pairing: need key", "no key session", "keep scanning...", "");
        ur_intake_reset();
        return;
    }

    /* Same §B.5 fixed stream as sign_run (byte-comparable with the smoke
     * anchor; real TRNG entropy is the P4/P5 provisioning item). */
    memset(entropy, 0x77, sizeof(entropy));

    /* Workspace requirement through the PURE PROBE (ws == NULL reports the
     * need in actual_len and touches nothing -- no key access, no parse). */
    rc = shlosilo_xmr_pairing_ffi(g_key_session, NULL, 0, NULL, 0,
                                  NULL, 0, &ws_need, NULL, 0);
    if (rc != 0 || ws_need == 0) {
        printf("pairing: ws probe fail rc=%d need=%u\r\n", rc, ws_need);
        UiScanInfo("pairing: ws probe FAIL", "keep scanning...", "", "");
        ur_intake_reset();
        return;
    }

    if (g_sign_out != NULL) {
        ExtFree(g_sign_out);
        g_sign_out = NULL;
        g_sign_out_len = 0;
    }
    g_sign_out = (uint8_t *)ExtMalloc(SIGN_OUT_MAX);
    /* The ws contract wants a u128-aligned base (the carve places the CN
     * scratch slot at u128 alignment relative to the base and the CN core
     * validates the ABSOLUTE address): over-allocate and align up; the free
     * below goes to the original block. */
    ws_raw = (uint8_t *)ExtMalloc(ws_need + 15u);
    if (ws_raw != NULL) {
        ws = (uint8_t *)(((uintptr_t)ws_raw + 15u) & ~(uintptr_t)15u);
    }
    if (g_sign_out == NULL || ws == NULL) {
        printf("pairing: alloc fail (out=%u ws=%u)\r\n",
               (unsigned)SIGN_OUT_MAX, ws_need);
        UiScanInfo("pairing: alloc FAIL", "keep scanning...", "", "");
        ExtFree(g_sign_out);
        g_sign_out = NULL;
        g_sign_out_len = 0;
        ExtFree(ws_raw);
        ur_intake_reset();
        return;
    }

    snprintf(l3, sizeof(l3), "key: %s",
             (g_key_from_se != 0) ? "se unlock"
                                  : ((g_key_console != 0) ? "key new" : "plate scan"));
    UiScanInfo("pairing: output received", "-> key images ready",
               "computing key images", l3);
    printf("pairing: start (payload=%u ws=%u)\r\n", plen, ws_need);
    t0 = osKernelGetTickCount();
    rc = shlosilo_xmr_pairing_ffi(g_key_session, payload, plen,
                                  entropy, sizeof(entropy),
                                  g_sign_out, SIGN_OUT_MAX, &out_len,
                                  ws, ws_need);
    dt = osKernelGetTickCount() - t0;
    ExtFree(ws_raw);
    if (rc != 0 || out_len == 0 || out_len > SIGN_OUT_MAX) {
        printf("pairing: FAIL rc=%d out=%u dt=%ums\r\n", rc, out_len, (unsigned)dt);
        UiScanInfo("pairing: FAIL", "keep scanning...", "", "");
        ExtFree(g_sign_out);
        g_sign_out = NULL;
        g_sign_out_len = 0;
        ur_intake_reset();
        return;     /* still on the scan page: intake restarts fresh */
    }

    printf("pairing: ok %u bytes in %ums -> xmr-keyimage qr\r\n",
           out_len, (unsigned)dt);
    g_sign_out_len = out_len;
    sign_out_type_for("xmr-output");    /* -> xmr-keyimage */
    ur_intake_reset();

    /* Beat 2: the key-image QR rides the F3 carousel. The QR page is
     * flow-owned while this leg is showing (g_pairing_qr): the exit gate must
     * not kill the plate session underneath it -- the sign request is beat 3.
     * A real exit is the back tap in the carousel (-> scan page) or from the
     * scan page (-> welcome, where the gate tears the session down). */
    scan_exit();
    g_pairing_qr = 1;
    UiSetLast("key images ready - scan with Cake");
    UiGotoPage(UI_PAGE_QR);
}

/* Decode a single-frame `ur:` into (g_ur_type, g_ur_payload). Returns 0 on
 * success (payload length through plen_out), non-zero on failure (nothing is
 * kept; the caller keeps scanning). */
static int ur_single_decode(const char *text, unsigned *plen_out)
{
    unsigned plen = 0;

    if (g_ur_payload == NULL) {
        g_ur_payload = (uint8_t *)ExtMalloc(UR_PAYLOAD_MAX);
    }
    if (g_ur_payload == NULL) {
        printf("ur: single-frame payload alloc fail\r\n");
        UiScanInfo("ur: payload alloc FAIL", "", "", "");
        return -1;
    }
    if (shlosilo_ur_decode_uri_ffi(text, (uint8_t *)g_ur_type,
                                  (unsigned)sizeof(g_ur_type),
                                  g_ur_payload, UR_PAYLOAD_MAX,
                                  &plen) != 0) {
        printf("ur: single-frame decode FAIL\r\n");
        UiScanInfo("ur: decode FAIL", "not a sign request?", "", "");
        ExtFree(g_ur_payload);
        g_ur_payload = NULL;
        return -1;
    }
    *plen_out = plen;
    return 0;
}

/* Sign-face type whitelist, shared by the single-frame and multipart
 * dispatch: only these types reach sign_run. Every other collected type
 * (the Cake exchange legs -- xmr-output is routed to pairing_run earlier,
 * xmr-keyimage is a device-OUT leg -- and anything unknown) is
 * prompt + keep scanning: the typed sign FFI refuses foreign types, and
 * the sign FAIL leg closes the plate session underneath -- a session
 * must survive a stray exchange-leg QR (spec: 提示 + 续扫). */
static int ur_type_is_sign(const char *type)
{
    return strncmp(type, "xmr-txunsigned", 14) == 0 ||
           strncmp(type, "crypto-monero-tx", 16) == 0 ||
           strncmp(type, "crypto-psbt", 11) == 0 ||
           strncmp(type, "eth-sign-request", 16) == 0;
}

/* Bug A (2026-10-09): the legacy fixture-key sign path (k_sign_idx12) used to
 * be the silent FALLBACK whenever a sign UR was scanned with NO session --
 * the device signed with the smoke-anchor fixture key and the wallet rejected
 * the result (Cake rc=-21, wrong key). No-session sign requests now prompt
 * "import a wallet first / 请先扫盘导入" + keep scanning.
 *
 * The legacy path is preserved as an EXPLICIT one-shot entry instead: the
 * smoke/acceptance anchor run ('sign fixture' dev console, se_smoke.c) arms
 * it, the next sign UR signs with the fixture key exactly as before
 * (byte-parity with the smoke anchor), then the arm clears. Off by default,
 * never a fallback. */
static int g_fixture_sign_ok;

/* 'sign fixture' (dev console): arm the one-shot legacy fixture-key sign. */
int ProductSignFixtureArm(void)
{
    g_fixture_sign_ok = 1;
    printf("sign: fixture arm SET (next sign UR -> idx12 fixture key)\r\n");
    return 0;
}

/* No-session sign request: prompt + keep scanning (spec: 提示 + 续扫). Shared
 * copy with the multipart completion leg so the two prompts cannot drift. */
static void no_session_prompt(void)
{
    printf("ur: sign request without session -> import first (keep scanning)\r\n");
    UiScanInfo("import a wallet first", "请先扫盘导入", "keep scanning...", "");
}

/* One scanned frame that starts with "ur:". Single-part frames sign right
 * away; multipart frames accumulate through the R3 fountain decoder until the
 * message completes, then sign the reassembled (type, payload). */
static void scan_ur_hit(const char *text)
{
    const char *slash1 = strchr(text, '/');
    const char *slash2 = (slash1 != NULL) ? strchr(slash1 + 1, '/') : NULL;
    char l3[40];
    unsigned accepted = 0;
    unsigned ws_need;
    int progress;

    if (slash2 == NULL && strncmp(text, "ur:xmr-output", 13) == 0) {
        /* T5 beat 1 (single-frame form): a Cake pairing request. Decode the
         * (type, payload) pair and answer the pairing leg -- the session
         * check lives inside pairing_run, so a keyless device prompts and
         * keeps scanning instead of falling into the fixture sign path.
         * Prefix is 13 chars ("ur:xmr-output") so the slash-less form is
         * covered too -- anything that claims to be xmr-output must never
         * reach the fixture sign path (no fixture fallback on this leg). */
        unsigned plen = 0;
        if (ur_single_decode(text, &plen) == 0) {
            printf("ur: single-frame type=%s payload=%u (pairing)\r\n",
                   g_ur_type, plen);
            pairing_run(g_ur_payload, plen);
        }
        return;
    }
    if (slash2 == NULL && g_key_session == NULL) {
        /* Bug A (2026-10-09): no session -> never fall silently into the
         * legacy fixture-key sign path (wrong key, wallet rejects rc=-21).
         * Prompt + keep scanning. The legacy path survives ONLY behind the
         * explicit one-shot 'sign fixture' arm (smoke/acceptance anchor). */
        if (g_fixture_sign_ok) {
            g_fixture_sign_ok = 0;      /* one-shot */
            scan_exit();
            sign_run(text, NULL, NULL, 0);
            return;
        }
        no_session_prompt();
        return;
    }
    if (slash2 == NULL) {
        /* Task 5b: single-frame request with a LIVE plate session. The
         * session sign face is typed-only and the fountain decoder rejects
         * single frames ("single frames go through ur_decode::decode"), so
         * extract (type, payload) through shlosilo_ur_decode_uri_ffi and run
         * the typed session sign on the pair. */
        unsigned plen = 0;
        if (ur_single_decode(text, &plen) == 0) {
            printf("ur: single-frame type=%s payload=%u (session sign)\r\n",
                   g_ur_type, plen);
            if (!ur_type_is_sign(g_ur_type)) {
                /* Exchange legs (xmr-keyimage, ...) and unknown types: the
                 * typed sign FFI would refuse and the FAIL leg closes the
                 * plate session underneath. Prompt + keep scanning instead
                 * so the session survives until the sign request shows up. */
                char l1[48];
                snprintf(l1, sizeof(l1), "collected %.16s", g_ur_type);
                printf("ur: non-sign single frame, keep scanning\r\n");
                UiScanInfo(l1, "not a sign request", "keep scanning...", "");
                ur_intake_reset();
                return;
            }
            scan_exit();
            sign_run(NULL, g_ur_type, g_ur_payload, plen);
        }
        return;
    }

    if (g_ur_dec == NULL) {
        ws_need = shlosilo_ur_decode_ws_len();
        g_ur_dec_ws = (uint8_t *)ExtMalloc(ws_need);
        g_ur_payload = (uint8_t *)ExtMalloc(UR_PAYLOAD_MAX);
        if (g_ur_dec_ws == NULL || g_ur_payload == NULL) {
            printf("ur: intake ws alloc fail (%u)\r\n", ws_need);
            UiScanInfo("ur: ws alloc fail", "", "", "");
            ur_intake_reset();
            return;
        }
        g_ur_dec = shlosilo_ur_decode_new(g_ur_dec_ws, ws_need);
        if (g_ur_dec == NULL) {
            printf("ur: decoder init fail\r\n");
            UiScanInfo("ur: decoder fail", "", "", "");
            ur_intake_reset();
            return;
        }
        printf("ur: multipart intake start (ws=%u)\r\n", ws_need);
        g_ur_t0_ms = osKernelGetTickCount();
        g_ur_feed_cnt = 0;
        g_ur_dup_cnt = 0;
        g_ur_collect_ms = 0;
        UiScanProgress(0);
    }

    if (shlosilo_ur_decode_feed(g_ur_dec, text, &accepted) != 0) {
        /* A rejected frame means it does not belong to the current session:
         * a message switch (the wallet UI toggles between two different
         * URs - e.g. Cake's Outputs(all)/(partial) - same type, different
         * checksum) or a malformed frame. Either way the session is stale;
         * reset so the next frame starts fresh instead of wedging the
         * intake on the old message forever. Frames cycle, so at most one
         * animation round is lost. */
        printf("ur: frame rejected (accepted=%u), session reset\r\n", accepted);
        UiScanInfo("ur multipart", "frame rejected", "session reset", "");
        ur_intake_reset();
        return;
    }
    g_ur_feed_cnt++;
    if (!accepted) {
        g_ur_dup_cnt++;
    }
    progress = shlosilo_ur_decode_progress(g_ur_dec);
    /* Diagnostic (stagenet UR hunt): show the frag-seq slot of the frame
     * just fed ("S1-11".."S24-11") -- photos of this line prove whether the
     * fed texts repeat (capture stickiness) or cycle (intake bug). */
    snprintf(l3, sizeof(l3), "fr %u dup %u S%.*s", g_ur_feed_cnt, g_ur_dup_cnt,
             (int)(slash2 - (slash1 + 1)), slash1 + 1);
    UiScanInfo("ur multipart", "collecting frames", l3, "");
    UiScanProgress((uint8_t)progress);

    if (!shlosilo_ur_decode_complete(g_ur_dec)) {
        return;
    }

    {
        unsigned tlen = 0, plen = 0;
        if (shlosilo_ur_decode_type(g_ur_dec, (uint8_t *)g_ur_type,
                                    sizeof(g_ur_type), &tlen) != 0 ||
            shlosilo_ur_decode_payload(g_ur_dec, g_ur_payload,
                                       UR_PAYLOAD_MAX, &plen) != 0) {
            printf("ur: complete but extract fail (t=%u p=%u)\r\n", tlen, plen);
            UiScanInfo("ur: extract FAIL", "", "", "");
            ur_intake_reset();
            return;
        }
        printf("ur: complete type=%s payload=%u\r\n", g_ur_type, plen);
        g_ur_collect_ms = osKernelGetTickCount() - g_ur_t0_ms;
        printf("ur: collected in %u ms (%u fr, %u dup)\r\n",
               (unsigned)g_ur_collect_ms, g_ur_feed_cnt, g_ur_dup_cnt);
        if (strncmp(g_ur_type, "xmr-output", 10) == 0) {
            /* T5 beat 1: Cake's output export -- the device answers the
             * pairing leg directly (xmr-keyimage QR out). Session check and
             * every failure prompt live inside pairing_run. */
            pairing_run(g_ur_payload, plen);
            return;
        }
        if (!ur_type_is_sign(g_ur_type)) {
            /* Real-wallet flows animate exchange legs first (xmr-output,
             * xmr-keyimage, ...) which need key material this device does
             * not hold. Collect, report, and KEEP SCANNING so the sign
             * request (xmr-txunsigned) is caught whenever it appears. */
            char l1[48], l2[48];
            snprintf(l1, sizeof(l1), "collected %.16s", g_ur_type);
            snprintf(l2, sizeof(l2), "not a sign request");
            printf("ur: non-sign type, keep scanning\r\n");
            UiScanInfo(l1, l2, "keep scanning...", "");
            ur_intake_reset();
            return;
        }
        if (g_key_session == NULL) {
            /* Bug A (2026-10-09): same no-session guard on the multipart
             * completion leg -- a reassembled sign request must never fall
             * into the legacy fixture-key path (wrong key, rc=-21). Prompt +
             * reset the intake + keep scanning; the explicit one-shot
             * 'sign fixture' arm keeps the smoke/acceptance anchor reachable. */
            if (g_fixture_sign_ok) {
                g_fixture_sign_ok = 0;  /* one-shot */
                scan_exit();
                sign_run(NULL, g_ur_type, g_ur_payload, plen);
                return;
            }
            no_session_prompt();
            ur_intake_reset();
            return;
        }
        scan_exit();
        sign_run(NULL, g_ur_type, g_ur_payload, plen);
    }
}

/* ---------------- scan session ---------------- */

/* D2.4 experiment (2026-09-18): DECODE POOL IN SRAM.
 *
 * The official firmware hands the decode library the LVGL gram buffer in
 * SRAM (480x450x2B = 432,000 B); our integration used a PSRAM pool. With the
 * PSRAM pool the library runs ~11x slower (measured: dec 568 ms/frame vs the
 * official 49 ms on the same device) and never decodes a code - every pass
 * of the analyser (binarization, region labelling, pattern search) is a
 * random-access-heavy workload, and QSPI PSRAM latency makes that crawl.
 * Same library, same camera, same board: the pool memory is the difference.
 *
 * This build replicates the official memory situation: the 410 KiB pool is
 * placed in the free SRAM window after .bss. The K2-D Rust pool section
 * (0x20099000..0x200FC000) is unused in the product flavor (no FFI calls
 * reach the Rust allocator), so the window is genuinely free *for this
 * build*; the start address is guarded against .bss growth at runtime.
 *
 * Set to 0 to fall back to the PSRAM pool (A/B switch). */
#define QR_POOL_IN_SRAM     1
#define QR_POOL_SRAM_ADDR   0x20084000u   /* after .bss, ends 0x200EA800 < data_parser */

static void scan_enter(void)
{
    char l1[40];

    if (g_qr_pool == NULL) {
#if QR_POOL_IN_SRAM
        extern uint8_t _ebss;
        if ((uint32_t)&_ebss > QR_POOL_SRAM_ADDR) {
            /* .bss grew into the reserved window: pool placement is stale. */
            printf("scan: sram pool guard hit (ebss=%08X)\r\n",
                   (unsigned)(uint32_t)&_ebss);
            UiScanInfo("sram pool guard", "bss overlap", "", "");
            g_scan = SCAN_FAILED;
            return;
        }
        g_qr_pool = (uint8_t *)QR_POOL_SRAM_ADDR;
        printf("scan: pool @ %08X (SRAM experiment)\r\n",
               (unsigned)(uint32_t)g_qr_pool);
#else
        g_qr_pool = ExtMalloc(QR_POOL_BYTES);
        if (g_qr_pool == NULL) {
            printf("scan: pool alloc failed\r\n");
            UiScanInfo("pool alloc FAIL", "410K psram", "", "");
            g_scan = SCAN_FAILED;
            return;
        }
        printf("scan: pool @ %08X (PSRAM)\r\n", (unsigned)(uint32_t)g_qr_pool);
#endif
    }

#if QR_POOL_IN_SRAM
    /* SRAM window handoff: the K2-D Rust pool lives inside the decode
     * pool's address range (the two are time-shared; see
     * shlosilo/embedded_alloc_glue.c). Never start the decoder while Rust
     * allocations are live in the window. */
    if (shlosilo_sram_pool_live_bytes() != 0) {
        printf("scan: sram pool busy (%u live bytes)\r\n",
               (unsigned)shlosilo_sram_pool_live_bytes());
        UiScanInfo("sram busy", "rust allocs live", "", "");
        g_scan = SCAN_FAILED;
        return;
    }
#endif

    UiScanInfo("camera init...", "", "", "");
    WDT_ReloadCounter();
    int32_t ret = QrDecodeInit(g_qr_pool);
    if (ret != DecodeInitSuccess) {
        printf("scan: QrDecodeInit ret=%d\r\n", (int)ret);
        snprintf(l1, sizeof(l1), "init FAIL ret=%d", (int)ret);
        UiScanInfo(l1, "check camera hw", "", "");
#if QR_POOL_IN_SRAM
        shlosilo_sram_pool_reset();     /* decoder may have written the window */
#endif
        g_scan = SCAN_FAILED;
        return;
    }

    printf("scan: camera up\r\n");
    g_scan_frames = 0;
    /* The entry tap's contact may still be resting: treat as already seen. */
    g_touch_prev = 1;
    g_scan_abort_req = 0;
    g_scan = SCAN_ACTIVE;
    UiScanInfo("scanning...", "point camera at QR", "", "");
}

static void scan_step(void)
{
    char l1[40], l2[40], l3[40];
    uint32_t cam, vR, vW, dec;
    int32_t n;

    WDT_ReloadCounter();
    n = QrDecodeProcess(g_qr_result, QR_RESULT_MAX - 1, 0);
    cam = QrDecodeGetCamTick();
    vR = QrDecodeGetViewRenderTick();
    vW = QrDecodeGetViewWaitTick();
    dec = QrDecodeGetDecodeTick();
    g_scan_frames++;

    if (n > 0) {
        char msg[48];
        /* Task 5b: classify the scan BEFORE any leg runs (zero-key probe) -
         * seed plates (class 1-4) go to the confirmation page, `ur:`
         * transport (class 5) keeps the existing UR intake leg, everything
         * else (class 0) keeps the existing non-signing payload leg. */
        int cls = shlosilo_seed_qr_probe_ffi((const uint8_t *)g_qr_result,
                                            (unsigned)n);
        g_qr_result[n] = '\0';
        printf("scan: hit %d chars (seed class %d)\r\n", (int)n, cls);
        if (cls >= SEED_CLASS_STANDARD12 && cls <= SEED_CLASS_COMPACT24) {
            scan_seed_confirm(cls, (unsigned)n);
            return;
        }
        if (cls == SEED_CLASS_UR || strncmp(g_qr_result, "ur:", 3) == 0) {
            /* QR flow into the sign page: single UR signs directly,
             * multipart frames accumulate first. */
            scan_ur_hit(g_qr_result);
            return;
        }
        snprintf(msg, sizeof(msg), "qr hit %d chars", (int)n);
        scan_exit();
        UiSetLast(msg);
        UiSetPayload(g_qr_result, (uint32_t)n);
        return;
    }

    /* Back aborts the scan. The press is sampled continuously - frame loop,
     * band flushes and capture waits all feed product_touch_poll - so a tap
     * lands even mid-frame. */
    product_touch_poll();
    if (g_scan_abort_req) {
        char msg[48];
        g_scan_abort_req = 0;
        scan_exit();
        ur_intake_reset();      /* abort cancels a partial UR intake too */
        snprintf(msg, sizeof(msg), "abort -> welcome (%d,%d)",
                 g_back_press_x, g_back_press_y);
        UiSetLast(msg);
        UiGotoPage(UI_PAGE_WELCOME);
        return;
    }

    if ((g_scan_frames % SCAN_INFO_EVERY_FRAMES) == 0) {
        snprintf(l1, sizeof(l1), "frames=%u", (unsigned)g_scan_frames);
        snprintf(l2, sizeof(l2), "cam %u dec %u vR %u vW %u ms",
                 (unsigned)cam, (unsigned)dec, (unsigned)vR, (unsigned)vW);
        snprintf(l3, sizeof(l3), "focus %u res %d",
                 (unsigned)UiScanGetFocus(), (int)n);
        UiScanInfo("scanning...", l1, l2, l3);
    }
}

static void scan_exit(void)
{
    QrDecodeDeinit();
    g_scan = SCAN_IDLE;

#if QR_POOL_IN_SRAM
    /* The decoder wrote over the shared SRAM window: drop the Rust pool
     * bookkeeping so the next Rust allocation rebuilds it from scratch
     * (the Rust side is unused while scanning; see embedded_alloc_glue.c). */
    shlosilo_sram_pool_reset();
#endif

    /* Camera teardown shares I2C0 (PB0/PB1) with the touch IC: restore the
     * known-good bus configuration before the next touch read. */
    I2cInit();
    UiTouchReset();
}

/* ---------------- UR carousel session (F3 output side) ---------------- */

static void carousel_enter(void)
{
    /* The output side shows the signed set when a sign session produced one
     * (UR type mapped at sign time), else the canned demo payload. */
    const uint8_t *payload = (g_sign_out_len > 0) ? g_sign_out : g_demo_payload;
    unsigned payload_len =
        (g_sign_out_len > 0) ? g_sign_out_len : (unsigned)DEMO_PAYLOAD_LEN;
    const char *type =
        (g_sign_out_len > 0) ? g_sign_out_type : DEMO_PAYLOAD_TYPE;

    if (shlosilo_sram_pool_live_bytes() != 0) {
        printf("carousel: sram pool busy\r\n");
        UiSetLast("ur: sram busy");
        g_carousel = CAROUSEL_FAILED;
        g_pairing_qr = 0;   /* failed show: the pairing flag must not survive
                             * into WELCOME (UiTick clears it only AFTER
                             * UiTick() has run -- a fresh back press could
                             * reach the QR demo page in the same tick with
                             * the stale exemption still set) */
        UiGotoPage(UI_PAGE_WELCOME);
        return;
    }
    /* The decode pool may hold scanner leftovers; hand the window back. */
    shlosilo_sram_pool_reset();

    unsigned enc_ws_need = shlosilo_ur_encode_ws_len();
    /* PSRAM heap_4 (ExtMalloc): bare malloc/free is newlib sbrk and grows
     * into the K2-D pool / diag region (the v9-v11 trap, and the same trap
     * v16 fixed on the smoke side). */
    g_ur_enc_ws = (uint8_t *)ExtMalloc(enc_ws_need);
    if (g_ur_enc_ws == NULL) {
        printf("carousel: encoder ws alloc fail (%u)\r\n", enc_ws_need);
        UiSetLast("ur: ws fail");
        g_carousel = CAROUSEL_FAILED;
        g_pairing_qr = 0;   /* see the sram-busy leg: no stale exemption */
        UiGotoPage(UI_PAGE_WELCOME);
        return;
    }
    g_ur_enc = shlosilo_ur_encode_begin(type, payload,
                                        payload_len, 200,
                                        g_ur_enc_ws, enc_ws_need);
    if (g_ur_enc == NULL) {
        ExtFree(g_ur_enc_ws);
        g_ur_enc_ws = NULL;
        printf("carousel: encoder begin failed\r\n");
        UiSetLast("ur: encoder fail");
        g_carousel = CAROUSEL_FAILED;
        g_pairing_qr = 0;   /* see the sram-busy leg: no stale exemption */
        UiGotoPage(UI_PAGE_WELCOME);
        return;
    }
    g_ur_total = (payload_len + 199) / 200;
    g_ur_shown = 0;
    /* The entry tap may still be resting on `back`: treat the contact as
     * already seen so exiting needs a fresh press. */
    g_touch_prev = 1;
    g_ur_exit_req = 0;
    g_carousel = CAROUSEL_ACTIVE;
    printf("carousel: begin %s, %u frames\r\n", type,
           (unsigned)g_ur_total);
}

static void carousel_exit(void)
{
    if (g_ur_enc != NULL) {
        shlosilo_ur_encode_free(g_ur_enc);
        g_ur_enc = NULL;
    }
    ExtFree(g_ur_enc_ws);
    g_ur_enc_ws = NULL;
    g_carousel = CAROUSEL_IDLE;
    UiTouchReset();
}

/* Leave the carousel. T5 beat 2 (the pairing output leg) is flow-owned: its
 * back tap returns to the SCAN page so the SAME key session carries into
 * beat 3 (the xmr-txunsigned request). Every other carousel (demo / signed
 * set) exits to welcome -- for the beat-4 signed set the session is already
 * closed, and a live plate session at welcome is the flow-exit teardown. */
static void carousel_leave(const char *why)
{
    int pairing = g_pairing_qr;

    carousel_exit();
    g_pairing_qr = 0;
    if (pairing) {
        UiSetLast("keyimage sent - scan txunsigned");
        UiGotoPage(UI_PAGE_SCAN);
        return;
    }
    UiSetLast(why);
    UiGotoPage(UI_PAGE_WELCOME);
}

/* A fresh back press (sampled anywhere - dwell slices, band flush waits,
 * capture waits) asks to leave the carousel. */
static int carousel_exit_requested(void)
{
    product_touch_poll();
    if (g_ur_exit_req) {
        g_ur_exit_req = 0;
        return 1;
    }
    return 0;
}

static void carousel_step(void)
{
    unsigned int flen = 0;
    int rc;

    WDT_ReloadCounter();

    if (carousel_exit_requested()) {
        carousel_leave("carousel -> welcome");
        return;
    }

    rc = shlosilo_ur_encode_next_cyclic(g_ur_enc, (uint8_t *)g_ur_frame,
                                        sizeof(g_ur_frame), &flen);
    if (rc != 0 || flen == 0 || flen >= sizeof(g_ur_frame)) {
        printf("carousel: frame error rc=%d len=%u\r\n", rc, flen);
        carousel_leave("ur: frame error");
        return;
    }
    g_ur_frame[flen] = '\0';

    /* The frame stream is cyclic (a wallet joining mid-cycle catches every
     * part on the next wrap): show the position WITHIN the cycle, wrapping
     * 1..N with it, instead of a counter that grows forever. */
    UiShowQrFrame(g_ur_frame, g_ur_shown % g_ur_total, g_ur_total);
    g_ur_shown++;

    /* Dwell in slices with a touch sample each: a single poll per cycle
     * missed most taps ("touch intermittently dead" on device). The render
     * and flush windows are covered by the UiInputPoll hook. */
    for (uint32_t t = 0; t < CAROUSEL_FRAME_MS; t += CAROUSEL_TOUCH_SLICE_MS) {
        if (carousel_exit_requested()) {
            carousel_leave("carousel -> welcome");
            return;
        }
        osDelay(CAROUSEL_TOUCH_SLICE_MS);
    }
}

/* ---------------- battery / charger housekeeping ---------------- */

/* PF15 charger EXTI callback (ISR context): latch only. */
static void product_charger_evt(void)
{
    g_charger_evt = 1;
}

/* Runs at the top of every loop pass (scan/carousel included): battery +
 * charger refresh for the corner readout. */
static void product_status_tick(void)
{
    static uint32_t last_batt;
    static uint32_t last_batt_pct;
    static uint8_t charger_shots;
    static uint32_t charger_shot_at;
    static bool batt_first = true;
    uint32_t now = osKernelGetTickCount();

    /* Battery percent algorithm on the official cadence (GetBatteryInterval,
     * 80 s): the first call runs right at boot and adopts a fresh measurement
     * (LoadBatteryPercent yields the invalid marker until then), so the
     * corner starts at the true level instead of a garbage byte. Runs before
     * the display push below, so the first paint is already the real value. */
    if (batt_first || now - last_batt_pct >= GetBatteryInterval()) {
        last_batt_pct = now;
        Aw32001RefreshState();
        BatteryIntervalHandler();
        UiSetBattery(GetBatterPercent(),
                     GetChargeState() != CHARGE_STATE_NOT_CHARGING);
    }

    /* Charger state + corner readout: refreshed every 5 s ("c" follows
     * plug/unplug within one tick; UiSetBattery repaints only on change). */
    if (batt_first || now - last_batt >= 5000) {
        last_batt = now;
        Aw32001RefreshState();
        UiSetBattery(GetBatterPercent(),
                     GetChargeState() != CHARGE_STATE_NOT_CHARGING);
    }
    batt_first = false;

    /* Charger event (EXTI-latched, both edges): two refresh shots - one
     * after a 250 ms settle (the AW32001 STATR needs a moment after a VBUS
     * edge; official waits 200 ms), one ~1 s later for slow chargers - so
     * "c" appears/disappears in well under a second. The 5 s periodic above
     * stays as the backstop. */
    if (g_charger_evt != 0) {
        g_charger_evt = 0;
        charger_shots = 2;
        charger_shot_at = now + 250;
    }
    if (charger_shots != 0 && (uint32_t)(now - charger_shot_at) < 0x80000000u) {
        charger_shots--;
        charger_shot_at = now + 1000;
        Aw32001RefreshState();
        UiSetBattery(GetBatterPercent(),
                     GetChargeState() != CHARGE_STATE_NOT_CHARGING);
    }
}

/* ---------------- power button ---------------- */

static void power_button_init(void)
{
    GPIO_InitTypeDef gpio_init = {0};

    SYSCTRL_APBPeriphClockCmd(SYSCTRL_APBPeriph_GPIO, ENABLE);
    gpio_init.GPIO_Pin = BUTTON_INT_PIN;
    gpio_init.GPIO_Mode = GPIO_Mode_IPU;
    gpio_init.GPIO_Remap = GPIO_Remap_1;
    GPIO_Init(BUTTON_INT_PORT, &gpio_init);
}

static void power_button_check(void)
{
    uint32_t now = osKernelGetTickCount();
    bool pressed = (GPIO_ReadInputDataBit(BUTTON_INT_PORT, BUTTON_INT_PIN) == Bit_RESET);

    if (!pressed) {
        g_button_pressed = false;
        return;
    }
    if (!g_button_pressed) {
        g_button_pressed = true;
        g_button_press_start = now;
        return;
    }
    if (now - g_button_press_start >= BUTTON_LONG_PRESS_MS) {
        printf("power button long press: restarting\r\n");
        NVIC_SystemReset();
    }
}

/* ---------------- L3 panic display ---------------- */

/* shlosilo_panic_hook - called by the staticlib's panic handler (the Rust
 * `no_std` side has no I/O; see flux/forgebox/staticlib/src/lib.rs). The
 * signature is declared "-> !" on the Rust side, so this never returns:
 * show the message on the panel and keep feeding the watchdog so the screen
 * stays readable (same contract as the smoke host's hook). */
void shlosilo_panic_hook(const uint8_t *msg, size_t len)
{
    char tmp[192];
    size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;

    __asm__ volatile("cpsie i");    /* panic may sit inside a critical section */
    memcpy(tmp, msg, n);
    tmp[n] = '\0';

    /* Persist before the screen (smoke parity: a panic that wedges the
     * display too would otherwise be lost; the boot replay reads this
     * sector back). Same RSLT record shape as hardfault_diag's. */
    {
        uint8_t block[256];
        uint32_t plen = (uint32_t)strlen(tmp);
        uint8_t sum = 0;
        uint32_t i;
        if (plen > sizeof(block) - 9u) {
            plen = sizeof(block) - 9u;
        }
        memset(block, 0xFF, sizeof(block));
        block[0] = 'R'; block[1] = 'S'; block[2] = 'L'; block[3] = 'T';
        block[4] = (uint8_t)(plen & 0xFF);
        block[5] = (uint8_t)(plen >> 8);
        for (i = 0; i < plen; i++) {
            block[8 + i] = (uint8_t)tmp[i];
            sum = (uint8_t)(sum + (uint8_t)tmp[i]);
        }
        block[6] = sum;
        gc_flash_init();
        __disable_irq();
        FLASH_EraseSector(FAULT_REC_BASE);
        CACHE_CleanAll(CACHE);
        __enable_irq();
        WDT_ReloadCounter();
        __disable_irq();
        (void)AES_Program(NULL, NULL, FAULT_REC_BASE,
                          (uint32_t)sizeof(block), block);
        CACHE_CleanAll(CACHE);
        __enable_irq();
        WDT_ReloadCounter();
    }

    printf("PANIC: %s\r\n", tmp);
    UiPanic(tmp);

    while (1) {
        WDT_ReloadCounter();
        osDelay(100);
    }
}
