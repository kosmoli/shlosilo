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

            if (UiGetPage() == UI_PAGE_SCAN && g_scan == SCAN_IDLE) {
                scan_enter();
            } else if (UiGetPage() == UI_PAGE_QR && g_carousel == CAROUSEL_IDLE) {
                carousel_enter();
            }
            if (UiGetPage() != UI_PAGE_SCAN && g_scan == SCAN_FAILED) {
                g_scan = SCAN_IDLE;     /* left the scan page; allow a retry */
            }
            if (UiGetPage() != UI_PAGE_QR && g_carousel == CAROUSEL_FAILED) {
                g_carousel = CAROUSEL_IDLE;     /* left the QR page; allow retry */
            }

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

/* xmr_gen_cache_flash.c */
extern void gc_flash_init(void);
extern const uint8_t *gc_load(const uint8_t *prefix, uint32_t prefix_len);
extern uint32_t gc_store(const uint8_t *prefix, uint32_t prefix_len,
                         const uint8_t *blob, uint32_t blob_len);

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

/* Sign result (feeds the output carousel on the QR page). */
static uint8_t *g_sign_out = NULL;
static unsigned g_sign_out_len = 0;
static char g_sign_out_type[32] = "bytes";

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
 * registry type (8304), everything else as opaque bytes. */
static void sign_out_type_for(const char *in_type)
{
    if (strcmp(in_type, "xmr-txunsigned") == 0 ||
        strcmp(in_type, "crypto-monero-tx") == 0) {
        snprintf(g_sign_out_type, sizeof(g_sign_out_type), "xmr-txsigned");
    } else if (strcmp(in_type, "crypto-psbt") == 0) {
        snprintf(g_sign_out_type, sizeof(g_sign_out_type), "crypto-psbt");
    } else {
        snprintf(g_sign_out_type, sizeof(g_sign_out_type), "bytes");
    }
}

/* Run one sign on this task's stack: uri != NULL is the single-frame path
 * (shlosilo_sign_ur_ffi), otherwise the multipart path
 * (shlosilo_sign_typed_ffi over the reassembled (type, payload)). */
static void sign_run(const char *uri, const char *type,
                     const uint8_t *payload, unsigned plen)
{
    char l1[48], l2[48], l3[48], result[192];
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
    snprintf(l3, sizeof(l3), "key: fixture idx12");
    UiSignInfo(l1, l2, l3);
    UiGotoPage(UI_PAGE_SIGN);

    /* BP+ generator tables must be ready before the prove path runs
     * (missing storage = the lib.rs:265 statement panic, 10-03). */
    gencache_prepare();

    printf("sign: start (ws=%u)\r\n", ws_need);
    g_sign_busy = 1;
    t0 = osKernelGetTickCount();
    if (uri != NULL) {
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
                     "stk used ~%uK (hwm %uW of %uK)",
                     out_len, (unsigned)dt, g_sign_out_type, used_k, hwm_w,
                     (unsigned)(PRODUCT_TASK_STACK_BYTES / 1024u));
        } else {
            g_sign_out_len = 0;
            snprintf(result, sizeof(result),
                     "sign FAIL: rc=%d\n"
                     "stk used ~%uK (hwm %uW of %uK)",
                     rc, used_k, hwm_w,
                     (unsigned)(PRODUCT_TASK_STACK_BYTES / 1024u));
        }
        snprintf(l3, sizeof(l3), "stk used ~%uK", used_k);
        UiSetLast(l3);
    }

    ur_intake_reset();
    printf("sign: done -> result page\r\n");
    UiSetPayload(result, (uint32_t)strlen(result));
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

    if (slash2 == NULL) {
        scan_exit();
        sign_run(text, NULL, NULL, 0);
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
        UiScanProgress(0);
    }

    if (shlosilo_ur_decode_feed(g_ur_dec, text, &accepted) != 0) {
        printf("ur: frame rejected (accepted=%u)\r\n", accepted);
        UiScanInfo("ur multipart", "frame rejected", "continuing", "");
        return;
    }
    progress = shlosilo_ur_decode_progress(g_ur_dec);
    snprintf(l3, sizeof(l3), "%s", accepted ? "new frame" : "dup frame");
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
        g_qr_result[n] = '\0';
        printf("scan: hit %d chars\r\n", (int)n);
        if (strncmp(g_qr_result, "ur:", 3) == 0) {
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
    printf("carousel: begin %s, %u frames\r\n", DEMO_PAYLOAD_TYPE,
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
        carousel_exit();
        UiSetLast("carousel -> welcome");
        UiGotoPage(UI_PAGE_WELCOME);
        return;
    }

    rc = shlosilo_ur_encode_next_cyclic(g_ur_enc, (uint8_t *)g_ur_frame,
                                        sizeof(g_ur_frame), &flen);
    if (rc != 0 || flen == 0 || flen >= sizeof(g_ur_frame)) {
        printf("carousel: frame error rc=%d len=%u\r\n", rc, flen);
        carousel_exit();
        UiSetLast("ur: frame error");
        UiGotoPage(UI_PAGE_WELCOME);
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
            carousel_exit();
            UiSetLast("carousel -> welcome");
            UiGotoPage(UI_PAGE_WELCOME);
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

    printf("PANIC: %s\r\n", tmp);
    UiPanic(tmp);

    while (1) {
        WDT_ReloadCounter();
        osDelay(100);
    }
}
