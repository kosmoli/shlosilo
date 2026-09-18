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
#include "cmsis_os.h"
#include "mhscpu.h"
#include "mhscpu_gpio.h"
#include "mhscpu_wdt.h"
#include "drv_exti.h"
#include "drv_i2c.h"
#include "drv_qrdecode.h"
#include "user_memory.h"
#include "hal_touch.h"
#include "shlosilo_ui.h"
#include "ui_layout.h"

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

typedef enum {
    SCAN_IDLE = 0,      /* not on the scan page (or exited) */
    SCAN_ACTIVE,        /* camera initialized, scanning frames */
    SCAN_FAILED,        /* on the scan page, init failed (exit to retry) */
} ScanState;

static void ProductTask(void *argument);
static void scan_enter(void);
static void scan_step(void);
static void scan_exit(void);
static void power_button_init(void);
static void power_button_check(void);

static uint32_t g_button_press_start = 0;
static bool g_button_pressed = false;

/* Scan session state */
static uint8_t *g_qr_pool = NULL;
static char g_qr_result[QR_RESULT_MAX];
static ScanState g_scan = SCAN_IDLE;
static uint32_t g_scan_frames = 0;
static int g_scan_touch_prev = 0;
static uint8_t g_flip = 0;      /* sensor image flip probe (tap preview to cycle) */

void CreateProductTask(void)
{
    static const osThreadAttr_t task_attr = {
        .name = "product_ui",
        .stack_size = 16 * 1024,
        .priority = osPriorityHigh,
    };
    osThreadNew(ProductTask, NULL, &task_attr);
}

static void ProductTask(void *argument)
{
    (void)argument;

    printf("product UI task started\r\n");
    WDT_ReloadCounter();

    ExtInterruptInit();
    TouchInit(NULL);
    TouchOpen();
    printf("touch probe: addr=0x%02X ok=%d\r\n",
           g_touch_probe_addr, g_touch_probe_ok);

    power_button_init();

    UiInit();
    UiShow();
    printf("ui: welcome page shown\r\n");

    uint32_t last_wdt = osKernelGetTickCount();
    uint32_t last_btn = osKernelGetTickCount();

    while (1) {
        if (g_scan == SCAN_ACTIVE) {
            WDT_ReloadCounter();
            scan_step();
            osDelay(5);
        } else {
            UiTick();

            if (UiGetPage() == UI_PAGE_SCAN && g_scan == SCAN_IDLE) {
                scan_enter();
            } else if (UiGetPage() != UI_PAGE_SCAN && g_scan == SCAN_FAILED) {
                g_scan = SCAN_IDLE;     /* left the scan page; allow a retry */
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

    UiScanInfo("camera init...", "", "", "");
    WDT_ReloadCounter();
    int32_t ret = QrDecodeInit(g_qr_pool);
    if (ret != DecodeInitSuccess) {
        printf("scan: QrDecodeInit ret=%d\r\n", (int)ret);
        snprintf(l1, sizeof(l1), "init FAIL ret=%d", (int)ret);
        UiScanInfo(l1, "check camera hw", "", "");
        g_scan = SCAN_FAILED;
        return;
    }

    printf("scan: camera up\r\n");
    g_scan_frames = 0;
    g_scan_touch_prev = 0;
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
        snprintf(msg, sizeof(msg), "qr hit %d chars", (int)n);
        scan_exit();
        UiSetLast(msg);
        UiSetPayload(g_qr_result, (uint32_t)n);
        return;
    }

    /* Touch poll between frames: back aborts the scan; tapping the preview
     * cycles the sensor image flip (orientation probe). */
    TouchStatus_t st;
    if (TouchGetStatus(&st) == 0) {
        int down = st.touch ? 1 : 0;
        if (down && !g_scan_touch_prev) {
            int tx = (int)st.x;
            int ty = (int)st.y;

            if (UiIsBackButton(tx, ty)) {
                char msg[48];
                scan_exit();
                snprintf(msg, sizeof(msg), "abort -> welcome (%d,%d)", tx, ty);
                UiSetLast(msg);
                UiGotoPage(UI_PAGE_WELCOME);
                return;
            }
            if (tx >= UI_S_PV_X0 && tx <= UI_S_PV_X0 + UI_S_PV_W &&
                ty >= UI_S_PV_Y0 && ty <= UI_S_PV_Y0 + UI_S_PV_H) {
                g_flip = (uint8_t)((g_flip + 1) & 3);
                SetSensorImageFlip((SensorImageFlipType)g_flip);
                printf("scan: sensor flip -> %u\r\n", (unsigned)g_flip);
            }
        }
        g_scan_touch_prev = down;
    }

    if ((g_scan_frames % SCAN_INFO_EVERY_FRAMES) == 0) {
        if (g_scan_frames < 40) {
            /* OTP gate probe (library authorization words + check result)
             * plus the decode pool address for verification. */
            snprintf(l1, sizeof(l1), "otp ck=%d", (int)QrDecodeOtpOk());
            snprintf(l2, sizeof(l2), "A=%08X B=%08X",
                     (unsigned)QrDecodeOtpWordA(), (unsigned)QrDecodeOtpWordB());
            snprintf(l3, sizeof(l3), "pool %08X", (unsigned)(uint32_t)g_qr_pool);
            UiScanInfo("otp probe", l1, l2, l3);
        } else {
            snprintf(l1, sizeof(l1), "frames=%u inj=%u flip=%u",
                     (unsigned)g_scan_frames, (unsigned)QrDecodeGetSelftestStamps(),
                     (unsigned)g_flip);
            snprintf(l2, sizeof(l2), "cam %u dec %u vR %u vW %u ms",
                     (unsigned)cam, (unsigned)dec, (unsigned)vR, (unsigned)vW);
            snprintf(l3, sizeof(l3), "focus %u res %d",
                     (unsigned)UiScanGetFocus(), (int)n);
            UiScanInfo("scanning...", l1, l2, l3);
        }
    }
}

static void scan_exit(void)
{
    QrDecodeDeinit();
    g_scan = SCAN_IDLE;

    /* Camera teardown shares I2C0 (PB0/PB1) with the touch IC: restore the
     * known-good bus configuration before the next touch read. */
    I2cInit();
    UiTouchReset();
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
