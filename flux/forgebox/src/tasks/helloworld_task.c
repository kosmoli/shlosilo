#include "helloworld_task.h"
#include "shlosilo_smoke_task.h"
#include "stdio.h"
#include "cmsis_os.h"
#include "mhscpu.h"
#include "mhscpu_wdt.h"
#include "hal_lcd.h"
#include "hal_touch.h"
#include "drv_exti.h"
#include "lvgl.h"
#include "stdlib.h"
#include "mhscpu_gpio.h"

#define LVGL_TICK_MS    5
#define LVGL_GRAM_PIXEL (LCD_DISPLAY_WIDTH * LCD_DISPLAY_HEIGHT / 10)

// Power button configuration
#define BUTTON_INT_PORT                 GPIOE
#define BUTTON_INT_PIN                  GPIO_Pin_14
#define BUTTON_LONG_PRESS_MS            3000
#define BUTTON_CHECK_INTERVAL_MS        50
#define WDT_FEED_INTERVAL_MS            100

static void HelloWorldTask(void *argument);
static void LvglTickTimerFunc(void *argument);
static void LcdFlush(struct _lv_disp_drv_t *disp_drv, const lv_area_t *area, lv_color_t *color_p);
static void PowerButtonInit(void);
static void PowerButtonCheck(void);
static void RestartDevice(void);

osThreadId_t g_helloWorldTaskHandle;
osTimerId_t g_lvglTickTimer;

static lv_disp_draw_buf_t g_dispBuf;
static lv_color_t g_lvglCache[LCD_DISPLAY_WIDTH * LCD_DISPLAY_HEIGHT / 10];
static lv_obj_t *g_container;

static uint32_t g_buttonPressStartTime = 0;
static bool g_buttonPressed = false;

/* LVGL is not thread safe: the helloworld task runs lv_timer_handler while the
 * smoke task calls lv_* directly to update the log — once touch added indev
 * hit-testing, concurrent object-tree access from both tasks caused a crash.
 * A global mutex serializes the two sides. */
static osMutexId_t g_lvglMutex = NULL;

void lvgl_lock(void)
{
    if (g_lvglMutex != NULL) {
        osMutexAcquire(g_lvglMutex, osWaitForever);
    }
}

void lvgl_unlock(void)
{
    if (g_lvglMutex != NULL) {
        osMutexRelease(g_lvglMutex);
    }
}

/* Touch indev: makes the smoke log scrollable (K2 diagnostic requirement — the test output is longer than one screen) */
static lv_indev_drv_t g_touchDrv;
/* Diagnostic counters: raw coordinates of the last press + error/press counts (shown on the smoke screen) */
volatile uint16_t g_touch_diag_x = 0xFFFF;
volatile uint16_t g_touch_diag_y = 0xFFFF;
volatile uint32_t g_touch_diag_err = 0;
volatile uint32_t g_touch_diag_press = 0;

static bool touch_indev_read_cb(struct _lv_indev_drv_t *drv, lv_indev_data_t *data)
{
    (void)drv;
    TouchStatus_t st;
    int32_t rc = TouchGetStatus(&st);
    if (rc != 0) {
        g_touch_diag_err++;
        data->state = LV_INDEV_STATE_RELEASED;
        return false;
    }
    if (st.touch) {
        g_touch_diag_press++;
        g_touch_diag_x = st.x;
        g_touch_diag_y = st.y;
        data->point.x = st.x;
        data->point.y = st.y;
        data->state = LV_INDEV_STATE_PRESSED;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
    }
    return false; /* no multi-point buffering */
}

void CreateHelloWorldTask(void)
{
    const osThreadAttr_t taskAttr = {
        .name = "display_bg",
        .stack_size = 1024 * 32,
        .priority = osPriorityHigh,
    };
    g_helloWorldTaskHandle = osThreadNew(HelloWorldTask, NULL, &taskAttr);
    g_lvglTickTimer = osTimerNew(LvglTickTimerFunc, osTimerPeriodic, NULL, NULL);
}

static void HelloWorldTask(void *argument)
{
    printf("Display background task started\n");

    static lv_disp_drv_t dispDrv;

    // Initialize LVGL
    lv_init();
    printf("LVGL initialized\n");

    // Initialize display buffer
    lv_disp_draw_buf_init(&g_dispBuf, g_lvglCache, NULL, LVGL_GRAM_PIXEL);
    printf("Display buffer initialized\n");

    // Initialize and register display driver
    lv_disp_drv_init(&dispDrv);
    dispDrv.flush_cb = LcdFlush;
    dispDrv.draw_buf = &g_dispBuf;
    dispDrv.hor_res = LCD_DISPLAY_WIDTH;
    dispDrv.ver_res = LCD_DISPLAY_HEIGHT;
    lv_disp_drv_register(&dispDrv);
    printf("Display driver registered\n");

    /* Touch input device: lets the smoke log scroll (480x800, 1:1 with the panel).
     * I2cInit must come before touch probing — the helloworld init chain never
     * called it (the keystone production firmware calls it in its own init chain);
     * without it the I2C0 clock is off and register access from the touch IC
     * driver is a bus fault. */
    g_lvglMutex = osMutexNew(NULL);

    /* build C: full replica of the keystone production architecture — ExtInterruptInit
     * enables EXTI (PA2 tamper/PD7 SD/PE14 button/PF1 touch INT) plus the real
     * TouchInit. The keystone production firmware has working touch on the same
     * hardware, which shows this init chain is the right one. */
    ExtInterruptInit();
    /* Note: touch goes through I2CIO bit-bang (GPIOB0/B1), so drv_i2c hardware I2C0
     * cannot be used (remapping it onto the same two pins collides and probing goes
     * blind). The keystone production firmware likewise does not call I2cInit for touch. */
    TouchInit(NULL);
    TouchOpen();
    lv_indev_drv_init(&g_touchDrv);
    g_touchDrv.type = LV_INDEV_TYPE_POINTER;
    g_touchDrv.read_cb = touch_indev_read_cb;
    lv_indev_drv_register(&g_touchDrv);
    printf("Touch indev registered\n");

    // Start LVGL tick timer
    osTimerStart(g_lvglTickTimer, LVGL_TICK_MS);
    printf("Timer started\n");

    // Pure black background; the smoke task draws its title and log on top of it.
    g_container = lv_obj_create(lv_scr_act());
    lv_obj_set_size(g_container, LCD_DISPLAY_WIDTH, LCD_DISPLAY_HEIGHT);
    lv_obj_set_style_bg_color(g_container, lv_color_hex(0x000000), 0);
    lv_obj_set_style_bg_opa(g_container, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(g_container, 0, 0);
    lv_obj_set_style_radius(g_container, 0, 0);
    lv_obj_set_style_pad_all(g_container, 0, 0);
    lv_obj_clear_flag(g_container, LV_OBJ_FLAG_SCROLLABLE);
    printf("Container created\n");

    /* Smoke diagnostics task draws its title/log onto the container. */
    CreateShlosiloSmokeTask();

    PowerButtonInit();

    uint32_t lastButtonCheck = osKernelGetTickCount();
    uint32_t lastWdtFeed = osKernelGetTickCount();

    while (1) {
        uint32_t now = osKernelGetTickCount();

        if (now - lastWdtFeed >= WDT_FEED_INTERVAL_MS) {
            lastWdtFeed = now;
            WDT_ReloadCounter();
        }

        if (now - lastButtonCheck >= BUTTON_CHECK_INTERVAL_MS) {
            lastButtonCheck = now;
            PowerButtonCheck();
        }

        lvgl_lock();
        lv_timer_handler();
        lvgl_unlock();

        /* v18: phase heartbeat to flash (~2s cadence, change-gated inside). */
        {
            static uint32_t lastPh = 0;
            if (now - lastPh >= 2000) {
                lastPh = now;
                extern void diag_heartbeat(void);
                diag_heartbeat();
            }
        }

        /* Loop-liveness heartbeat (diagnostic, 2026-09-30): raw LcdDraw of a
         * 24x24 square at the top-right, toggled every ~500 ms. Independent of
         * LVGL and of the smoke task — if this square animates, the display_bg
         * loop (and the WDT feed) is alive.
         * v5: same serialization discipline as LcdFlush — lvgl_lock + LcdBusy
         * wait (LcdDraw is async DMA; v4's unguarded draws wedged the panel). */
        {
            static uint32_t lastHb = 0;
            static uint16_t hbColor = 0xF800; /* red/green toggle */
            if (now - lastHb >= 500) {
                lastHb = now;
                static uint16_t hbBuf[16 * 16];
                for (unsigned i = 0; i < 16 * 16; i++) {
                    hbBuf[i] = hbColor;
                }
                lvgl_lock();
                LcdDraw(464, 8, 479, 23, hbBuf);
                /* v17: bounded wait (see smoke_task) — a wedge here froze the
                 * loop's WDT feed and looked like a whole-system death. */
                for (unsigned i = 0; i < 1000u && LcdBusy(); i++) {
                    osDelay(1);
                }
                lvgl_unlock();
                hbColor = (hbColor == 0xF800) ? 0x07E0 : 0xF800;
            }
        }
        osDelay(5);
    }
}

static void LvglTickTimerFunc(void *argument)
{
    lv_tick_inc(LVGL_TICK_MS);
}

static void LcdFlush(struct _lv_disp_drv_t *disp_drv, const lv_area_t *area, lv_color_t *color_p)
{
    LcdDraw(area->x1, area->y1, area->x2, area->y2, (uint16_t *)color_p);
    /* v17: bounded wait — the flush runs under the lvgl_lock inside the loop;
     * an unbounded wedge here froze everything (and the WDT feed with it). */
    for (unsigned i = 0; i < 1000u && LcdBusy(); i++) {
        osDelay(1);
    }
    lv_disp_flush_ready(disp_drv);
}

static void PowerButtonInit(void)
{
    GPIO_InitTypeDef gpioInit = {0};

    SYSCTRL_APBPeriphClockCmd(SYSCTRL_APBPeriph_GPIO, ENABLE);
    gpioInit.GPIO_Pin = BUTTON_INT_PIN;
    gpioInit.GPIO_Mode = GPIO_Mode_IPU;
    gpioInit.GPIO_Remap = GPIO_Remap_1;
    GPIO_Init(BUTTON_INT_PORT, &gpioInit);
}

static void PowerButtonCheck(void)
{
    uint32_t now = osKernelGetTickCount();
    bool pressed = (GPIO_ReadInputDataBit(BUTTON_INT_PORT, BUTTON_INT_PIN) == Bit_RESET);

    if (!pressed) {
        g_buttonPressed = false;
        return;
    }

    if (!g_buttonPressed) {
        g_buttonPressed = true;
        g_buttonPressStartTime = now;
        return;
    }

    if (now - g_buttonPressStartTime >= BUTTON_LONG_PRESS_MS) {
        RestartDevice();
    }
}

static void RestartDevice(void)
{
    printf("Power button long press detected, restarting...\n");
    NVIC_SystemReset();
}
