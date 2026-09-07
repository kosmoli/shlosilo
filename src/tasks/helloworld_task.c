#include "helloworld_task.h"
#include "stdio.h"
#include "cmsis_os.h"
#include "mhscpu.h"
#include "mhscpu_wdt.h"
#include "hal_lcd.h"
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

        lv_timer_handler();
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
    while (LcdBusy()) {
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
