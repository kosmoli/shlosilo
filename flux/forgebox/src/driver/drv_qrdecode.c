#include "drv_qrdecode.h"
#include "mhscpu.h"
#include "decodelib.h"
#include "user_memory.h"
#include "cmsis_os.h"
#include <string.h>
#include "hal_lcd.h"
#include "shlosilo_ui.h"
#include "qr_selftest.h"

/* D2.1: the aiming preview (binarized) is rendered by shlosilo_ui; see the
 * UiScanPreview call in QrDecodeProcess below. The legacy LVGL-based
 * ViewImageOnLcd path stays disabled (kept for reference only). */
/* #define VIEW_IMAGE_ENABLE */

/*camera XCK set*/
#define CAM_XCK_GPIO                GPIOA
#define CAM_XCK_GPIO_PIN            GPIO_Pin_5
#define CAM_XCK_TIM                 TIM_5

/*camera I2C set*/
#define SI2C_PORT                   GPIOB
#define SI2C_SCL_PIN                GPIO_Pin_0
#define SI2C_SDA_PIN                GPIO_Pin_1
#define SI2C_GPIO_REMAP             GPIO_Remap_0

/*camera PWDN set*/
#define CAM_PWDN_GPIO               GPIOH
#define CAM_PWDN_GOIO_PIN           GPIO_Pin_9

/*camera RST set*/
#define CAM_RST_GPIO                GPIOH
#define CAM_RST_GOIO_PIN            GPIO_Pin_8

static void DCMI_NVICConfig(void);
static void CameraI2CGPIOConfig(void);
static void Cameraclk_Configuration(void);
#ifdef VIEW_IMAGE_ENABLE
static uint8_t *GetQrDecodeImageAddr(void);
static void ViewImageOnLcd(void);
#endif

static uint32_t g_camTick = 0;
static uint32_t g_viewRenderTick = 0;
static uint32_t g_viewWaitTick = 0;
static uint32_t g_decodeTick = 0;

/* Capture->decode self-test: stamp a synthetic QR (qr_selftest.h) into the
 * completed capture buffer while the diagnostic window is open. Two module
 * sizes alternate on consecutive injected frames (10 px and 16 px per
 * module, whole-frame white background) so a detection-layer size dependency
 * shows up as an A/B difference. A decode of the pattern proves the pipeline
 * works end to end; injecting stops on success or when the window closes.
 *
 * OTP probe: the library gates functionality on two OTP words ("MH19" and
 * "03QR"); MhbarCheckOtpChar() is the library's own check and its raw inputs
 * are readable for diagnosis. */
/* Diagnostic switch: the capture->decode self-test injection (D2.3/D2.4
 * bring-up instrument) is disabled in the product build. Set to 1 to
 * re-enable: stamps a synthetic QR into the completed capture buffer every
 * 8th frame for QR_SELFTEST_WINDOW frames, and stops for good on the first
 * decode (the pattern is the give-away "SELFTEST-OK"). */
#ifndef QR_DIAG_SELFTEST
#define QR_DIAG_SELFTEST 0
#endif
#define QR_SELFTEST_PERIOD  8
#define QR_SELFTEST_WINDOW  120        /* frames of diagnostic injection */
extern int32_t MhbarCheckOtpChar(void);
#define QR_OTP_WORD_A_ADDR  0x400081CCu
#define QR_OTP_WORD_B_ADDR  0x400081DCu
static uint32_t g_selftestCount = 0;
static uint32_t g_selftestStamps = 0;
static bool g_selftestDone = false;
static int32_t g_otpOk = -1;
static uint32_t g_otpA = 0;
static uint32_t g_otpB = 0;

static uint8_t *g_memPool = NULL;
DecodeConfigTypeDef g_decodeCfg = {0};

/* Progress rendering goes through shlosilo_ui (no LVGL fonts in this build). */

/**
 * @brief       QR decode init, malloc QRDECODE_BUFF_SIZE byte mem.
 * @retval      none.
 */
int32_t QrDecodeInit(uint8_t *pool)
{
    DecodeInitTypeDef DecodeInitStruct = {0};
    DecodeFlagTypeDef ret;

    SYSCTRL_AHBPeriphClockCmd(SYSCTRL_AHBPeriph_OTP, ENABLE);
    SYSCTRL_AHBPeriphResetCmd(SYSCTRL_AHBPeriph_OTP, ENABLE);

    /* Read the two OTP gate words and run the library's own check. */
    g_otpA = *(volatile uint32_t *)QR_OTP_WORD_A_ADDR;
    g_otpB = *(volatile uint32_t *)QR_OTP_WORD_B_ADDR;
    g_otpOk = MhbarCheckOtpChar();
    printf("scan: otpA=0x%08X otpB=0x%08X otpCheck=%d\n",
           (unsigned)g_otpA, (unsigned)g_otpB, (int)g_otpOk);

    g_memPool = pool;
    CameraI2CGPIOConfig();
    Cameraclk_Configuration();
    DecodeInitStruct.pool = g_memPool;
    DecodeInitStruct.size = QRDECODE_BUFF_SIZE;
    DecodeInitStruct.CAM_PWDN_GPIOx = CAM_PWDN_GPIO;
    DecodeInitStruct.CAM_PWDN_GPIO_Pin = CAM_PWDN_GOIO_PIN;
    DecodeInitStruct.CAM_RST_GPIOx = CAM_RST_GPIO;
    DecodeInitStruct.CAM_RST_GPIO_Pin = CAM_RST_GOIO_PIN;
    DecodeInitStruct.CAM_I2Cx = I2C0;
    DecodeInitStruct.CAM_I2CClockSpeed = I2C_ClockSpeed_400KHz;
    DecodeInitStruct.SensorConfig = NULL;
    DecodeInitStruct.SensorCfgSize = 0;
    ret = DecodeInit(&DecodeInitStruct);
    DecodeConfigInit(&g_decodeCfg);
    /* Scan QR codes only. The library default additionally enables eight
     * one-dimensional symbologies (CODE128/39/93, EAN13/8, UPC-A/E0/E1);
     * scanning every frame for all of them costs ~500 ms on this hardware
     * (measured: dec ~567 ms per frame), which caps the loop at ~1.3 fps.
     * QR keeps its default tuning: 0xb = enable + missing-corner + curve. */
    g_decodeCfg.cfgCODE128 = 0;
    g_decodeCfg.cfgCODE39 = 0;
    g_decodeCfg.cfgCODE93 = 0;
    g_decodeCfg.cfgEAN13 = 0;
    g_decodeCfg.cfgEAN8 = 0;
    g_decodeCfg.cfgUPC_A = 0;
    g_decodeCfg.cfgUPC_E0 = 0;
    g_decodeCfg.cfgUPC_E1 = 0;
    g_decodeCfg.cfgISBN13 = 0;
    g_decodeCfg.cfgInterleaved2of5 = 0;
    g_decodeCfg.cfgPDF417 = 0;
    g_decodeCfg.cfgDataMatrix = 0;
    DCMI_NVICConfig();

    return ret;
}

/**
 * @brief       QR decode deinit, release hardware/software source.
 * @retval      none.
 */
void QrDecodeDeinit(void)
{
    //SRAM_FREE(g_memPool);
    CloseDecode();
    //SYSCTRL_AHBPeriphClockCmd(SYSCTRL_AHBPeriph_OTP, DISABLE);
}

uint32_t QrDecodeGetCamTick(void)
{
    uint32_t tick = g_camTick;
    g_camTick = 0;
    return tick;
}

uint32_t QrDecodeGetViewRenderTick(void)
{
    uint32_t tick = g_viewRenderTick;
    g_viewRenderTick = 0;
    return tick;
}

uint32_t QrDecodeGetViewWaitTick(void)
{
    uint32_t tick = g_viewWaitTick;
    g_viewWaitTick = 0;
    return tick;
}

uint32_t QrDecodeGetSelftestStamps(void)
{
    return g_selftestStamps;
}

int32_t QrDecodeOtpOk(void)
{
    return g_otpOk;
}

uint32_t QrDecodeOtpWordA(void)
{
    return g_otpA;
}

uint32_t QrDecodeOtpWordB(void)
{
    return g_otpB;
}

uint32_t QrDecodeGetDecodeTick(void)
{
    uint32_t tick = g_decodeTick;
    g_decodeTick = 0;
    return tick;
}

/// @brief QR decode process, called in the decoding thread loop.
/// @param[out] result store qrdecode result here if success.
/// @param[in] maxLen max length of result.
/// @param[in] progress 0-100, show progress bar on lcd. Do not show progress bar if progress value is 0.
/// @return err code, int32_t
///             return QR decode char length.
///             0 represents unrecognized image.
///             A negative number returned represents an error.
int32_t QrDecodeProcess(char *result, uint32_t maxLen, uint8_t progress)
{
    int32_t resnum;
    DecodeResultTypeDef res = {.result = (uint8_t *)result, .maxn = maxLen};
    uint32_t tick;
    static uint8_t progressNum = 100;

    if (progressNum != progress) {
        if (progress > 0) {
            UiScanProgress(progress);
        }
        progressNum = progress;
    }
    tick = osKernelGetTickCount();
    DecodeDcmiStart();
    while (!DecodeDcmiFinish()) {           //Finish waiting by DCMI_CallBackFrame()
        UiInputPoll();                      // keep sampling input while the capture runs
        osDelay(1);
    }
    g_camTick += osKernelGetTickCount() - tick;

    /* Self-test stamp (diagnostic builds only; see QR_DIAG_SELFTEST).
     * Right after the capture completes, so the preview below also shows
     * the stamped pattern. Consecutive burst frames carry the two size
     * variants (small on even offsets, large on odd). */
    g_selftestCount++;
#if QR_DIAG_SELFTEST
    if (!g_selftestDone && g_selftestCount <= QR_SELFTEST_WINDOW) {
        uint32_t phase = g_selftestCount % QR_SELFTEST_PERIOD;
        int module_px = 0;

        if ((g_selftestCount % QR_SELFTEST_PERIOD) == 0) {
            module_px = QR_SELFTEST_MODULE_PX_SMALL;
        } else if ((g_selftestCount % QR_SELFTEST_PERIOD) == 1) {
            module_px = QR_SELFTEST_MODULE_PX_LARGE;
        }
        (void)phase;
        if (module_px > 0) {
            char *img = GetImageBuffAddr();
            if (img != NULL) {
                QrSelfTestStamp((uint8_t *)img, 640, 480, module_px);
                g_selftestStamps++;
            }
        }
    }
#endif

    tick = osKernelGetTickCount();
    /* Binarized aiming preview (shlosilo_ui): the captured frame is valid
     * here - after the capture completed and before DecodeStart consumes it. */
    {
        char *imgAddr = GetImageBuffAddr();
        if (imgAddr != NULL) {
            UiScanPreview((const uint8_t *)imgAddr, 640, 480);
        }
    }
    g_viewRenderTick += osKernelGetTickCount() - tick;
    tick = osKernelGetTickCount();
    while (!DecodeDcmiFinish()) {
        UiInputPoll();                      // second-finish wait: same input coverage
        osDelay(1);
    }
    g_viewWaitTick += osKernelGetTickCount() - tick;
    tick = osKernelGetTickCount();
    resnum = DecodeStart(&g_decodeCfg, &res);
    if (resnum > 0) {
        /* Self-test decoded: capture->decode path proven; stop stamping so
         * the scanner stays clean for real scans. */
        if (!g_selftestDone && resnum == 11 &&
                memcmp(res.result, "SELFTEST-OK", 11) == 0) {
            g_selftestDone = true;
        }
        CleanDecodeBuffFlag();
    }
    g_decodeTick += osKernelGetTickCount() - tick;

    return resnum;
    //return 0;
}

#ifdef VIEW_IMAGE_ENABLE

#define VIEW_IMAGE_LINE             20

static uint8_t *staticImgAddr = NULL;

static uint8_t *GetQrDecodeImageAddr(void)
{
    return staticImgAddr;
}

static void ViewImageOnLcd(void)
{
    uint8_t *imgAddr;

    static uint16_t *buffer1 = NULL;
    uint8_t *u8Addr;
    uint16_t R, G, B;

    if (buffer1 == NULL) {
        buffer1 = SRAM_MALLOC(320 * VIEW_IMAGE_LINE * 2);
    }

    imgAddr = (uint8_t *)GetImageBuffAddr();
    if (imgAddr == NULL) {
        imgAddr = staticImgAddr;
    }
    if (imgAddr == NULL) {
        return;
    }
    staticImgAddr = imgAddr;

    uint32_t i, camPixelIndex = 0, line;
    uint32_t x = 0, y = 0;
#define START_SCAN_LINE 225
#define START_SCAN_COL  82
    for (line = START_SCAN_LINE; line < START_SCAN_LINE + 320; line += VIEW_IMAGE_LINE) {
        x = 0;
        while (LcdBusy()) {
            osDelay(1);
        }
        for (i = 0; i < 320 * VIEW_IMAGE_LINE; i++) {
            camPixelIndex = ((320 - y) * 3 / 2 + 80) + (x * 3 / 2) * 640;
            u8Addr = (uint8_t *)&buffer1[i];
            // *u8Addr = (imgAddr[camPixelIndex] & 0xF1) | (imgAddr[camPixelIndex] >> 5);
            // *(u8Addr + 1) = ((imgAddr[camPixelIndex] << 3) & 0xE0) | (imgAddr[camPixelIndex] >> 3);
            G = imgAddr[camPixelIndex] >> 2;
            R = G >> 1;
            B = R;
            *(uint16_t*)u8Addr = ((R << 3 | B << 8 | G << 13 | G >> 3));
            x++;
            if (x >= 320) {
                x = 0;
                y++;
            }
        }
        LcdDraw(START_SCAN_COL, line, START_SCAN_COL + 320 - 1, line + VIEW_IMAGE_LINE - 1, (uint16_t *)buffer1);
    }
}

#endif

/* DCMI Interrupt Config */
static void DCMI_NVICConfig(void)
{
    NVIC_InitTypeDef NVIC_InitStructure;

    NVIC_SetPriorityGrouping(NVIC_PriorityGroup_3);

    NVIC_InitStructure.NVIC_IRQChannel = DCMI_IRQn;
    NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 1;
    NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;
    NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;
    NVIC_Init(&NVIC_InitStructure);

//  DCMI_ITConfig(DCMI_IT_VSYNC, ENABLE);
    DCMI_ITConfig(DCMI_IT_OVF, ENABLE);
//  DCMI_ITConfig(DCMI_IT_LINE, ENABLE);
    DCMI_ITConfig(DCMI_IT_FRAME, ENABLE);
    DCMI_ITConfig(DCMI_IT_ERR, ENABLE);

    DCMI_ClearITPendingBit(DCMI_IT_VSYNC);
    DCMI_ClearITPendingBit(DCMI_IT_OVF);
    DCMI_ClearITPendingBit(DCMI_IT_LINE);
    DCMI_ClearITPendingBit(DCMI_IT_FRAME);
    DCMI_ClearITPendingBit(DCMI_IT_ERR);
}

/* I2C Pin Config */
static void CameraI2CGPIOConfig(void)
{
    SYSCTRL_APBPeriphClockCmd(SYSCTRL_APBPeriph_I2C0, ENABLE);
    I2C_DeInit(I2C0);

    GPIO_PinRemapConfig(SI2C_PORT, SI2C_SCL_PIN, SI2C_GPIO_REMAP);
    GPIO_PinRemapConfig(SI2C_PORT, SI2C_SDA_PIN, SI2C_GPIO_REMAP);
}

/* Camera Clock Config */
static void Cameraclk_Configuration(void)
{
    uint32_t Period = 0;
    uint32_t PWM_HZ = 24000000;
    SYSCTRL_ClocksTypeDef clocks;
    TIM_PWMInitTypeDef TIM_PWMSetStruct;

    SYSCTRL_APBPeriphClockCmd(SYSCTRL_APBPeriph_TIMM0, ENABLE);

    SYSCTRL_GetClocksFreq(&clocks);

    /* Check PCLK, need >= 48MHz */
    //if (clocks.PCLK_Frequency / 2 < PWM_HZ) {
    PWM_HZ = clocks.PCLK_Frequency / 2;
    //}

    Period = clocks.PCLK_Frequency / PWM_HZ;

    TIM_PWMSetStruct.TIM_LowLevelPeriod = (Period / 2 - 1);
    TIM_PWMSetStruct.TIM_HighLevelPeriod = (Period - TIM_PWMSetStruct.TIM_LowLevelPeriod - 2);

    TIM_PWMSetStruct.TIMx = CAM_XCK_TIM;
    TIM_PWMInit(TIMM0, &TIM_PWMSetStruct);

    GPIO_PinRemapConfig(CAM_XCK_GPIO, CAM_XCK_GPIO_PIN, GPIO_Remap_2);

    TIM_Cmd(TIMM0, CAM_XCK_TIM, ENABLE);
}

void DCMI_IRQHandler(void)
{
    if (DCMI_GetITStatus(DCMI_IT_LINE) != RESET) {
        DCMI_ClearITPendingBit(DCMI_IT_LINE);
    }

    if (DCMI_GetITStatus(DCMI_IT_VSYNC) != RESET) {
        DCMI_ClearITPendingBit(DCMI_IT_VSYNC);
    }

    if (DCMI_GetITStatus(DCMI_IT_FRAME) != RESET) {
        //callback
        DCMI_CallBackFrame();
        DCMI_ClearITPendingBit(DCMI_IT_FRAME);
    }

    if (DCMI_GetITStatus(DCMI_IT_OVF) != RESET) {
        DCMI_ClearITPendingBit(DCMI_IT_OVF);
    }

    if (DCMI_GetITStatus(DCMI_IT_ERR) != RESET) {
        DCMI_ClearITPendingBit(DCMI_IT_ERR);
    }
}
