#include "stdio.h"
#include "stdlib.h"
#include "define.h"
#include "drv_battery.h"
#include "mhscpu.h"
#include "user_delay.h"
#include "drv_aw32001.h"
#include "cmsis_os.h"
#include "flash_address.h"
#include "user_memory.h"
#include "drv_gd25qxx.h"
#include "assert.h"
#include "user_utils.h"

#define BATTERY_DEBUG           0
#define BATTERY_ARRAY_LEN       10

#if BATTERY_DEBUG == 1
#define BATTERY_PRINTF(fmt, args...)                printf(fmt, ##args)
#else
#define BATTERY_PRINTF(fmt, args...)
#endif

#define BATTERY_DELAY_TO_DECREASE_PERCENT               2
#define BATTERY_DIFF_THRESHOLD                          40
#define BATTERY_CHARGING_BY_TIME                        75
#define BATTERY_LOG_PERCENT_INTERVAL                    10
#define BATTERY_LOG_ONLY_LOW_BATTERY                    1
#define BATTERY_LOG_DETAIL                              1
#define BATTERY_ADC_TIMES                               10
#define BATTERY_PCT_CHANGE_MIN_TICK_DISCHARGE           (80 * 1000)
#define BATTERY_PCT_CHANGE_MIN_TICK_CHARGING            (80 * 1000)
#define BATTERY_INVALID_PERCENT_VALUE                   101
#define BATTERY_CHANNEL                                 ADC_CHANNEL_4
#define RTC_BAT_CHANNEL                                 ADC_CHANNEL_3
#define RTC_WAKE_UP_INTERVAL_DISCHARGE                  (60 * 30)           //30 minutes

static uint8_t LoadBatteryPercent(void);
static void SaveBatteryPercent(uint8_t percent);

const uint16_t dischargeCurve[100] = {
    3391, 3409, 3423, 3435, 3447, 3459, 3469, 3478, 3488, 3497,
    3505, 3513, 3521, 3528, 3535, 3541, 3548, 3554, 3560, 3566,
    3571, 3576, 3582, 3587, 3593, 3598, 3604, 3609, 3615, 3621,
    3627, 3634, 3641, 3648, 3655, 3663, 3671, 3679, 3688, 3697,
    3706, 3716, 3725, 3735, 3744, 3753, 3762, 3770, 3778, 3785,
    3792, 3799, 3805, 3811, 3817, 3822, 3828, 3833, 3838, 3844,
    3849, 3853, 3858, 3863, 3867, 3872, 3877, 3883, 3891, 3900,
    3910, 3921, 3932, 3943, 3954, 3964, 3974, 3977, 3980, 3983,
    3986, 3990, 3993, 3996, 3999, 4000, 4003, 4006, 4009, 4013,
    4019, 4028, 4038, 4049, 4062, 4076, 4090, 4107, 4125, 4156,
};

const uint16_t chargingCurve[100] = {
    3380, 3495, 3531, 3547, 3556, 3564, 3572, 3579, 3588, 3596,
    3605, 3613, 3622, 3631, 3639, 3646, 3655, 3662, 3668, 3675,
    3681, 3687, 3692, 3697, 3701, 3706, 3710, 3714, 3719, 3724,
    3729, 3734, 3739, 3744, 3750, 3756, 3762, 3769, 3776, 3784,
    3792, 3800, 3808, 3819, 3827, 3836, 3845, 3855, 3865, 3874,
    3883, 3892, 3900, 3908, 3916, 3923, 3930, 3936, 3943, 3949,
    3955, 3960, 3965, 3970, 3975, 3980, 3985, 3989, 3994, 3999,
    4003, 4010, 4016, 4024, 4033, 4042, 4052, 4063, 4074, 4084,
    4094, 4102, 4109, 4115, 4119, 4123, 4127, 4131, 4135, 4139,
    4144, 4149, 4155, 4161, 4168, 4176, 4186, 4195, 4200, 4200,
};

static uint8_t g_batterPercent = BATTERY_INVALID_PERCENT_VALUE;
static uint32_t g_batteryFlashAddress = SPI_FLASH_ADDR_BATTERY_INFO;

void RtcBatAdcDetEnable(void)
{
    GPIO_SetBits(GPIOE, GPIO_Pin_0);
}

void RtcBatAdcDetDisable(void)
{
    GPIO_ResetBits(GPIOE, GPIO_Pin_0);
}

/// @brief Battery init, ADC init, load FLASH value.
/// @param
void BatteryInit(void)
{
    ADC_InitTypeDef ADC_InitStruct;
    GPIO_InitTypeDef gpioInit;

    SYSCTRL_APBPeriphClockCmd(SYSCTRL_APBPeriph_GPIO | SYSCTRL_APBPeriph_ADC, ENABLE);
    SYSCTRL_APBPeriphResetCmd(SYSCTRL_APBPeriph_ADC, ENABLE);

    GPIO_PinRemapConfig(GPIOC, GPIO_Pin_3 | GPIO_Pin_4, GPIO_Remap_2);
    GPIO_PullUpCmd(GPIOC, GPIO_Pin_3 | GPIO_Pin_4, DISABLE);

    gpioInit.GPIO_Mode = GPIO_Mode_Out_PP;
    gpioInit.GPIO_Pin = GPIO_Pin_0;
    gpioInit.GPIO_Remap = GPIO_Remap_1;
    GPIO_Init(GPIOE, &gpioInit);
    RtcBatAdcDetDisable();

    ADC_InitStruct.ADC_Channel = ADC_CHANNEL_4;
    ADC_InitStruct.ADC_SampSpeed = ADC_SpeedPrescaler_2;
    ADC_InitStruct.ADC_IRQ_EN = DISABLE;
    ADC_InitStruct.ADC_FIFO_EN = DISABLE;

    ADC_Init(&ADC_InitStruct);
    g_batterPercent = LoadBatteryPercent();
}

/// @brief Battery init, ADC init.
void BatteryOpen(void)
{
    ADC_InitTypeDef ADC_InitStruct;

    SYSCTRL_APBPeriphClockCmd(SYSCTRL_APBPeriph_GPIO | SYSCTRL_APBPeriph_ADC, ENABLE);
    SYSCTRL_APBPeriphResetCmd(SYSCTRL_APBPeriph_ADC, ENABLE);

    GPIO_PinRemapConfig(GPIOC, GPIO_Pin_4, GPIO_Remap_2);
    GPIO_PullUpCmd(GPIOC, GPIO_Pin_4, DISABLE);

    ADC_InitStruct.ADC_Channel = ADC_CHANNEL_4;
    ADC_InitStruct.ADC_SampSpeed = ADC_SpeedPrescaler_2;
    ADC_InitStruct.ADC_IRQ_EN = DISABLE;
    ADC_InitStruct.ADC_FIFO_EN = DISABLE;

    ADC_Init(&ADC_InitStruct);
}

/// @brief Get battery voltage.
/// @param
/// @return Battery voltage, in millivolts.
uint32_t GetBatteryMilliVolt(void)
{
    int32_t i, adcAver, temp, max, min;
    uint64_t adcSum = 0;

    max = 0;
    min = 0xFFF;
    osKernelLock();
    ADC_StartCmd(ENABLE);
    ADC_ChannelSwitch(BATTERY_CHANNEL);
    for (i = 0; i < BATTERY_ADC_TIMES; i++) {
        do {
            UserDelay(1);
            temp = ADC_GetResult();
        } while (temp >= 0xF00);
        adcSum += temp;
        if (temp > max) {
            max = temp;
        }
        if (temp < min) {
            min = temp;
        }
    }
    ADC_StartCmd(DISABLE);
    BATTERY_PRINTF("max=%d,min=%d\r\n", max, min);
    adcSum -= max;
    adcSum -= min;
    adcAver = adcSum / (BATTERY_ADC_TIMES - 2);
    BATTERY_PRINTF("adcAver=%d\r\n", adcAver);
    osKernelUnlock();
    return ADC_CalVoltage(adcAver, 6200);
}

uint32_t GetRtcBatteryMilliVolt(void)
{
    int32_t i, adcAver, temp, max, min;
    uint64_t adcSum = 0;
    uint32_t vol;

    RtcBatAdcDetEnable();
    UserDelay(10);
    max = 0;
    min = 0xFFF;
    ADC_StartCmd(ENABLE);
    ADC_ChannelSwitch(RTC_BAT_CHANNEL);
    for (i = 0; i < BATTERY_ADC_TIMES; i++) {
        do {
            UserDelay(1);
            temp = ADC_GetResult();
        } while (temp >= 0xFF0);
        adcSum += temp;
        if (temp > max) {
            max = temp;
        }
        if (temp < min) {
            min = temp;
        }
    }
    ADC_StartCmd(DISABLE);
    adcSum -= max;
    adcSum -= min;
    adcAver = adcSum / (BATTERY_ADC_TIMES - 2);
    vol = ADC_CalVoltage(adcAver, 1880);
    temp = vol;
    if (adcAver > 2420) {
        vol = vol * 285 / 100;
    } else if (adcAver > 2070) {
        vol = vol * 29 / 10;
    } else if (adcAver < 2020) {
        vol = vol * 27 / 10;
    } else if ((adcAver >= 2020) && (adcAver < 2038)) {
        vol = vol * 28 / 10;
    } else {
        vol = vol * 284 / 100;
    }

    RtcBatAdcDetDisable();
    return vol;
}

/// @brief Execute once every minimum percent change time interval.
/// @param
bool BatteryIntervalHandler(void)
{
    UsbPowerState usbPowerState;
    uint8_t percent;
    uint32_t milliVolt = 0;
    bool change = false;
    static bool first = true;
    static uint8_t powerOffCnt = 0;
    static uint8_t delayIncrease = 0, delayDecrease = 0;

    usbPowerState = GetUsbPowerState();
    milliVolt = GetBatteryMilliVolt();
    percent = GetBatteryPercentByMilliVolt(milliVolt, usbPowerState == USB_POWER_STATE_DISCONNECT);

    printf("handler,milliVolt=%d,percent=%d,showPercent=%d,usbPowerState=%d\n", milliVolt, percent, GetBatterPercent(), usbPowerState);
    if (usbPowerState == USB_POWER_STATE_DISCONNECT && milliVolt < dischargeCurve[0]) {
        printf("low volt,power off\n");
        powerOffCnt++;
        if (powerOffCnt >= 10) {
            Aw32001PowerOff();
        }
    }
    powerOffCnt = 0;
    if (first) {
        first = false;
        change = true;
    }

    if (g_batterPercent == BATTERY_INVALID_PERCENT_VALUE) {
        //todo: get the stored battery data.
        BATTERY_PRINTF("init battery percent\r\n");
        g_batterPercent = percent;
        change = true;
    }
    if (percent < g_batterPercent && usbPowerState == USB_POWER_STATE_DISCONNECT) {
        //The battery percentage only decreases when discharging.
        //The battery percentage decrease by 1% each time.
        // g_batterPercent--;
        if (percent > 85) {
            delayDecrease++;
        } else {
            delayDecrease = BATTERY_DELAY_TO_DECREASE_PERCENT;
        }
        if (percent < g_batterPercent && delayDecrease >= BATTERY_DELAY_TO_DECREASE_PERCENT) {
            g_batterPercent--;
            change = true;
            delayDecrease = 0;
        }
    } else if (usbPowerState == USB_POWER_STATE_CONNECT) {
        //The battery percentage only increase when charging.
        //The battery percentage increase by 1% each time.
        if (percent < g_batterPercent && percent >= BATTERY_CHARGING_BY_TIME) {
            //printf("delay increate battery percentage delayIncrease = %d\n", delayIncrease);
            delayIncrease++;
        }

        // delayIncrease == 4 * 80 320s
        if (percent > g_batterPercent || delayIncrease == 4) {
            g_batterPercent++;
            if (g_batterPercent >= 100) {
                g_batterPercent = 100;
            }
            change = true;
            delayIncrease = 0;
        }
    }
    BATTERY_PRINTF("g_batterPercent=%d\r\n", g_batterPercent);
    if (change) {
        SaveBatteryPercent(g_batterPercent);
    }
    return change;
}

/// @brief Get the battery percentage after correction.
/// @return Battery level percentage.
uint8_t GetBatterPercent(void)
{
    return g_batterPercent;
}

/// @brief Get battery interval tick
/// @return Battery interval tick.
uint32_t GetBatteryInterval(void)
{
    return GetUsbPowerState() == USB_POWER_STATE_DISCONNECT ? BATTERY_PCT_CHANGE_MIN_TICK_DISCHARGE : BATTERY_PCT_CHANGE_MIN_TICK_CHARGING;
}

/// @brief Get the saved battery level percentage.
/// @return BATTERY_INVALID_PERCENT_VALUE until the first
///         BatteryIntervalHandler() call measures and adopts a value.
static uint8_t LoadBatteryPercent(void)
{
    /* Product build: the official battery history lives in SPI flash
     * (Gd25 read/erase/write at SPI_FLASH_ADDR_BATTERY_INFO). That block
     * is not wired in this tree - the previous version parsed a freshly
     * malloc'd, UNINITIALISED buffer as if it were flash history, so
     * every boot started from a garbage byte (device report 2026-09-19:
     * "battery shows 1% after every boot, then crawls up").
     * Return the invalid marker instead: the first BatteryIntervalHandler()
     * call adopts a fresh measurement (the official empty-flash path),
     * so the corner starts at the true level. One ADC read is done here
     * as a warm-up and discarded. */
    (void)GetBatteryMilliVolt();
    return BATTERY_INVALID_PERCENT_VALUE;
}

/// @brief Save the battery level percentage.
/// @param percent Battery level percentage.
static void SaveBatteryPercent(uint8_t percent)
{
    ASSERT(g_batteryFlashAddress >= SPI_FLASH_ADDR_BATTERY_INFO && g_batteryFlashAddress < SPI_FLASH_ADDR_BATTERY_INFO + SPI_FLASH_SIZE_BATTERY_INFO);
    g_batteryFlashAddress++;
    if (g_batteryFlashAddress >= SPI_FLASH_ADDR_BATTERY_INFO + SPI_FLASH_SIZE_BATTERY_INFO) {
        g_batteryFlashAddress = SPI_FLASH_ADDR_BATTERY_INFO;
    }
    BATTERY_PRINTF("save battery percent, addr=%d\r\n", g_batteryFlashAddress);
}

uint8_t GetBatteryPercentByMilliVolt(uint32_t milliVolt, bool discharge)
{
    uint16_t const *curve = discharge ? dischargeCurve : chargingCurve;
    uint8_t percent;

    for (percent = 0; percent < 100; percent++) {
        if (milliVolt <= curve[percent]) {
            break;
        }
    }

    return percent;
}
