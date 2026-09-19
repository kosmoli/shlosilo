#include "drv_ft6336.h"
#include "stdio.h"
#include "mhscpu.h"
#include "drv_i2c.h"
#include "log_print.h"
#include "user_delay.h"
#include "drv_i2c_io.h"

/* FT6X36 register map (FT6236/FT6336/FT6436 datasheet, "CTPM Register
 * Mapping"):
 *   0x00 DEVICE_MODE [2:0]: 000b WORKING, 100b FACTORY
 *   0x86 CTRL:  0 = keep Active mode when there is no touching (never enter
 *               Monitor); 1 = switch to Monitor automatically (factory
 *               default), delayed by 0x87 TIMEENTERM (default 0x0A).
 * In Monitor mode "the serial port is closed and no data shall be transferred
 * with the host processor": the first touch only wakes the chip back to
 * Active and is never reported. Device symptom (2026-09-19): "the first tap
 * after boot or after sitting idle does nothing; the next one works".
 * Disable the auto-switch: keep the chip in WORKING + Active. */
#define FT6336_REG_DEVICE_MODE 0x00
#define FT6336_REG_CTRL        0x86

/* Last TD_STATUS byte + event bits seen by Ft6336GetStatus (on-screen diag). */
volatile uint8_t g_touch_last_status = 0;
volatile uint8_t g_touch_last_event = 0;

static void Ft6336Configure(void)
{
    uint8_t buf[2];
    uint8_t reg = FT6336_REG_CTRL;
    uint8_t val = 0xFF;
    int attempt;

    /* Write-and-verify with retries: a single write inside the chip's
     * post-reset init window can be lost (the chip may not be listening yet).
     * Re-writing until CTRL reads back 0 closes that hole. */
    for (attempt = 1; attempt <= 3; attempt++) {
        buf[0] = FT6336_REG_DEVICE_MODE;
        buf[1] = 0x00;              /* WORKING mode */
        I2cSendData(FT6336_I2C_ADDR, buf, 2);

        buf[0] = FT6336_REG_CTRL;
        buf[1] = 0x00;              /* never auto-enter Monitor */
        I2cSendData(FT6336_I2C_ADDR, buf, 2);

        I2cSendAndReceiveData(FT6336_I2C_ADDR, &reg, 1, &val, 1);
        if (val == 0x00) {
            break;
        }
        UserDelay(10);
    }
    printf("touch: ctrl(0x86)=0x%02X (attempt %d)\r\n", (unsigned)val, attempt);
}

/// @brief Read one FT6336 register, best effort (0xFF when there is no answer).
int Ft6336PeekReg(uint8_t reg, uint8_t *out)
{
    if (out == NULL) {
        return -1;
    }
    *out = 0xFF;
    I2cSendAndReceiveData(FT6336_I2C_ADDR, &reg, 1, out, 1);
    return 0;
}

/// @brief Boot check (~1 s after reset, chip fully settled): the Active-mode
/// configuration must survive the chip's own init - re-apply and verify when
/// CTRL does not read back 0x00 (a write that lost the race with the chip's
/// init would otherwise leave the auto-Monitor default armed).
void Ft6336BootVerify(void)
{
    uint8_t ctrl = 0xFF;

    Ft6336PeekReg(FT6336_REG_CTRL, &ctrl);
    if (ctrl == 0x00) {
        printf("touch: boot check ctrl ok\r\n");
        return;
    }
    printf("touch: boot check ctrl=0x%02X -> reconfigure\r\n", (unsigned)ctrl);
    Ft6336Configure();
}

/// @brief FT6336 touch pad init.
/// @param func Interrupt callback function, called when EXTINT gpio rasing/falling.
void Ft6336Init(void)
{
    I2cInit();
    Ft6336Configure();
}

/// @brief FT6336 open.
void Ft6336Open(void)
{
    I2cInit();
    Ft6336Configure();
}

/// @brief Get touch status, including touch state, X/Y coordinate.
/// @param status TouchStatus struct addr.
int32_t Ft6336GetStatus(TouchStatus_t *status)
{
    uint8_t sendByte, readBuff[5] = {0};

    sendByte = 0x02;
    I2cSendAndReceiveData(FT6336_I2C_ADDR, &sendByte, 1, readBuff, 5);

    //PrintArray("read touch", readBuff, 5);
    status->touch = readBuff[0] > 0 ? true : false;
    status->x = ((readBuff[1] & 0x0F) << 8) + readBuff[2];
#if (FT6336_REVERSE_X)
    status->x = TOUCH_PAD_RES_X - status->x - 1;
#endif
    status->y = ((readBuff[3] & 0x0F) << 8) + readBuff[4];
#if (FT6336_REVERSE_Y)
    status->y = TOUCH_PAD_RES_Y - status->y - 1;
#endif

    return SUCCESS_CODE;
}
