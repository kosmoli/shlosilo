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
#define FT6336_REG_TD_STATUS   0x02

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

/* One 5-byte register burst (TD_STATUS..P1_YL). Pre-filled with 0xFF so a
 * failed transfer reads as junk rather than as "no touch". */
static void Ft6336ReadPacket(uint8_t *b)
{
    uint8_t reg = FT6336_REG_TD_STATUS;

    b[0] = 0xFF; b[1] = 0xFF; b[2] = 0xFF; b[3] = 0xFF; b[4] = 0xFF;
    I2cSendAndReceiveData(FT6336_I2C_ADDR, &reg, 1, b, 5);
}

/* 0 = no touch, 1 = valid touch, 2 = point reported with invalid coords.
 * datasheet: TD_STATUS[3:0] counts points (only 1-2 are valid); coordinates
 * live in Pn_XH[3:0]:Pn_XL (12 bit). All-ones coordinates (4095) with a
 * nonzero count is the "reported but not valid" state seen on device. */
static int Ft6336Classify(const uint8_t *b)
{
    uint8_t count = (uint8_t)(b[0] & 0x0F);

    if (count < 1 || count > 2) {
        return 0;
    }
    if ((((uint16_t)(b[1] & 0x0F) << 8) | b[2]) >= TOUCH_PAD_RES_X) {
        return 2;
    }
    if ((((uint16_t)(b[3] & 0x0F) << 8) | b[4]) >= TOUCH_PAD_RES_Y) {
        return 2;
    }
    return 1;
}

/// @brief Get touch status, including touch state, X/Y coordinate.
/// @param status TouchStatus struct addr.
int32_t Ft6336GetStatus(TouchStatus_t *status)
{
    uint8_t pkt[5], rb[5];
    int cls;

    Ft6336ReadPacket(pkt);
    cls = Ft6336Classify(pkt);

    if (cls == 2) {
        /* The chip reported a point with junk coordinates. Re-read once: a
         * read that raced the chip's register update settles on the second
         * try and the sample is saved. If it is STILL junk the sample is
         * dropped - a bogus press must never move the edge tracker (that is
         * how the first tap after boot got eaten). */
        Ft6336ReadPacket(rb);
        if (Ft6336Classify(rb) == 1) {
            for (int i = 0; i < 5; i++) {
                pkt[i] = rb[i];
            }
            cls = 1;
        } else {
            cls = 0;
        }
    }

    if (cls == 1) {
        uint16_t x = (uint16_t)(((pkt[1] & 0x0F) << 8) | pkt[2]);
        uint16_t y = (uint16_t)(((pkt[3] & 0x0F) << 8) | pkt[4]);

        status->touch = true;
#if (FT6336_REVERSE_X)
        x = TOUCH_PAD_RES_X - x - 1;
#endif
#if (FT6336_REVERSE_Y)
        y = TOUCH_PAD_RES_Y - y - 1;
#endif
        status->x = x;
        status->y = y;
    } else {
        status->touch = false;
        status->x = 0;
        status->y = 0;
    }

    return SUCCESS_CODE;
}
