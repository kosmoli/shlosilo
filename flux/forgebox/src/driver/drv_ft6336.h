#ifndef _DRV_FT6336_H
#define _DRV_FT6336_H

#include "stdint.h"
#include "stdbool.h"
#include "err_code.h"
#include "cmsis_os.h"
#include "hal_touch.h"

#define FT6336_I2C_ADDR                 0x38

/// @brief FT6336 touch pad init.
void Ft6336Init(void);

/// @brief FT6336 open.
void Ft6336Open(void);

/// @brief Get touch status, including touch state, X/Y coordinate.
/// @param status TouchStatus struct addr.
int32_t Ft6336GetStatus(TouchStatus_t *status);

/// @brief Read one FT6336 register, best effort (0xFF when there is no answer).
int Ft6336PeekReg(uint8_t reg, uint8_t *out);

/// @brief Boot-time config check: re-apply the Active-mode configuration when
/// register 0x86 does not read back 0x00 (the chip's own post-reset init can
/// lose an early write). Called ~1 s after reset.
void Ft6336BootVerify(void);

#endif
