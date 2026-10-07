#ifndef _HOST_SHADOW_MHSCPU_H
#define _HOST_SHADOW_MHSCPU_H

/*
 * Host-test shadow of external/mh1903_lib .../mhscpu.h.
 * The keystore data plane pulls drv_otp.h / drv_mpu.h, which include the
 * vendor header for the MH1903 register map. On the host there is no chip:
 * this shadow satisfies the include so the production sources compile
 * unmodified. The OTP register window itself is emulated by mmap()-ing the
 * real OTP address range (see host_shims.c).
 */
#include "stdint.h"

#endif
