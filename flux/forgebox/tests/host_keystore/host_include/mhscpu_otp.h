#ifndef _HOST_SHADOW_MHSCPU_OTP_H
#define _HOST_SHADOW_MHSCPU_OTP_H

/*
 * Host-test shadow of the MH1903 OTP driver interface (mhscpu_otp.h).
 * Only the entry points the keystore data plane calls are declared; the
 * implementations live in host_shims.c on top of a fake OTP window.
 */
#include "stdint.h"

void OTP_PowerOn(void);

#endif
