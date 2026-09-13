/* Local minimal stub for the vendored mhscpu_qspi.c driver (forgebox-helloworld). */
#ifndef USER_DELAY_H_STUB
#define USER_DELAY_H_STUB
#include "mhscpu.h"
static inline void UserDelayUs(uint32_t us)
{
    /* crude busy wait; only used during flash type probe */
    volatile uint32_t n = us * 100u;
    while (n--) {
        __NOP();
    }
}
#endif
