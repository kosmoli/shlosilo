#include "drv_trng.h"
#include "mhscpu.h"
//#include "string.h"
//#include "log_print.h"

void TrngInit(void)
{
    SYSCTRL_APBPeriphClockCmd(SYSCTRL_APBPeriph_TRNG, ENABLE);
    SYSCTRL_APBPeriphResetCmd(SYSCTRL_APBPeriph_TRNG, ENABLE);
}

void TrngGet(void *buf, uint32_t len)
{
    uint32_t buf4[4];

    for (uint32_t i = 0; i < len; i += 16) {
        TRNG_Start(TRNG0);
        while (0 != TRNG_Get(buf4, TRNG0));
        if (len - i >= 16) {
            memcpy((uint8_t *)buf + i, buf4, 16);
        } else {
            memcpy((uint8_t *)buf + i, buf4, len - i);
        }
    }
    /* Wipe the stack temp: buf4 holds raw TRNG blocks and must not linger
       after return (pool #46 hygiene gap, fixed 2026-10-28). Volatile walk
       so the compiler cannot dead-store-eliminate the wipe. */
    {
        volatile uint32_t *vp = buf4;
        for (uint32_t j = 0; j < 4; j++) {
            vp[j] = 0;
        }
    }
}
