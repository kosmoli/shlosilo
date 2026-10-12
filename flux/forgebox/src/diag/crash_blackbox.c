/* crash_blackbox.c — crash-forensics blackbox: QSPI NOR persistence.
 *
 * Erase+program discipline mirrors the proven panic-path write (the smoke
 * task's res_write_at / the old shlosilo_panic_hook block): one 4KB sector
 * erase in an irq-off window, CACHE_CleanAll, one 256B program at the
 * sector base, CACHE_CleanAll, WDT feed between steps.
 */
#include <string.h>
#include "mhscpu.h"
#include "crash_blackbox.h"

/* xmr_gen_cache_flash.c: QSPI write-access bring-up (without it the erase can
 * silently fail and stale records replay forever). */
extern void gc_flash_init(void);
extern void FLASH_EraseSector(uint32_t addr);
extern void CACHE_CleanAll(CACHE_TypeDef *cache);

static volatile uint8_t g_bb_phase = CRASH_PHASE_NONE;

void crash_bb_init(void)
{
    gc_flash_init();
}

uint8_t crash_bb_phase_cur(void)
{
    return g_bb_phase;
}

static void bb_erase(void)
{
    gc_flash_init();
    __disable_irq();
    FLASH_EraseSector(CRASH_REC_BASE);
    CACHE_CleanAll(CACHE);
    __enable_irq();
    WDT_ReloadCounter();
}

static void bb_write_rec(const crash_rec_t *rec)
{
    uint8_t block[256];
    memset(block, 0xFF, sizeof(block));
    memcpy(block, rec, sizeof(*rec));
    bb_erase();
    __disable_irq();
    (void)AES_Program(NULL, NULL, CRASH_REC_BASE, (uint32_t)sizeof(block), block);
    CACHE_CleanAll(CACHE);
    __enable_irq();
    WDT_ReloadCounter();
}

void crash_bb_phase(uint8_t phase)
{
    crash_rec_t rec;
    g_bb_phase = crash_phase_advance(g_bb_phase, phase);
    crash_rec_init(&rec, CRASH_REC_TYPE_PHASE, g_bb_phase);
    bb_write_rec(&rec);
}

void crash_bb_phase_clear(void)
{
    g_bb_phase = CRASH_PHASE_NONE;
    bb_erase();
}

void crash_bb_write_panic(const char *msg, uint32_t len, uint32_t pc, uint32_t lr)
{
    crash_rec_t rec;
    crash_rec_init(&rec, CRASH_REC_TYPE_PANIC, g_bb_phase);
    rec.pc = pc;
    rec.lr = lr;
    crash_rec_loc_from_panic(&rec, msg, len);
    bb_write_rec(&rec);
}

void crash_bb_write_hardfault(const uint32_t *stack)
{
    crash_rec_t rec;
    crash_rec_init(&rec, CRASH_REC_TYPE_HARDFAULT, g_bb_phase);
    rec.pc = stack[6];              /* stacked PC */
    rec.lr = stack[5];              /* stacked LR */
    rec.xpsr = stack[7];            /* stacked xPSR */
    rec.sp = (uint32_t)(uintptr_t)stack;
    rec.cfsr = SCB->CFSR;
    rec.hfsr = SCB->HFSR;
    rec.bfar = SCB->BFAR;
    bb_write_rec(&rec);
}

int crash_bb_read(crash_rec_t *out)
{
    const volatile uint8_t *p = (const volatile uint8_t *)CRASH_REC_BASE;
    for (uint32_t i = 0; i < sizeof(*out); i++) {
        ((uint8_t *)out)[i] = p[i];
    }
    return crash_rec_valid(out);
}

void crash_bb_consume(void)
{
    bb_erase();
}
