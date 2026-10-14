/* crash_noinit.c -- warm-reset crash marker in NOINIT SRAM.
 *
 * 2026-10-14: the QSPI NOR record path is dead on this board (identical
 * garbage reads from two sectors, erase+program both silently ignored;
 * the same sectors demonstrably worked in September -- the controller
 * config changed under us). The v3/v4 diagnostic precedent keeps a marker
 * in the noinit region at 0x20098000 that survives a WDT warm reset; this
 * is now the PRIMARY crash recorder. Zero flash, zero drivers: a few
 * absolute word writes that cannot fail.
 *
 * Layout (16 bytes, word-aligned):
 *   [0] magic  'CRNV' (0x43524E56)
 *   [1] phase  (crash_phase value at death; 0xFF = NONE)
 *   [2] type   (1=PHASE pin 2=PANIC 3=HARDFAULT; 0 = clean run marker)
 *   [3] pc     (fault PC, best effort)
 *
 * Rules: writers stamp type/phase and NEVER erase (a clean pairing return
 * stamps type=0 so a surviving pin means the leg never returned). The boot
 * reader copies the words out and stamps type=0 (consume) so the next run
 * starts clean.
 */

#include <stdint.h>
#include "crash_noinit.h"

#define CRASH_NOINIT_BASE 0x20098000u
#define CRASH_NOINIT_MAGIC 0x43524E56u /* 'CRNV' */

static volatile uint32_t *noinit_words(void)
{
    return (volatile uint32_t *)(uintptr_t)CRASH_NOINIT_BASE;
}

void crash_noinit_mark(uint8_t type, uint8_t phase, uint32_t pc)
{
    volatile uint32_t *w = noinit_words();
    w[1] = (uint32_t)phase;
    w[2] = (uint32_t)type;
    w[3] = pc;
    w[0] = CRASH_NOINIT_MAGIC; /* committed last */
}

int crash_noinit_read(crash_noinit_rec_t *out)
{
    volatile uint32_t *w = noinit_words();
    uint32_t magic = w[0];
    if (magic != CRASH_NOINIT_MAGIC || out == 0) {
        return 0;
    }
    out->phase = (uint8_t)(w[1] & 0xFFu);
    out->type = (uint8_t)(w[2] & 0xFFu);
    out->pc = w[3];
    /* consume: stamp a clean-run marker so the next boot starts fresh */
    w[2] = 0;
    w[0] = 0;
    return 1;
}
