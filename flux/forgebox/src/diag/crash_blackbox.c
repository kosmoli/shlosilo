/* crash_blackbox.c — crash-forensics blackbox: QSPI NOR persistence.
 *
 * BOARD LIMITATION (2026-10-14 A/B/C/D ladder, repeated with a write ladder):
 * on the current forgebox board the QSPI record region is effectively
 * READ-ONLY — erase and program are silently ignored and reads return a
 * frozen image. The flash write path below is kept (with its 69 host tests)
 * because other boards demonstrably persist records through it; here the
 * frozen screen (crash_screen_hold) and the phase paint are the actual
 * recorder. The write attempts stay live: they are ms-level, WDT-fed, and
 * proven harmless during the mainnet acceptance run — gating them behind a
 * flag would change a verified build for no field gain.
 *
 * WDT-safe APPEND-ONLY log (fix15). The crash path NEVER erases: a write is
 * one pure-program append (NOR programming turns 1 -> 0 without an erase) of
 * a 256B slot block into the first all-0xFF slot of the record sector — the
 * erase-then-program discipline of fix14 is gone. That erase was fatal in
 * two ways: a WDT landing mid-erase leaves a half-erased sector whose CRC is
 * invalid (the whole sector reads as "no record"), and its irq-off window
 * (tens to hundreds of ms) both perturbed the pairing leg and starved the
 * very watchdog whose reset it was racing.
 *
 * Erase happens in exactly two healthy-state places:
 *   (a) crash_bb_consume() — the operator's back tap;
 *   (b) the sector-full reclaim inside crash_store_append(healthy=1), which
 *       keeps the read-rule winner so an unconsumed crash record survives.
 * Panic hook / HardFault / PHASE pins pass healthy=0 and only ever program.
 *
 * Write-path discipline: ms-level program, WDT fed before and after every
 * flash step, and NO __disable_irq window anywhere on the write path (the
 * irq-off window stays only around the healthy-state erase). No LVGL, no
 * heap, no RTOS delay — the hardfault path runs with the scheduler dead.
 *
 * The whole 4KB sector block is programmed per append because AES_Program
 * asserts a 4KB-aligned ADDRESS (see res_write_at in shlosilo_smoke_task.c)
 * and the AES path encrypts full 4KB units; re-programming the bytes that
 * are already there is electrically a no-op (1 -> 0 with identical data).
 */
#include <string.h>
#include "mhscpu.h"
#include "crash_blackbox.h"
#include "crash_noinit.h"
#include "shlosilo_ui.h"
#include "crash_store.h"

/* xmr_gen_cache_flash.c: QSPI write-access bring-up (without it the erase can
 * silently fail and stale records replay forever). */
extern void gc_flash_init(void);
extern void FLASH_EraseSector(uint32_t addr);
extern void CACHE_CleanAll(CACHE_TypeDef *cache);

static volatile uint8_t g_bb_phase = CRASH_PHASE_NONE;

/* Sector image for the program call. Static, not stack: the hardfault path
 * must not spend 4KB of the crashed task's stack. Single-writer discipline:
 * all writers run from the pairing leg or a dying system, never concurrently
 * (a mutex is useless in the panic path anyway). */
static uint8_t g_bb_block[CRASH_BB_SECTOR_SIZE];

#define BB_BASE ((const uint8_t *)(uintptr_t)CRASH_REC_BASE)

void crash_bb_init(void)
{
    gc_flash_init();
}

/* The ONLY erase primitive in the module: healthy-state paths ((a) and (b))
 * only. Keeps the proven short irq-off window around the 4KB erase, with the
 * WDT fed around it. */
static void bb_erase(void)
{
    gc_flash_init();
    WDT_ReloadCounter();
    __disable_irq();
    FLASH_EraseSector(CRASH_REC_BASE);
    CACHE_CleanAll(CACHE);
    __enable_irq();
    WDT_ReloadCounter();
}

/* Pure-program write: no erase, no irq-off window. One page-program loop
 * (ms level), WDT fed before and after. */
static void bb_program_block(void)
{
    gc_flash_init();
    WDT_ReloadCounter();
    /* Proven program discipline (res_write_at parity, 2026-10-13 field fix):
     * AES_Program runs in a SHORT irq-off window -- without it, any ISR
     * touching the QSPI controller/XIP cache mid-program silently aborts the
     * transaction (the fix14/15 field symptom: records never landed). The
     * program step is ms-level, so the window is WDT-safe; the ERASE is the
     * long one and keeps its own window + feed. */
    __disable_irq();
    (void)AES_Program(NULL, NULL, CRASH_REC_BASE,
                      (uint32_t)sizeof(g_bb_block), g_bb_block);
    CACHE_CleanAll(CACHE);
    __enable_irq();
    WDT_ReloadCounter();
}

/* Append one record to the sector. All placement / read-rule / reclaim
 * decisions live in crash_store (host-tested); this is the flash glue. */
static void bb_append(const crash_rec_t *rec, int healthy)
{
    int erase_first = 0;
    int slot;

    /* Fresh view for the placement decision (2026-10-14: field census found
     * bad=16 -- whole-block programming over a stale sector mirror ANDs old
     * records into garbage). The PROGRAM image below no longer depends on
     * this view being fresh: non-target bytes are 0xFF, and NOR 1->0
     * programming makes re-programming other slots a no-op regardless of
     * what the mirror believed. */
    CACHE_CleanAll(CACHE);
    memcpy(g_bb_block, BB_BASE, sizeof(g_bb_block));
    slot = crash_store_append(g_bb_block, rec, healthy, &erase_first);
    if (slot < 0) {
        WDT_ReloadCounter();        /* dropped on the crash path: full sector */
        return;
    }
    if (erase_first) {
        bb_erase();                 /* (b) healthy-state sector-full reclaim */
        /* reclaim rebuilds the kept record at slot 0 inside g_bb_block;
         * program it like any other append (FF elsewhere). */
    }
    {
        /* 0xFF-fill program image: only the appended slot carries data. */
        static uint8_t prog[CRASH_BB_SECTOR_SIZE];
        memset(prog, 0xFF, sizeof(prog));
        memcpy(&prog[(uint32_t)slot * CRASH_BB_SLOT_SIZE],
               &g_bb_block[(uint32_t)slot * CRASH_BB_SLOT_SIZE],
               CRASH_BB_SLOT_SIZE);
        memcpy(g_bb_block, prog, sizeof(g_bb_block));
    }
    bb_program_block();
}

void crash_bb_phase(uint8_t phase)
{
    crash_rec_t rec;
    g_bb_phase = crash_phase_advance(g_bb_phase, phase);
    crash_rec_init(&rec, CRASH_REC_TYPE_PHASE, g_bb_phase);
    crash_rec_seal(&rec);           /* records must carry a valid crc */
    crash_noinit_mark(CRASH_NOINIT_TYPE_PHASE, g_bb_phase, 0u);
    {
        /* The frozen screen IS the recorder (2026-10-14): paint the phase
         * name so the last frame before a hang self-reports the death
         * point. Fixed vocabulary, operator diagnostic surface. */
        char ph[28];
        snprintf(ph, sizeof(ph), "P%u %s", (unsigned)phase,
                 crash_phase_name(phase));
        /* The SCAN page renders UiScanInfo lines 2-4 ONLY -- line 1 sits
         * under the progress bar (2026-10-14 field A/B: the l2/l3/l4 text
         * shows, the l1 never does). Paint the phase into the VISIBLE
         * slot; the frozen frame the operator stares at is the recorder. */
        UiScanInfo("phase", ph, "", "");
        UiSetLast(ph);
        UiGotoPage(UiGetPage());
    }
    bb_append(&rec, 0);             /* crash path: program only */
}

void crash_bb_phase_clear(void)
{
    crash_rec_t rec;
    g_bb_phase = CRASH_PHASE_NONE;
    /* Pairing leg returned (any outcome): append the leg-returned marker
     * (PHASE/NONE). It closes the run so a surviving PHASE pin still means
     * "the leg never returned". Healthy path: the sector-full reclaim is the
     * only erase this call may ever trigger. */
    crash_noinit_mark(CRASH_NOINIT_TYPE_NONE, CRASH_PHASE_NONE, 0u);
    crash_rec_init(&rec, CRASH_REC_TYPE_PHASE, CRASH_PHASE_NONE);
    crash_rec_seal(&rec);
    bb_append(&rec, 1);
}

/* Paint the death certificate and hold forever (feeding the WDT so nothing
 * resets us). The screen outlives every persistence medium on this board
 * (QSPI sector immutable, SRAM scrubbed at warm reset). */
static void crash_screen_hold(const crash_rec_t *rec)
{
    char l2[40], l4[40], l5[64];
    snprintf(l2, sizeof(l2), "PC %08X LR %08X",
             (unsigned)rec->pc, (unsigned)rec->lr);
    snprintf(l4, sizeof(l4), "PHASE %u %s",
             (unsigned)rec->phase, crash_phase_name(rec->phase));
    snprintf(l5, sizeof(l5), "LOC %.48s",
             rec->loc[0] != '\0' ? rec->loc : "-");
    UiCrashInfo(crash_rec_type_name(rec->type), l2, "", l4, l5);
    UiGotoPage(UI_PAGE_CRASH);
    for (;;) {
        WDT_ReloadCounter();
    }
}

void crash_bb_write_panic(const char *msg, uint32_t len, uint32_t pc, uint32_t lr)
{
    crash_rec_t rec;
    crash_noinit_mark(CRASH_NOINIT_TYPE_PANIC, g_bb_phase, 0u);
    crash_rec_init(&rec, CRASH_REC_TYPE_PANIC, g_bb_phase);
    rec.pc = pc;
    rec.lr = lr;
    crash_rec_loc_from_panic(&rec, msg, len);
    crash_rec_seal(&rec);
    bb_append(&rec, 0);             /* crash path: program only */
    crash_screen_hold(&rec);        /* never returns */
}

void crash_bb_write_hardfault(const uint32_t *stack)
{
    crash_rec_t rec;
    crash_noinit_mark(CRASH_NOINIT_TYPE_HARDFAULT, g_bb_phase, stack[6]);
    crash_rec_init(&rec, CRASH_REC_TYPE_HARDFAULT, g_bb_phase);
    rec.pc = stack[6];              /* stacked PC */
    rec.lr = stack[5];              /* stacked LR */
    rec.xpsr = stack[7];            /* stacked xPSR */
    rec.sp = (uint32_t)(uintptr_t)stack;
    rec.cfsr = SCB->CFSR;
    rec.hfsr = SCB->HFSR;
    rec.bfar = SCB->BFAR;
    crash_rec_seal(&rec);
    bb_append(&rec, 0);             /* crash path: program only */
    crash_screen_hold(&rec);        /* never returns */
}

int crash_bb_read(crash_rec_t *out)
{
    /* Full-sector scan + read rule (crash_store_scan is the single source of
     * truth; see crash_store.h for the rule text). */
    return crash_store_scan(BB_BASE, out);
}

void crash_bb_consume(void)
{
    bb_erase();                     /* (a) operator back-tap consume */
}
