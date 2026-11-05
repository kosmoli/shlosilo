/* hardfault_diag.c — K2-D diagnostics: the real HardFault handler
 *
 * Previously a HardFault fell into startup's weak Default_Handler (infinite
 * loop) -> WDT reset after 2s, losing all fault information (the export
 * alignment incident; the two blind reflashes after the crash on cn5).
 * This handler captures the fault: reads the SCB fault status registers and
 * pulls the stacked PC/LR out of the stack frame, writes them into the
 * .diag_noinit retention area, then triggers a WDT reset on purpose.
 * After the reboot the smoke task reads that area at startup and prints the
 * registers to the screen.
 *
 * 2026-09-30 fix: the record area used to live at 0x2000F004 (commented as
 * "0x2000F000 is not taken by .bss"), but g_lvglCache had long covered that
 * address — clearing .bss at boot wiped the record, so the diagnostics never
 * worked. It now lives in .diag_noinit in mh1903b.ld (0x20098800, NOLOAD:
 * not zeroed at boot, retained across a warm WDT reset).
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "mhscpu.h"
#include "crash_blackbox.h"

/* Read by smoke after reset. Layout: [magic][cfsr][hfsr][bfar][pc][lr][xpsr] */
#define FAULT_MAGIC 0x464C5444U /* 'FLTD' */
volatile uint32_t g_fault_log[7] __attribute__((section(".diag_noinit")));

/* naked: only fetch the exception stack frame (the 8 words pushed automatically when the smoke task faults) */
__attribute__((naked)) void HardFault_Handler(void)
{
    __asm__ volatile(
        "tst   lr, #4          \n"
        "ite   eq              \n"
        "mrseq r0, msp         \n"
        "mrsne r0, psp         \n"
        "b     hardfault_capture\n");
}

void hardfault_capture(uint32_t *stack) __attribute__((noreturn));
void hardfault_capture(uint32_t *stack)
{
    g_fault_log[0] = FAULT_MAGIC;
    g_fault_log[1] = SCB->CFSR;
    g_fault_log[2] = SCB->HFSR;
    g_fault_log[3] = SCB->BFAR;
    g_fault_log[4] = stack[6]; /* stacked PC */
    g_fault_log[5] = stack[5]; /* stacked LR */
    g_fault_log[6] = stack[7]; /* stacked xPSR */

    /* Persist the fault record before anything else. The blackbox writes a
     * sealed crash_rec_t (type HARDFAULT + SCB regs + stacked PC/LR/xPSR/SP +
     * pairing-phase marker) into the record sector and then paints the death
     * certificate and holds the screen (crash_screen_hold: never returns, WDT
     * fed forever) -- on this board the QSPI record sector is read-only and
     * the warm reset scrubs the SRAM noinit slots, so the frozen screen is
     * the only medium that outlives the crash. The flash attempt is kept
     * (harmless, ms-level) for boards where it lands; the WDT-reset tail
     * below is only a defensive fallback for a write path that ever returns. */
    crash_bb_write_hardfault(stack);

    /* Active reset: the shortest WDT window is enough */
    WDT_ModeConfig(WDT_Mode_CPUReset);
    WDT_SetReload(0x10U);
    WDT_ReloadCounter();
    WDT_Enable();
    for (;;) {
        __asm__ volatile("wfi");
    }
}
