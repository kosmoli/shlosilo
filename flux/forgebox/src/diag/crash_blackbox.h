/* crash_blackbox.h — crash-forensics blackbox: QSPI NOR persistence.
 *
 * One 4KB sector (0x01E42000, the historical FAULT/panic record sector) holds
 * an APPEND-ONLY log of sealed crash_rec_t records (fix15; layout and rules
 * in crash_store.h, host-tested):
 *
 *   +--------------------------------------------------------------+
 *   | 4KB sector @ 0x01E42000 = 16 slots x 256B (program granularity)|
 *   | slot 0: [rec 104B | 0xFF pad]  slot 1: [rec | pad] ... slot 15 |
 *   | append order = slot order = chronological ("newest" = last)    |
 *   +--------------------------------------------------------------+
 *
 * Record types:
 *   - type PHASE (phase 0..4) : pin written before each pairing phase
 *     (silent-hang pin); a surviving pin means the leg never returned;
 *   - type PHASE (phase NONE) : leg-returned marker (written when the
 *     pairing leg returns - closes the run, retires older pins);
 *   - type PANIC              : written by the Rust panic hook;
 *   - type HARDFAULT          : written by hardfault_diag.c before the WDT
 *     reset.
 *
 * READ RULE (boot peek; implemented once in crash_store_scan):
 *   1. scan all slots; a slot counts iff its CRC validates (half-programmed
 *      slots are skipped and never reused);
 *   2. any valid PANIC/HARDFAULT -> report the newest one (crash records
 *      trump PHASE pins and are dismissed ONLY by the operator's consume -
 *      PHASE pins written after a crash coexist with it but never shadow
 *      it);
 *   3. else the newest record being a PHASE pin -> report it (silent-hang
 *      pin, its phase byte is the hang point);
 *   4. else report nothing (empty sector, or the leg-returned marker is on
 *      top).
 *
 * WRITE RULE (WDT safety): the crash path (panic hook / HardFault / PHASE
 * pins) is PURE PROGRAM (NOR 1 -> 0), never erase - a WDT kill mid-write can
 * only leave a half-programmed slot that reads as invalid. Erase happens
 * only in healthy state: (a) the operator's back-tap consume, (b) the
 * sector-full reclaim before consuming a slot (keeps the read-rule winner).
 * The write path feeds the WDT and keeps interrupts enabled (no irq-off
 * window); only the healthy-state erase keeps the proven short irq-off
 * window.
 *
 * Write path is deliberately minimal: no LVGL, no heap, no RTOS delay — the
 * hardfault path runs with the scheduler dead. */
#ifndef CRASH_BLACKBOX_H
#define CRASH_BLACKBOX_H

#include <stdint.h>
#include "crash_record.h"

#define CRASH_REC_BASE 0x01E42000u /* 4KB sector, same record area as the
                                    * legacy 'RSLT' fault/panic records */

void crash_bb_init(void);              /* flash write-access bring-up */
uint8_t crash_bb_phase_cur(void);      /* current pairing phase marker */

/* Phase pin: validates the transition (crash_phase_advance), then seals a
 * PHASE record into the next free slot (program only). Also the Rust-side
 * hook target (shlosilo_crash_phase_set_hook). */
void crash_bb_phase(uint8_t phase);
/* Pairing leg returned (clean or failed): append the leg-returned marker
 * (PHASE/NONE). Append-only; the healthy-state sector-full reclaim is the
 * only erase this path may trigger. */
void crash_bb_phase_clear(void);

void crash_bb_write_panic(const char *msg, uint32_t len, uint32_t pc, uint32_t lr);
void crash_bb_write_hardfault(const uint32_t *stack);

int crash_bb_read(crash_rec_t *out);   /* 1 = a reportable record (read rule) */
void crash_bb_consume(void);           /* erase: back-tap acknowledge */

#endif
