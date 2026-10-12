/* crash_blackbox.h — crash-forensics blackbox: QSPI NOR persistence.
 *
 * One 4KB sector (0x01E42000, the historical FAULT/panic record sector) holds
 * ONE sealed crash_rec_t padded to a 256B block:
 *   - type PHASE      : written before each pairing phase (silent-hang pin);
 *   - type PANIC      : written by the Rust panic hook;
 *   - type HARDFAULT  : written by hardfault_diag.c before the WDT reset.
 * The pairing leg erases the sector again when it RETURNS (any outcome) — a
 * surviving phase record therefore means the leg never returned. Boot reads
 * the record; the operator's back tap consumes (erases) it.
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

/* Phase marker: validates the transition (crash_phase_advance), then seals a
 * PHASE record to flash. Also the Rust-side hook target
 * (shlosilo_crash_phase_set_hook). */
void crash_bb_phase(uint8_t phase);
/* Pairing leg returned (clean or failed): erase the record area. */
void crash_bb_phase_clear(void);

void crash_bb_write_panic(const char *msg, uint32_t len, uint32_t pc, uint32_t lr);
void crash_bb_write_hardfault(const uint32_t *stack);

int crash_bb_read(crash_rec_t *out);   /* 1 = valid sealed record present */
void crash_bb_consume(void);           /* erase: back-tap acknowledge */

#endif
