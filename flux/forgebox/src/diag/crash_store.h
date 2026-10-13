/* crash_store.h — append-only crash-record log over one 4KB NOR sector.
 *
 * Pure layout + append/read rules (no hardware; host-tested by
 * tests/host_crash). The flash persistence layer lives in crash_blackbox.c.
 *
 * Layout — one sector = 16 slots of 256B (the program granularity); a sealed
 * 104B crash_rec_t sits at the slot head, the slot tail stays 0xFF:
 *
 *     slot 0        slot 1        slot 2        ...        slot 15
 *     +-----------+ +-----------+ +-----------+            +-----------+
 *     |rec | pad  | |rec | pad  | |rec | pad  |    ...     | 0xFF ...  |
 *     +-----------+ +-----------+ +-----------+            +-----------+
 *     0x000        0x100         0x200                      0xF00   (4KB)
 *
 *     pad = 0xFF (unprogrammed NOR). Records are APPENDED in slot order;
 *     slot order = program order = chronological order ("seq" = slot index,
 *     "newest" = highest slot index).
 *
 * Append discipline (NOR programming only turns 1 -> 0; no erase needed):
 *   - a new record is programmed into the FIRST slot whose 256B are all 0xFF;
 *   - the crash path NEVER erases: panic hook / HardFault / PHASE pins
 *     program only (a WDT kill mid-program leaves a half-programmed slot
 *     which fails CRC and is skipped forever - never reused, never valid);
 *   - the only erases are (a) the operator's back-tap consume and (b) the
 *     healthy-state sector-full reclaim before consuming a slot
 *     (crash_store_append with healthy=1; keeps the read-rule winner).
 *
 * READ RULE (crash_store_scan is the single source of truth):
 *   1. scan all 16 slots in order; a slot holds a record iff its first
 *      sizeof(crash_rec_t) bytes pass crash_rec_valid() (magic+ver+enums+
 *      crc) - half-programmed/garbage slots are skipped;
 *   2. if ANY valid PANIC/HARDFAULT record exists -> report the LATEST one
 *      (highest slot). Crash records trump PHASE pins: a PHASE pin written
 *      after a crash record coexists with it in the sector (both survive)
 *      but never shadows it on read - only the operator's consume dismisses
 *      a crash ("an unacknowledged crash must replay on every boot");
 *   3. else if the LATEST valid record is a PHASE pin (type PHASE, phase !=
 *      NONE) -> report it: silent-hang pin - the pairing leg died without
 *      panic/fault and its phase byte is the hang point;
 *   4. else -> nothing to report: the sector is empty, or the latest marker
 *      is the leg-returned marker (type PHASE, phase == NONE; written when
 *      the pairing leg returns - it closes the run and retires the pins
 *      written before it).
 */
#ifndef CRASH_STORE_H
#define CRASH_STORE_H

#include <stdint.h>
#include "crash_record.h"

#define CRASH_BB_SLOT_SIZE   256u
#define CRASH_BB_SECTOR_SIZE 4096u
#define CRASH_BB_SLOTS       (CRASH_BB_SECTOR_SIZE / CRASH_BB_SLOT_SIZE) /* 16 */

/* Pure sector-image helpers (the caller owns a CRASH_BB_SECTOR_SIZE image:
 * RAM copy for writes, the memory-mapped sector for reads). */
int  crash_store_slot_free(const uint8_t *sector, uint32_t slot); /* 1 = all 0xFF */
int  crash_store_find_free(const uint8_t *sector);  /* first free slot, -1 = full */
/* NOR program model: the slot bytes AND with the record block (1 -> 0 only,
 * 0xFF pad is a no-op) - appending never disturbs bytes already there. */
void crash_store_program_slot(uint8_t *sector, uint32_t slot,
                              const crash_rec_t *rec);
/* Read rule above: 1 = report *out, 0 = nothing to report. */
int  crash_store_scan(const uint8_t *sector, crash_rec_t *out);

/* Append one record to the image. Returns the slot it landed in, or -1 when
 * the write is dropped (sector full on the crash path - NEVER erase there).
 * healthy=1 (leg-returned marker / operator-driven) allows the (b) sector-
 * full reclaim: the image is compacted in place (read-rule winner kept at
 * slot 0) and *erase_first is set - the caller must ERASE the physical
 * sector before programming the compacted image back. */
int crash_store_append(uint8_t *sector, const crash_rec_t *rec, int healthy,
                       int *erase_first);

#endif
