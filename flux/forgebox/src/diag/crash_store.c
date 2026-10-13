/* crash_store.c — pure append-log logic (no hardware; see crash_store.h).
 *
 * Compiled both into the firmware and into tests/host_crash with plain gcc. */
#include <string.h>
#include <stddef.h>
#include "crash_store.h"

/* Layout pins: the flash writer and the host test both rely on these. */
_Static_assert(sizeof(crash_rec_t) == 104u, "crash_rec_t size pinned");
_Static_assert(sizeof(crash_rec_t) <= CRASH_BB_SLOT_SIZE,
               "record fits in one slot");
_Static_assert((CRASH_BB_SECTOR_SIZE % CRASH_BB_SLOT_SIZE) == 0u,
               "slots tile the sector exactly");

static const uint8_t *slot_cptr(const uint8_t *sector, uint32_t slot)
{
    return sector + slot * CRASH_BB_SLOT_SIZE;
}

int crash_store_slot_free(const uint8_t *sector, uint32_t slot)
{
    const uint8_t *p = slot_cptr(sector, slot);
    for (uint32_t i = 0; i < CRASH_BB_SLOT_SIZE; i++) {
        if (p[i] != 0xFFu) {
            return 0;
        }
    }
    return 1;
}

int crash_store_find_free(const uint8_t *sector)
{
    for (uint32_t s = 0; s < CRASH_BB_SLOTS; s++) {
        if (crash_store_slot_free(sector, s)) {
            return (int)s;
        }
    }
    return -1;
}

void crash_store_program_slot(uint8_t *sector, uint32_t slot,
                              const crash_rec_t *rec)
{
    uint8_t *p = sector + slot * CRASH_BB_SLOT_SIZE;
    const uint8_t *src = (const uint8_t *)rec;
    /* NOR program = bitwise AND (1 -> 0 only). The slot tail (bytes beyond
     * the record) is 0xFF in the block and ANDing 0xFF is a no-op. */
    for (uint32_t i = 0; i < sizeof(*rec); i++) {
        p[i] &= src[i];
    }
}

int crash_store_scan(const uint8_t *sector, crash_rec_t *out)
{
    crash_rec_t rec;
    crash_rec_t newest;             /* newest valid record of any type */
    crash_rec_t newest_crash;       /* newest valid PANIC/HARDFAULT */
    int have_newest = 0;
    int have_crash = 0;

    for (uint32_t s = 0; s < CRASH_BB_SLOTS; s++) {
        memcpy(&rec, slot_cptr(sector, s), sizeof(rec));
        if (!crash_rec_valid(&rec)) {
            continue;               /* empty, half-programmed or foreign */
        }
        newest = rec;
        have_newest = 1;
        if (rec.type == CRASH_REC_TYPE_PANIC ||
            rec.type == CRASH_REC_TYPE_HARDFAULT) {
            newest_crash = rec;
            have_crash = 1;
        }
    }

    /* READ RULE (see crash_store.h): crash records trump PHASE pins and are
     * only dismissed by consumption; a lone newest PHASE pin is the
     * silent-hang pin; anything else (leg-returned marker on top, empty
     * sector) reports nothing. */
    if (have_crash) {
        *out = newest_crash;
        return 1;
    }
    if (have_newest && newest.type == CRASH_REC_TYPE_PHASE &&
        newest.phase != CRASH_PHASE_NONE) {
        *out = newest;
        return 1;
    }
    return 0;
}

int crash_store_append(uint8_t *sector, const crash_rec_t *rec, int healthy,
                       int *erase_first)
{
    int slot = crash_store_find_free(sector);

    if (erase_first != NULL) {
        *erase_first = 0;
    }
    if (slot < 0) {
        crash_rec_t winner;
        int have;

        if (!healthy) {
            return -1;              /* crash path: drop the write, NEVER erase */
        }
        /* (b) sector-full pre-consumption compaction (healthy state only):
         * collapse the sector to its read-rule winner so an unconsumed crash
         * record survives the erase, then continue the append past it. */
        have = crash_store_scan(sector, &winner);
        memset(sector, 0xFF, CRASH_BB_SECTOR_SIZE);
        if (have) {
            crash_store_program_slot(sector, 0, &winner);
        }
        if (erase_first != NULL) {
            *erase_first = 1;
        }
        slot = crash_store_find_free(sector);
        if (slot < 0) {
            return -1;
        }
    }
    crash_store_program_slot(sector, (uint32_t)slot, rec);
    return slot;
}
