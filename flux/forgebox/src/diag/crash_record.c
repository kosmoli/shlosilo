/* crash_record.c — pure crash-record logic (no hardware; see crash_record.h).
 *
 * Compiled both into the firmware and into tests/host_crash with plain gcc. */
#include <string.h>
#include "crash_record.h"

/* Layout pins: the flash writer and the host test both rely on these. */
_Static_assert(sizeof(crash_rec_t) == 104u, "crash_rec_t size pinned");
_Static_assert(offsetof(crash_rec_t, pc) == 8u, "crash_rec_t pc offset pinned");
_Static_assert(offsetof(crash_rec_t, loc) == 36u, "crash_rec_t loc offset pinned");
_Static_assert(offsetof(crash_rec_t, crc) == 100u, "crash_rec_t crc offset pinned");

uint32_t crash_crc32(const uint8_t *data, uint32_t len)
{
    /* Table-less CRC-32 (IEEE 802.3, reflected, init/final 0xFFFFFFFF). */
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

void crash_rec_init(crash_rec_t *r, uint8_t type, uint8_t phase)
{
    memset(r, 0, sizeof(*r));
    r->magic[0] = CRASH_REC_MAGIC0;
    r->magic[1] = CRASH_REC_MAGIC1;
    r->magic[2] = CRASH_REC_MAGIC2;
    r->magic[3] = CRASH_REC_MAGIC3;
    r->ver = CRASH_REC_VER;
    r->type = type;
    r->phase = phase;
}

void crash_rec_seal(crash_rec_t *r)
{
    r->crc = crash_crc32((const uint8_t *)r, (uint32_t)offsetof(crash_rec_t, crc));
}

int crash_rec_valid(const crash_rec_t *r)
{
    if (r->magic[0] != CRASH_REC_MAGIC0 || r->magic[1] != CRASH_REC_MAGIC1 ||
        r->magic[2] != CRASH_REC_MAGIC2 || r->magic[3] != CRASH_REC_MAGIC3) {
        return 0;
    }
    if (r->ver != CRASH_REC_VER) {
        return 0;
    }
    if (r->type > CRASH_REC_TYPE_HARDFAULT) {
        return 0;
    }
    if (r->phase != CRASH_PHASE_NONE && r->phase > CRASH_PHASE_MAX) {
        return 0;
    }
    return r->crc == crash_crc32((const uint8_t *)r, (uint32_t)offsetof(crash_rec_t, crc));
}

void crash_rec_loc_from_panic(crash_rec_t *r, const char *msg, uint32_t len)
{
    const char *tail = NULL;
    uint32_t n;

    r->loc[0] = '\0';
    if (msg == NULL) {
        return;
    }
    if (len > 512u) {
        len = 512u;
    }
    /* The panic handler formats "message @ file:line"; the location is the
     * diagnostic pin and sits at the END, so a plain front-truncation would
     * drop it. Keep the last " @ " suffix when present. */
    for (uint32_t i = 0; i + 3u <= len; i++) {
        if (msg[i] == ' ' && msg[i + 1] == '@' && msg[i + 2] == ' ') {
            tail = &msg[i + 3];
            n = len - (i + 3u);
            if (n > CRASH_LOC_MAX - 1u) {
                n = CRASH_LOC_MAX - 1u;
            }
            memcpy(r->loc, tail, n);
            r->loc[n] = '\0';
            return;
        }
    }
    n = len;
    if (n > CRASH_LOC_MAX - 1u) {
        n = CRASH_LOC_MAX - 1u;
    }
    memcpy(r->loc, msg, n);
    r->loc[n] = '\0';
}

const char *crash_rec_type_name(uint8_t type)
{
    switch (type) {
    case CRASH_REC_TYPE_PHASE:
        return "HANG";        /* phase record left behind = interrupted leg */
    case CRASH_REC_TYPE_PANIC:
        return "PANIC";
    case CRASH_REC_TYPE_HARDFAULT:
        return "HARDFAULT";
    default:
        return "UNKNOWN";
    }
}

const char *crash_phase_name(uint8_t phase)
{
    switch (phase) {
    case CRASH_PHASE_PAIR_ENTER:
        return "PAIRING-ENTER";
    case CRASH_PHASE_PAIR_ALLOC:
        return "PAIRING-ALLOC";
    case CRASH_PHASE_PAIR_FFI_IN:
        return "PAIRING-FFI-IN";
    case CRASH_PHASE_PAIR_LOOP:
        return "PAIRING-LOOP";
    case CRASH_PHASE_PAIR_FFI_OUT:
        return "PAIRING-FFI-OUT";
    case 5:
        return "DECRYPT-IN";
    case 6:
        return "SIG-VERIFY";
    case 7:
        return "CN-DONE";
    case 8:
        return "OWNERSHIP";
    case 9:
        return "PARSED";
    case 10:
        return "SIG-OK";
    default:
        return "NONE";
    }
}

int crash_phase_transition_ok(uint8_t from, uint8_t to)
{
    if (to == CRASH_PHASE_NONE) {
        return 1;                 /* clear */
    }
    if (to == CRASH_PHASE_PAIR_ENTER) {
        return 1;                 /* new pairing run restarts at 0 */
    }
    if (to == from) {
        return 1;                 /* idempotent re-mark */
    }
    if (from != CRASH_PHASE_NONE && from < CRASH_PHASE_MAX &&
        to == (uint8_t)(from + 1u)) {
        return 1;                 /* monotonic advance inside one run */
    }
    return 0;
}

uint8_t crash_phase_advance(uint8_t from, uint8_t to)
{
    return crash_phase_transition_ok(from, to) ? to : from;
}
