/* crash_record.h — crash-forensics blackbox record: PURE layout + validation.
 *
 * Host-testable: this header and crash_record.c touch no hardware (stdint +
 * string only) so tests/host_crash can compile them with plain gcc. The flash
 * persistence layer lives in crash_blackbox.c.
 *
 * Record layout (packed, 104 bytes; the flash block pads to 256 with 0xFF):
 *   [0..4)   magic "CRF1"
 *   [4]      ver (1)
 *   [5]      type (0 phase marker | 1 panic | 2 hardfault)
 *   [6]      pairing phase (0..10, 0xFF = none)
 *   [7]      flags (reserved, 0)
 *   [8..36)  pc, lr, xpsr, cfsr, hfsr, bfar, sp (u32 LE each)
 *   [36..100) panic location string ("file:line"), NUL-padded, truncated 64B
 *   [100..104) crc32 over bytes [0..100)
 */
#ifndef CRASH_RECORD_H
#define CRASH_RECORD_H

#include <stdint.h>
#include <stddef.h>

#define CRASH_REC_MAGIC0 'C'
#define CRASH_REC_MAGIC1 'R'
#define CRASH_REC_MAGIC2 'F'
#define CRASH_REC_MAGIC3 '1'
#define CRASH_REC_VER    1u
#define CRASH_LOC_MAX    64u

/* Record types (fixed vocabulary on the operator page). */
#define CRASH_REC_TYPE_PHASE      0u
#define CRASH_REC_TYPE_PANIC      1u
#define CRASH_REC_TYPE_HARDFAULT  2u

/* Pairing-phase markers: written before each key phase of the pairing leg so
 * a silent hang (WDT reset, no panic screen) still pins the hang point.
 * 0=enter pairing 1=alloc done 2=ffi enter 3=before per-output loop 4=ffi back
 * 5=decrypt-in 6=sig-verify 7=cn-done 8=ownership 9=parsed 10=sig-ok */
#define CRASH_PHASE_PAIR_ENTER   0u
#define CRASH_PHASE_PAIR_ALLOC   1u
#define CRASH_PHASE_PAIR_FFI_IN  2u
#define CRASH_PHASE_PAIR_LOOP    3u
#define CRASH_PHASE_PAIR_FFI_OUT 4u
#define CRASH_PHASE_DECRYPT_IN   5u
#define CRASH_PHASE_SIG_VERIFY   6u
#define CRASH_PHASE_CN_DONE      7u
#define CRASH_PHASE_OWNERSHIP    8u
#define CRASH_PHASE_PARSED       9u
#define CRASH_PHASE_SIG_OK       10u
#define CRASH_PHASE_MAX          10u
#define CRASH_PHASE_NONE         0xFFu

typedef struct {
    uint8_t  magic[4];
    uint8_t  ver;
    uint8_t  type;
    uint8_t  phase;
    uint8_t  flags;
    uint32_t pc;
    uint32_t lr;
    uint32_t xpsr;
    uint32_t cfsr;
    uint32_t hfsr;
    uint32_t bfar;
    uint32_t sp;
    char     loc[CRASH_LOC_MAX];
    uint32_t crc;
} crash_rec_t;

/* ---- pure record helpers (host-tested) ---- */
uint32_t crash_crc32(const uint8_t *data, uint32_t len);
void crash_rec_init(crash_rec_t *r, uint8_t type, uint8_t phase);
void crash_rec_seal(crash_rec_t *r);              /* fill crc */
int  crash_rec_valid(const crash_rec_t *r);       /* 1 = magic+ver+crc+enums OK */
/* Panic message -> loc field: keep the " @ file:line" tail when present,
 * else the truncated message itself (never more than 63 bytes + NUL). */
void crash_rec_loc_from_panic(crash_rec_t *r, const char *msg, uint32_t len);
const char *crash_rec_type_name(uint8_t type);
const char *crash_phase_name(uint8_t phase);

/* ---- phase-marker state machine (host-tested) ---- */
/* Legal transitions: ->NONE (clear), ->0 (new pairing run), ->same (idempotent),
 * ->prev+1 (monotonic advance within one run). Everything else is refused. */
int      crash_phase_transition_ok(uint8_t from, uint8_t to);
uint8_t  crash_phase_advance(uint8_t from, uint8_t to); /* to if legal else from */

#endif
