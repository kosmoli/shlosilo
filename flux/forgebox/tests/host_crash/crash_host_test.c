/* crash_host_test.c — host test for the crash-forensics record logic.
 *
 * Covers everything that does not need flash/FreeRTOS (those parts stay
 * firmware-only behind static discipline):
 *   - record struct layout pins (size + offsets, both static and runtime),
 *   - crc32 known-answer vector,
 *   - seal/valid round trip + tamper detection on every field region,
 *   - panic-message -> loc extraction (the " @ file:line" tail pin),
 *   - the pairing-phase state machine (monotonic 0..4, restart, idempotent,
 *     invalid skips refused, NONE clear).
 *
 * Build/run: bash run.sh  (plain gcc; see run.sh). */
#include <stdio.h>
#include <string.h>
#include "crash_record.h"

static int failures;

static void check(int cond, const char *what)
{
    if (cond) {
        printf("ok   %s\n", what);
    } else {
        printf("FAIL %s\n", what);
        failures++;
    }
}

int main(void)
{
    crash_rec_t r, r2;

    /* ---- layout pins (static asserts live in crash_record.c too) ---- */
    _Static_assert(sizeof(crash_rec_t) == 104u, "size");
    _Static_assert(offsetof(crash_rec_t, pc) == 8u, "pc offset");
    _Static_assert(offsetof(crash_rec_t, loc) == 36u, "loc offset");
    _Static_assert(offsetof(crash_rec_t, crc) == 100u, "crc offset");
    check(sizeof(crash_rec_t) == 104u, "layout: sizeof == 104");
    check(offsetof(crash_rec_t, phase) == 6u, "layout: phase at 6");

    /* ---- crc32 known answer ("123456789" -> 0xCBF43926) ---- */
    check(crash_crc32((const uint8_t *)"123456789", 9) == 0xCBF43926u,
          "crc32: IEEE vector");

    /* ---- seal/valid round trip ---- */
    crash_rec_init(&r, CRASH_REC_TYPE_PANIC, CRASH_PHASE_PAIR_FFI_IN);
    r.pc = 0x0801ABCDu;
    r.lr = 0x08021234u;
    check(!crash_rec_valid(&r), "valid: unsealed record rejected");
    crash_rec_seal(&r);
    check(crash_rec_valid(&r), "valid: sealed record accepted");
    check(r.type == CRASH_REC_TYPE_PANIC && r.phase == CRASH_PHASE_PAIR_FFI_IN,
          "seal keeps type/phase");

    /* tamper detection across field regions */
    r2 = r; r2.pc ^= 1u;
    check(!crash_rec_valid(&r2), "tamper: pc caught");
    r2 = r; r2.phase = CRASH_PHASE_PAIR_LOOP;
    check(!crash_rec_valid(&r2), "tamper: phase caught");
    r2 = r; r2.loc[3] ^= 0x20;
    check(!crash_rec_valid(&r2), "tamper: loc caught");
    r2 = r; r2.magic[0] ^= 0xFF;
    check(!crash_rec_valid(&r2), "tamper: magic caught");
    r2 = r; r2.ver = 2;
    check(!crash_rec_valid(&r2), "tamper: ver caught");
    r2 = r; r2.type = 7;
    crash_rec_seal(&r2);
    check(!crash_rec_valid(&r2), "enum: out-of-range type rejected even sealed");
    r2 = r; r2.phase = 5;
    crash_rec_seal(&r2);
    check(!crash_rec_valid(&r2), "enum: out-of-range phase rejected even sealed");

    /* erased-sector shape is never a record */
    memset(&r2, 0xFF, sizeof(r2));
    check(!crash_rec_valid(&r2), "erased flash (0xFF) rejected");

    /* ---- panic message -> loc ---- */
    crash_rec_init(&r, CRASH_REC_TYPE_PANIC, CRASH_PHASE_PAIR_LOOP);
    crash_rec_loc_from_panic(
        &r,
        "ready flag implies table present @ vendor/monero-bulletproofs/src/generator_cache_hook.rs:297",
        93);
    check(strcmp(r.loc, "vendor/monero-bulletproofs/src/generator_cache_hook.rs:297") == 0,
          "loc: file:line tail kept");
    crash_rec_loc_from_panic(&r, "short message", 13);
    check(strcmp(r.loc, "short message") == 0, "loc: bare message kept");
    {
        char long_msg[200];
        memset(long_msg, 'x', sizeof(long_msg));
        memcpy(long_msg + 160, " @ a/b.rs:7", 11);
        crash_rec_loc_from_panic(&r, long_msg, 171);
        check(strcmp(r.loc, "a/b.rs:7") == 0, "loc: tail wins over front truncation");
        check(strlen(r.loc) < CRASH_LOC_MAX, "loc: always NUL-terminated < 64");
    }

    /* ---- phase state machine ---- */
    check(crash_phase_transition_ok(0, 1), "phase: 0->1 ok");
    check(crash_phase_transition_ok(1, 2), "phase: 1->2 ok");
    check(crash_phase_transition_ok(2, 3), "phase: 2->3 ok");
    check(crash_phase_transition_ok(3, 4), "phase: 3->4 ok");
    check(crash_phase_transition_ok(4, 0), "phase: 4->0 restart ok");
    check(crash_phase_transition_ok(1, 0), "phase: 1->0 restart ok (stale trail)");
    check(crash_phase_transition_ok(CRASH_PHASE_NONE, 0), "phase: NONE->0 ok");
    check(crash_phase_transition_ok(2, 2), "phase: idempotent ok");
    check(crash_phase_transition_ok(4, 4), "phase: 4->4 idempotent ok");
    check(crash_phase_transition_ok(2, CRASH_PHASE_NONE), "phase: clear ok");
    check(!crash_phase_transition_ok(0, 2), "phase: 0->2 skip refused");
    check(!crash_phase_transition_ok(2, 1), "phase: backward refused");
    check(!crash_phase_transition_ok(4, 3), "phase: backward from 4 refused");
    check(!crash_phase_transition_ok(CRASH_PHASE_NONE, 3),
          "phase: NONE->3 refused (no cold jump)");

    check(crash_phase_advance(0, 2) == 0, "advance: invalid keeps old");
    check(crash_phase_advance(0, 1) == 1, "advance: valid moves");
    {
        uint8_t s = CRASH_PHASE_NONE;
        s = crash_phase_advance(s, 0);
        s = crash_phase_advance(s, 1);
        s = crash_phase_advance(s, 2);
        s = crash_phase_advance(s, 3);
        s = crash_phase_advance(s, 3);   /* idempotent re-mark */
        s = crash_phase_advance(s, 4);
        check(s == 4, "advance: full pairing run 0..4");
    }

    /* fixed vocabulary names */
    check(strcmp(crash_rec_type_name(CRASH_REC_TYPE_PHASE), "HANG") == 0,
          "vocab: phase record reads HANG");
    check(strcmp(crash_phase_name(CRASH_PHASE_PAIR_LOOP), "PAIRING-LOOP") == 0,
          "vocab: loop phase name");

    if (failures != 0) {
        printf("%d FAILURES\n", failures);
        return 1;
    }
    printf("all crash-record host tests passed\n");
    return 0;
}
