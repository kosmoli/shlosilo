/* crash_host_test.c — host test for the crash-forensics record logic.
 *
 * Covers everything that does not need flash/FreeRTOS (those parts stay
 * firmware-only behind static discipline):
 *   - record struct layout pins (size + offsets, both static and runtime),
 *   - crc32 known-answer vector,
 *   - seal/valid round trip + tamper detection on every field region,
 *   - panic-message -> loc extraction (the " @ file:line" tail pin),
 *   - the pairing-phase state machine (monotonic 0..4, restart, idempotent,
 *     invalid skips refused, NONE clear),
 *   - the append-log store (crash_store): slot placement on a NOR image
 *     (1->0 program model), multi-append newest-wins, consume-erase read
 *     empty, half-programmed record rejected (and its slot never reused),
 *     the PHASE/PANIC coexistence read rule, and full-sector behavior
 *     (crash path drops / healthy path reclaims keeping the winner).
 *
 * Build/run: bash run.sh  (plain gcc; see run.sh). */
#include <stdio.h>
#include <string.h>
#include "crash_record.h"
#include "crash_store.h"

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

/* ---- append-log helpers (NOR sector image model) ---- */
static uint8_t g_img[CRASH_BB_SECTOR_SIZE];

static void img_erase(void)
{
    memset(g_img, 0xFF, sizeof(g_img));
}

static void img_make_pin(crash_rec_t *r, uint8_t phase)
{
    crash_rec_init(r, CRASH_REC_TYPE_PHASE, phase);
    crash_rec_seal(r);
}

static void img_make_crash(crash_rec_t *r, uint8_t type, uint8_t phase,
                           uint32_t pc)
{
    crash_rec_init(r, type, phase);
    r->pc = pc;
    crash_rec_seal(r);
}

static int img_count_valid(void)
{
    crash_rec_t rec;
    int n = 0;
    for (uint32_t s = 0; s < CRASH_BB_SLOTS; s++) {
        memcpy(&rec, &g_img[s * CRASH_BB_SLOT_SIZE], sizeof(rec));
        if (crash_rec_valid(&rec)) {
            n++;
        }
    }
    return n;
}

/* Simulate a WDT kill mid-program: only the first n bytes of the record block
 * reach the NOR (1->0 AND model, like crash_store_program_slot). */
static void img_program_partial(uint32_t slot, const crash_rec_t *rec,
                                uint32_t nbytes)
{
    const uint8_t *src = (const uint8_t *)rec;
    uint8_t *p = &g_img[slot * CRASH_BB_SLOT_SIZE];
    if (nbytes > sizeof(*rec)) {
        nbytes = sizeof(*rec);
    }
    for (uint32_t i = 0; i < nbytes; i++) {
        p[i] &= src[i];
    }
}

static void append_log_tests(void)
{
    crash_rec_t rec, out;
    int slot;
    int erase_first;

    /* ---- slot layout ---- */
    check(CRASH_BB_SLOTS == 16u && CRASH_BB_SLOT_SIZE == 256u,
          "store: 16 x 256B slots tile the 4KB sector");
    img_erase();
    check(crash_store_find_free(g_img) == 0, "store: fresh image first free = 0");
    img_make_pin(&rec, CRASH_PHASE_PAIR_ENTER);
    erase_first = 99;
    slot = crash_store_append(g_img, &rec, 0, &erase_first);
    check(slot == 0 && erase_first == 0, "store: append lands in slot 0, no erase");
    check(!crash_store_slot_free(g_img, 0) &&
          crash_store_find_free(g_img) == 1,
          "store: programmed slot taken, next free = 1");

    /* ---- append several -> read the newest ---- */
    img_erase();
    img_make_pin(&rec, CRASH_PHASE_PAIR_ENTER);
    crash_store_append(g_img, &rec, 0, NULL);
    img_make_pin(&rec, CRASH_PHASE_PAIR_ALLOC);
    crash_store_append(g_img, &rec, 0, NULL);
    img_make_pin(&rec, CRASH_PHASE_PAIR_FFI_IN);
    crash_store_append(g_img, &rec, 0, NULL);
    check(crash_store_scan(g_img, &out) == 1 && out.phase == CRASH_PHASE_PAIR_FFI_IN,
          "append: several pins -> newest pin wins");
    img_make_crash(&rec, CRASH_REC_TYPE_PANIC, CRASH_PHASE_PAIR_FFI_IN, 0x0800CAFEu);
    crash_store_append(g_img, &rec, 0, NULL);
    check(crash_store_scan(g_img, &out) == 1 && out.type == CRASH_REC_TYPE_PANIC &&
              out.pc == 0x0800CAFEu,
          "append: record fields survive the round trip");

    /* ---- consume (erase) -> read empty ---- */
    img_erase();
    check(crash_store_scan(g_img, &out) == 0, "consume: erased sector reads empty");
    img_make_pin(&rec, CRASH_PHASE_PAIR_LOOP);
    crash_store_append(g_img, &rec, 0, NULL);
    img_erase();                        /* operator back-tap consume */
    check(crash_store_scan(g_img, &out) == 0,
          "consume: erase after appends -> read empty");

    /* ---- half-programmed record rejected ---- */
    img_erase();
    img_make_crash(&rec, CRASH_REC_TYPE_PANIC, CRASH_PHASE_PAIR_LOOP, 0x1111u);
    crash_store_append(g_img, &rec, 0, NULL);       /* slot 0: valid crash */
    img_make_pin(&rec, CRASH_PHASE_PAIR_FFI_OUT);
    img_program_partial(1, &rec, 60u);              /* WDT kill mid-record */
    check(crash_store_scan(g_img, &out) == 1 && out.pc == 0x1111u,
          "half-program: damaged slot skipped, earlier record reported");
    check(!crash_store_slot_free(g_img, 1),
          "half-program: damaged slot is not free (never reused)");
    check(crash_store_find_free(g_img) == 2,
          "half-program: append moves past the damaged slot");
    img_program_partial(2, &rec, 102u);             /* kill inside the crc */
    {
        crash_rec_t damaged;
        memcpy(&damaged, &g_img[2 * CRASH_BB_SLOT_SIZE], sizeof(damaged));
        check(!crash_rec_valid(&damaged),
              "half-program: crc-region cut record rejected");
    }
    check(crash_store_find_free(g_img) == 3,
          "half-program: crc-cut slot also skipped");

    /* ---- PHASE + PANIC coexistence read rule ---- */
    img_erase();
    img_make_pin(&rec, CRASH_PHASE_PAIR_ENTER);
    crash_store_append(g_img, &rec, 0, NULL);
    img_make_pin(&rec, CRASH_PHASE_PAIR_ALLOC);
    crash_store_append(g_img, &rec, 0, NULL);
    img_make_crash(&rec, CRASH_REC_TYPE_HARDFAULT, CRASH_PHASE_PAIR_ALLOC, 0x2222u);
    crash_store_append(g_img, &rec, 0, NULL);
    check(crash_store_scan(g_img, &out) == 1 && out.type == CRASH_REC_TYPE_HARDFAULT &&
              out.pc == 0x2222u,
          "rule: crash after pins -> crash record wins");

    img_erase();
    img_make_crash(&rec, CRASH_REC_TYPE_PANIC, CRASH_PHASE_PAIR_FFI_IN, 0x3333u);
    crash_store_append(g_img, &rec, 0, NULL);       /* stale crash at slot 0 */
    img_make_pin(&rec, CRASH_PHASE_PAIR_ALLOC);
    crash_store_append(g_img, &rec, 0, NULL);       /* later pins coexist */
    img_make_pin(&rec, CRASH_PHASE_PAIR_LOOP);
    crash_store_append(g_img, &rec, 0, NULL);
    check(img_count_valid() == 3,
          "rule: pins written after a crash coexist with it (all valid)");
    check(crash_store_scan(g_img, &out) == 1 && out.type == CRASH_REC_TYPE_PANIC &&
              out.pc == 0x3333u,
          "rule: newer pins never shadow the crash record");

    img_erase();
    img_make_pin(&rec, CRASH_PHASE_PAIR_ALLOC);
    crash_store_append(g_img, &rec, 0, NULL);
    img_make_pin(&rec, CRASH_PHASE_PAIR_FFI_OUT);
    crash_store_append(g_img, &rec, 0, NULL);
    check(crash_store_scan(g_img, &out) == 1 && out.phase == CRASH_PHASE_PAIR_FFI_OUT,
          "rule: newest PHASE pin, no crash = silent-hang pin");

    img_erase();
    img_make_pin(&rec, CRASH_PHASE_PAIR_LOOP);
    crash_store_append(g_img, &rec, 0, NULL);
    img_make_pin(&rec, CRASH_PHASE_NONE);           /* leg-returned marker */
    crash_store_append(g_img, &rec, 1, NULL);
    check(crash_store_scan(g_img, &out) == 0,
          "rule: leg-returned marker on top retires the pins");
    img_erase();
    img_make_pin(&rec, CRASH_PHASE_NONE);
    crash_store_append(g_img, &rec, 1, NULL);
    check(crash_store_scan(g_img, &out) == 0, "rule: lone leg-returned marker -> nothing");

    img_erase();
    img_make_pin(&rec, CRASH_PHASE_PAIR_FFI_OUT);   /* run 1 ended */
    crash_store_append(g_img, &rec, 0, NULL);
    img_make_pin(&rec, CRASH_PHASE_NONE);
    crash_store_append(g_img, &rec, 1, NULL);
    img_make_pin(&rec, CRASH_PHASE_PAIR_ENTER);     /* run 2 hangs */
    crash_store_append(g_img, &rec, 0, NULL);
    img_make_pin(&rec, CRASH_PHASE_PAIR_ALLOC);
    crash_store_append(g_img, &rec, 0, NULL);
    check(crash_store_scan(g_img, &out) == 1 && out.phase == CRASH_PHASE_PAIR_ALLOC,
          "rule: pins after a marker = new open run, newest wins");

    /* ---- full-sector behavior ---- */
    img_erase();
    {
        int i;
        for (i = 0; i < (int)CRASH_BB_SLOTS; i++) {
            img_make_pin(&rec, (uint8_t)(i % (CRASH_PHASE_MAX + 1u)));
            erase_first = 99;
            slot = crash_store_append(g_img, &rec, 0, &erase_first);
            if (slot != i || erase_first != 0) {
                break;
            }
        }
        check(i == (int)CRASH_BB_SLOTS, "full: 16 appends fill the sector");
    }
    check(crash_store_find_free(g_img) == -1, "full: find_free reports full");
    check(crash_store_scan(g_img, &out) == 1,
          "full: scan still reports the newest record");

    {
        uint8_t snapshot[CRASH_BB_SECTOR_SIZE];
        memcpy(snapshot, g_img, sizeof(snapshot));
        img_make_crash(&rec, CRASH_REC_TYPE_PANIC, CRASH_PHASE_PAIR_LOOP, 0x4444u);
        erase_first = 99;
        slot = crash_store_append(g_img, &rec, 0, &erase_first);
        check(slot == -1 && erase_first == 0,
              "full: crash-path append drops (never erases)");
        check(memcmp(snapshot, g_img, sizeof(snapshot)) == 0,
              "full: dropped append leaves the sector untouched");
    }

    img_erase();                        /* 15 pins + 1 crash = full */
    {
        int i;
        for (i = 0; i < (int)CRASH_BB_SLOTS - 1; i++) {
            img_make_pin(&rec, (uint8_t)(i % (CRASH_PHASE_MAX + 1u)));
            crash_store_append(g_img, &rec, 0, NULL);
        }
        img_make_crash(&rec, CRASH_REC_TYPE_PANIC, CRASH_PHASE_PAIR_LOOP, 0x5555u);
        crash_store_append(g_img, &rec, 0, NULL);
    }
    img_make_pin(&rec, CRASH_PHASE_NONE);           /* leg-returned marker */
    erase_first = 99;
    slot = crash_store_append(g_img, &rec, 1, &erase_first);
    check(slot == 1 && erase_first == 1,
          "full: healthy append reclaims (erase flagged) then lands");
    check(crash_store_find_free(g_img) == 2, "full: reclaimed sector has room");
    check(crash_store_scan(g_img, &out) == 1 && out.pc == 0x5555u,
          "full: reclaim keeps the read-rule winner (crash replays)");
    {
        crash_rec_t winner;
        memcpy(&winner, g_img, sizeof(winner));
        check(crash_rec_valid(&winner) && winner.pc == 0x5555u,
              "full: winner sealed at slot 0 after reclaim");
    }

    img_erase();
    {
        int i;
        for (i = 0; i < (int)CRASH_BB_SLOTS; i++) {
            img_make_pin(&rec, (uint8_t)(i % (CRASH_PHASE_MAX + 1u)));
            crash_store_append(g_img, &rec, 0, NULL);
        }
    }
    img_make_pin(&rec, CRASH_PHASE_NONE);
    erase_first = 99;
    slot = crash_store_append(g_img, &rec, 1, &erase_first);
    check(slot == 1 && erase_first == 1, "full: pins-only sector reclaims too");
    check(crash_store_scan(g_img, &out) == 0,
          "full: reclaimed pins are retired by the marker on top");

    /* ---- NOR 1->0 program model ---- */
    img_erase();
    img_make_crash(&rec, CRASH_REC_TYPE_PANIC, CRASH_PHASE_PAIR_LOOP, 0x6666u);
    crash_store_program_slot(g_img, 0, &rec);
    {
        uint8_t before[CRASH_BB_SLOT_SIZE];
        uint8_t expect[CRASH_BB_SLOT_SIZE];
        const uint8_t *src = (const uint8_t *)&rec;
        uint32_t i;
        memcpy(before, g_img, sizeof(before));
        img_make_crash(&rec, CRASH_REC_TYPE_HARDFAULT, CRASH_PHASE_PAIR_LOOP, 0x7777u);
        crash_store_program_slot(g_img, 0, &rec);   /* over-program (abuse) */
        for (i = 0; i < sizeof(expect); i++) {
            uint8_t newb = (i < sizeof(rec)) ? src[i] : 0xFFu;
            expect[i] = (uint8_t)(before[i] & newb);
        }
        check(memcmp(expect, g_img, sizeof(expect)) == 0,
              "nor: programming only turns 1->0 (no bit rises)");
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

    /* ---- append-log store (fix15) ---- */
    append_log_tests();

    if (failures != 0) {
        printf("%d FAILURES\n", failures);
        return 1;
    }
    printf("all crash-record host tests passed\n");
    return 0;
}
