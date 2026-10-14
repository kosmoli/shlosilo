/* crash_noinit.h -- warm-reset crash marker (see crash_noinit.c). */
#ifndef CRASH_NOINIT_H
#define CRASH_NOINIT_H

#include <stdint.h>

typedef struct {
    uint8_t phase;
    uint8_t type;   /* 1=PHASE pin 2=PANIC 3=HARDFAULT */
    uint32_t pc;
} crash_noinit_rec_t;

#define CRASH_NOINIT_TYPE_NONE       0u
#define CRASH_NOINIT_TYPE_PHASE      1u
#define CRASH_NOINIT_TYPE_PANIC      2u
#define CRASH_NOINIT_TYPE_HARDFAULT  3u

void crash_noinit_mark(uint8_t type, uint8_t phase, uint32_t pc);
int  crash_noinit_read(crash_noinit_rec_t *out);

#endif /* CRASH_NOINIT_H */
