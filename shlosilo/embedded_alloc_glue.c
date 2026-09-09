/* shlosilo_embedded_alloc_glue.c — P6.2c/K2-D: L3 memory interface
 *
 * embedded_alloc.rs's EmbeddedAllocator calls these two symbols.
 *
 * K2-D SRAM-first (restored 2026-09-10 after the filter-repo checkout
 * reverted the uncommitted original): Rust allocations are served from a
 * dedicated first-fit pool in on-chip SRAM (.sram_pool, NOLOAD) — no XIP
 * flash wait states, dramatically faster than PSRAM for the many small
 * BP+/CLSAG temporaries. Allocations that do not fit the pool (CN
 * scratchpad 2MB, oversized spill) go to the PSRAM heap_4 and are counted
 * for smoke diagnostics (shlosilo_sram_pool_fallback_count).
 *
 * Pool sizing: SRAM 1MB = FreeRTOS heap_4 450K (ucHeap, untouched) +
 * statics/stacks (~580K used incl. heap_4) leaves ~436K before the
 * reserved .data_parser_section at 0x200FC000. Pool = 384K, padded down
 * from the measured free window for margin. Per-run pool peak ~350K
 * (device-verified fallback=17 with pool+PSRAM split).
 *
 * Concurrency: Rust alloc/free happen only on the single smoke task
 * (see shlosilo/critical_section_impl.c rationale); no lock here.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "user_memory.h"

#ifndef SRAM_POOL_ENABLED
#define SRAM_POOL_ENABLED 1
#endif

#if SRAM_POOL_ENABLED

#define SHLOSILO_POOL_SIZE ((size_t)352 * 1024)
#define SHLOSILO_POOL_ALIGN 8u

/* Placed in its own NOLOAD SRAM section (see mh1903b.ld). */
static uint8_t g_sram_pool[SHLOSILO_POOL_SIZE]
    __attribute__((section(".sram_pool"), aligned(8), used));

/* First-fit allocator over one contiguous pool.
 * Block header: size (incl. header) with bit0 = in-use flag. */
typedef struct {
    size_t size_and_flag;
} pool_hdr_t;

#define HDR_SIZE (sizeof(pool_hdr_t))
#define FLAG_USED 1u

static pool_hdr_t *pool_first(void)
{
    return (pool_hdr_t *)g_sram_pool;
}

static pool_hdr_t *pool_next(pool_hdr_t *h)
{
    uint8_t *p = (uint8_t *)h + (h->size_and_flag & ~FLAG_USED);
    if (p >= g_sram_pool + SHLOSILO_POOL_SIZE) {
        return NULL;
    }
    return (pool_hdr_t *)p;
}

static unsigned int g_sram_pool_fallback_count = 0;
static size_t g_pool_initialized;

unsigned int shlosilo_sram_pool_fallback_count(void)
{
    return g_sram_pool_fallback_count;
}

static void pool_init(void)
{
    if (g_pool_initialized != 0x5A5A5A5Au) {
        pool_first()->size_and_flag = SHLOSILO_POOL_SIZE;
        g_pool_initialized = 0x5A5A5A5Au;
    }
}

void *shlosilo_sram_pool_malloc(size_t size)
{
    if (size == 0) {
        size = 1;
    }
    size = (size + SHLOSILO_POOL_ALIGN - 1u) & ~(size_t)(SHLOSILO_POOL_ALIGN - 1u);
    size_t need = size + HDR_SIZE; /* header-inclusive block size */

    pool_init();
    for (pool_hdr_t *h = pool_first(); h != NULL; h = pool_next(h)) {
        if (h->size_and_flag & FLAG_USED) {
            continue;
        }
        size_t total = h->size_and_flag & ~FLAG_USED;
        if (total < need) {
            continue;
        }
        /* Split if the remainder can hold a header + 8 payload bytes. */
        if (total >= need + HDR_SIZE + SHLOSILO_POOL_ALIGN) {
            pool_hdr_t *rest = (pool_hdr_t *)((uint8_t *)h + need);
            rest->size_and_flag = total - need;
            h->size_and_flag = need | FLAG_USED;
        } else {
            h->size_and_flag |= FLAG_USED;
        }
        return (uint8_t *)h + HDR_SIZE;
    }
    return NULL;
}

void shlosilo_sram_pool_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    pool_hdr_t *h = (pool_hdr_t *)((uint8_t *)ptr - HDR_SIZE);
    h->size_and_flag &= ~FLAG_USED;

    /* Coalesce forward (enough for the observed churn pattern). */
    pool_hdr_t *next = pool_next(h);
    if (next != NULL && !(next->size_and_flag & FLAG_USED)) {
        h->size_and_flag += next->size_and_flag;
    }
}

#endif /* SRAM_POOL_ENABLED */

void *shlosilo_embedded_malloc(size_t size)
{
    /* P6.4 zero-on-alloc (v2-security §3 threat 1: uninitialized read of
     * old key material): the heap does not zero returned memory, zero
     * here. Key material is filled right after alloc; the extra memset
     * on non-key allocs is negligible. */
#if SRAM_POOL_ENABLED
    void *p = shlosilo_sram_pool_malloc(size);
    if (p != NULL) {
        memset(p, 0, size);
        return p;
    }
    g_sram_pool_fallback_count++;
#endif
    void *p2 = ExtMalloc(size);
    if (p2 != NULL) {
        memset(p2, 0, size);
    }
    return p2;
}

void shlosilo_embedded_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
#if SRAM_POOL_ENABLED
    /* Pool pointers live inside g_sram_pool (SRAM @0x2000xxxx); PSRAM
     * heap pointers live at/above MHSCPU_PSRAM_BASE (0x80000000).
     * Dispatch on the address range. */
    if ((uintptr_t)ptr >= (uintptr_t)g_sram_pool &&
        (uintptr_t)ptr < (uintptr_t)(g_sram_pool + SHLOSILO_POOL_SIZE)) {
        shlosilo_sram_pool_free(ptr);
        return;
    }
#endif
    ExtFree(ptr);
}
