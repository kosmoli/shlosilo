/* shlosilo_embedded_alloc_glue.c — P6.2c/K2-D: L3 memory interface
 *
 * embedded_alloc.rs's EmbeddedAllocator calls these two symbols.
 * K2-D SRAM-first policy (2026-09): Rust allocations try the on-chip
 * SRAM heap first (450K, zero XIP wait); on exhaustion fall back to the
 * PSRAM heap_4 (8MB) and count the fallback for smoke diagnostics.
 * Reconstructed 2026-09-10 after the filter-repo checkout reverted the
 * uncommitted K2-D working-tree version (lesson: commit before rewrite).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "user_memory.h"
/* PSRAM memory window base (mhscpu.h MHSCPU_PSRAM_BASE); kept literal
 * here because the shlosilo/ include path does not cover driver headers. */
#define SHLOSILO_PSRAM_ADDR_BASE 0x80000000UL

#ifndef SRAM_POOL_ENABLED
#define SRAM_POOL_ENABLED 1
#endif

#if SRAM_POOL_ENABLED
static unsigned int g_sram_pool_fallback_count = 0;

unsigned int shlosilo_sram_pool_fallback_count(void)
{
    return g_sram_pool_fallback_count;
}
#else
unsigned int shlosilo_sram_pool_fallback_count(void)
{
    return 0u;
}
#endif

void *shlosilo_embedded_malloc(size_t size)
{
    /* P6.4 zero-on-alloc (v2-security §3 threat 1: uninitialized read of
     * old key material): heap does not zero returned memory, zero here.
     * Key material is filled right after alloc; the extra memset on
     * non-key allocs is negligible. */
#if SRAM_POOL_ENABLED
    /* K2-D SRAM-first: on-chip SRAM has no XIP flash wait states.
     * Big allocations (CN scratchpad 2MB) cannot fit the 450K SRAM heap
     * and take the PSRAM fallback path — each fallback is counted. */
    void *p = SramMalloc(size);
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
    /* SramFree (FreeRTOS heap_4, SRAM @0x2000xxxx) and ExtFree (PSRAM
     * heap_4 @0x8000xxxx) operate on disjoint heaps; dispatch on the
     * address range the pointer lives in. */
    if ((uintptr_t)ptr < SHLOSILO_PSRAM_ADDR_BASE) {
        SramFree(ptr);
        return;
    }
#endif
    ExtFree(ptr);
}
