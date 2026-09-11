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
 * statics/stacks (.bss ends 0x20095C9B) leaves ~415K before the MSP
 * stack reservation (.data_parser_section at 0x200FC000..0x20100000).
 * Pool = 400K at 0x20098000..0x200FC000 — the entire free window. The
 * BP+/CLSAG live set needs it: at 352K the pool exhausted mid-proof
 * (599 fallbacks, xmr +2.4s); the full window is what brings the
 * fallback count back to the ~17 oversized allocations (CN scratchpad
 * and friends) that must go to PSRAM anyway.
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

#define SHLOSILO_POOL_SIZE ((size_t)400 * 1024)
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
/* Diagnostics: why did fallbacks happen? Capacity (one huge alloc) vs
 * fragmentation (many small allocs while free bytes remain). */
static size_t g_fb_max_size;
static size_t g_fb_total_bytes;
static size_t g_fb_first[4];
static size_t g_fb_last_size;
/* Pool utilization: is the pool genuinely capacity-bound at peak? */
static size_t g_pool_live_bytes;
static size_t g_pool_peak_live;
static unsigned int g_pool_live_blocks;
static unsigned int g_pool_peak_blocks;

unsigned int shlosilo_sram_pool_fallback_count(void)
{
    return g_sram_pool_fallback_count;
}

size_t shlosilo_sram_pool_fallback_max_size(void)
{
    return g_fb_max_size;
}

size_t shlosilo_sram_pool_fallback_total_bytes(void)
{
    return g_fb_total_bytes;
}

const size_t *shlosilo_sram_pool_fallback_first4(void)
{
    return g_fb_first;
}

size_t shlosilo_sram_pool_fallback_last_size(void)
{
    return g_fb_last_size;
}

size_t shlosilo_sram_pool_free_total(void)
{
    size_t free_bytes = 0;
    for (pool_hdr_t *h = pool_first(); h != NULL; h = pool_next(h)) {
        if (!(h->size_and_flag & FLAG_USED)) {
            free_bytes += h->size_and_flag & ~FLAG_USED;
        }
    }
    return free_bytes;
}

size_t shlosilo_sram_pool_free_largest(void)
{
    size_t largest = 0;
    for (pool_hdr_t *h = pool_first(); h != NULL; h = pool_next(h)) {
        if (!(h->size_and_flag & FLAG_USED)) {
            size_t sz = h->size_and_flag & ~FLAG_USED;
            if (sz > largest) {
                largest = sz;
            }
        }
    }
    return largest;
}

unsigned int shlosilo_sram_pool_block_count(void)
{
    unsigned int n = 0;
    for (pool_hdr_t *h = pool_first(); h != NULL; h = pool_next(h)) {
        n++;
    }
    return n;
}

size_t shlosilo_sram_pool_peak_live(void)
{
    return g_pool_peak_live;
}

unsigned int shlosilo_sram_pool_peak_blocks(void)
{
    return g_pool_peak_blocks;
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
        /* Count exactly what the block records: free() subtracts
         * (size_and_flag & ~FLAG) of whatever block is freed — for a
         * split allocation that is 'need', for a non-split one 'total'.
         * Anything else drifts (device showed peak live = 35MB). */
        g_pool_live_bytes += (h->size_and_flag & ~FLAG_USED);
        g_pool_live_blocks++;
        if (g_pool_live_bytes > g_pool_peak_live) {
            g_pool_peak_live = g_pool_live_bytes;
            g_pool_peak_blocks = g_pool_live_blocks;
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
    g_pool_live_bytes -= (h->size_and_flag & ~FLAG_USED);
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
    /* Large allocations bypass the pool when they exceed the threshold;
     * the pool serves the BP+ hot set, huge linear buffers (CN scratchpad
     * 2MB) always go to the PSRAM heap.
     *
     * Threshold history:
     *  - 32K: the 43520B mid-run alloc landed in PSRAM, bp4 regressed
     *    ~400ms vs the pre-rewrite run.
     *  - 48K (K2-D final): that 43520B alloc stays in SRAM. It is the BP+
     *    WIP round-3 CT Straus lookup table (34 items x 1280B), and the
     *    ~409ms recovery anchors the per-byte cost of a PSRAM-resident
     *    CT table (~4352 select steps x ~27k cycles).
     *  - 192K (A1 experiment, 2026-09-11): the WIP round-1/round-2 tables
     *    (166400B = 130 items, 84480B = 66 items) also land in SRAM. Each
     *    CT select scans all 8 ProjectiveNiels entries (1280B); from QSPI
     *    PSRAM that costs ~21-23 cycles/byte (~30k cycles per select+add),
     *    from SRAM ~2k. The bp1/bp2 tables (321K/322K, 257/258 items)
     *    exceed 192K and keep their previous PSRAM path. Fallback stays a
     *    safe no-op: a pool that cannot fit the table degrades to PSRAM. */
#ifndef SRAM_POOL_MAX_ALLOC
#define SRAM_POOL_MAX_ALLOC (192u * 1024u)
#endif
    if (size > SRAM_POOL_MAX_ALLOC) {
        g_sram_pool_fallback_count++;
        if (size > g_fb_max_size) {
            g_fb_max_size = size;
        }
        g_fb_total_bytes += size;
        g_fb_last_size = size;
        if (g_sram_pool_fallback_count <= 4) {
            g_fb_first[g_sram_pool_fallback_count - 1] = size;
        }
    } else {
    void *p = shlosilo_sram_pool_malloc(size);
    if (p != NULL) {
        memset(p, 0, size);
        return p;
    }
    g_sram_pool_fallback_count++;
    if (size > g_fb_max_size) {
        g_fb_max_size = size;
    }
    g_fb_total_bytes += size;
    g_fb_last_size = size;
    if (g_sram_pool_fallback_count <= 4) {
        g_fb_first[g_sram_pool_fallback_count - 1] = size;
    }
    }
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
