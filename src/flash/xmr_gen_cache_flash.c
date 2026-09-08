/**
 * @file xmr_gen_cache_flash.c
 * @brief QSPI flash backend for the BP+ generator cache (XMR knife-1 L3).
 *
 * Persists the 256KB BP+ generator blob (2048 points x 128B raw extended
 * coordinates) produced by the vendored monero-bulletproofs cache hooks into a
 * reserved region of the firmware QSPI NOR flash. On load the blob is served
 * zero-copy straight from the XIP memory map after a CRC32 check.
 *
 * Flash layout (single slot, fixed address):
 *   [magic "XGC1" 4B][blob_len u32 LE][crc32 u32 LE][blob ...]  padded to 4KB sectors
 *
 * Region: GEN_CACHE_FLASH_BASE .. +GEN_CACHE_FLASH_SECTORS*4096
 * Firmware image lives at 0x01081000 (~815KB used); the cache slot at 0x01E00000
 * leaves >12MB of growth headroom below it and ~1.6MB above.
 *
 * Erase/program follows the proven keystone drv_qspi_flash.c pattern:
 * __disable_irq + FLASH_EraseSector + CACHE_CleanAll + page program + read-back
 * verify (XIP), all under the ROM QSPI API.
 */
#include "mhscpu_qspi.h"
#include "mhscpu_wdt.h"
#include "mhscpu_cache.h"
#include "mhscpu.h"
#include <stdint.h>
#include <string.h>
#include "cmsis_os.h"

/* Reserved slot: 65 x 4KB sectors = 260KB (256KB blob + header + slack). */
#define GEN_CACHE_FLASH_BASE 0x01E00000u
#define GEN_CACHE_SECTOR_SIZE 0x1000u
#define GEN_CACHE_SECTORS 65u
#define GEN_CACHE_MAX_BLOB (2048u * 128u)

#define GC_MAGIC0 'X'
#define GC_MAGIC1 'G'
#define GC_MAGIC2 'C'
#define GC_MAGIC3 '1'

static uint8_t volatile g_gc_ready = 0;

static uint8_t gc_rom_program_page(uint32_t addr, uint32_t size, uint8_t *buffer)
{
    /* AES_Program with NULL cmd — the exact keystone QspiFlashEraseAndWrite write
     * path (drv_qspi_flash.c): under GCC it routes to the full mhscpu_qspi.c
     * driver (QSPI_ProgramPage, WREN + DMA + quad select for GD chips). Caller
     * manages the irq window and feeds the WDT between 4KB blocks. */
    return AES_Program(NULL, NULL, addr, size, buffer);
}

#define gc_rom_erase_sector(addr) FLASH_EraseSector((addr))
#define gc_cache_clean_all() CACHE_CleanAll(CACHE)

/* CRC32 (IEEE 802.3, reflected, poly 0xEDB88320, init/xorout 0xFFFFFFFF). */
static uint32_t gc_crc32(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    uint32_t i;
    int8_t bit;
    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/**
 * @brief Init QSPI for ROM erase/program access. Call once before gc_load/gc_store.
 *
 * Mirrors keystone QspiFlashInit() minus TRNG/rand and the chip-type probe:
 * the firmware already boots from this flash via XIP, so the controller is
 * alive; we only need DMA/CRYPT clocks for the program path and the standard
 * latency setting.
 */
void gc_flash_init(void)
{
    /* No clock/reset pokes beyond what AES_Program needs: the system is live when
     * this runs. The QSPI controller is already up — the firmware itself boots
     * from this flash via XIP. */
    SYSCTRL_AHBPeriphClockCmd(SYSCTRL_AHBPeriph_CRYPT, ENABLE);
    QSPI_SetLatency(0);
    g_gc_ready = 1;
}

/**
 * @brief Load callback for shlosilo_gen_cache_set_hooks.
 * @param prefix Generator-set tag ("bulletproof_plus" / "bulletproof").
 * @return Pointer to [len u32 LE][crc u32 LE][blob] in XIP memory, or NULL.
 *
 * Zero-copy: the Rust adapter reads the blob straight from the returned XIP
 * pointer. Only prefixes that map to this slot are served; the single slot
 * stores whichever generator set was persisted first (the device currently
 * proves BP+ only).
 */
const uint8_t *gc_load(const uint8_t *prefix, uint32_t prefix_len)
{
    const uint8_t volatile *base = (const uint8_t volatile *)GEN_CACHE_FLASH_BASE;
    uint32_t magic, len, crc, calc;
    uint32_t i;

    (void)prefix;
    (void)prefix_len; /* single slot: serve any prefix that fits the layout */

    magic = ((uint32_t)base[0]) | ((uint32_t)base[1] << 8) |
            ((uint32_t)base[2] << 16) | ((uint32_t)base[3] << 24);
    if (magic != ((uint32_t)GC_MAGIC0 | ((uint32_t)GC_MAGIC1 << 8) |
                  ((uint32_t)GC_MAGIC2 << 16) | ((uint32_t)GC_MAGIC3 << 24))) {
        return NULL;
    }
    len = ((uint32_t)base[4]) | ((uint32_t)base[5] << 8) |
          ((uint32_t)base[6] << 16) | ((uint32_t)base[7] << 24);
    if (len == 0 || len > GEN_CACHE_MAX_BLOB) {
        return NULL;
    }
    crc = ((uint32_t)base[8]) | ((uint32_t)base[9] << 8) |
          ((uint32_t)base[10] << 16) | ((uint32_t)base[11] << 24);
    calc = gc_crc32((const uint8_t *)GEN_CACHE_FLASH_BASE + 12, len);
    if (calc != crc) {
        return NULL;
    }
    for (i = 0; i < 12; i++) {
        (void)base[i];
    }
    return (const uint8_t *)GEN_CACHE_FLASH_BASE;
}

/**
 * @brief Store callback: erase + program the slot, then verify by CRC.
 * @return 0 on success (verified), non-zero on failure.
 */
uint32_t gc_store(const uint8_t *prefix, uint32_t prefix_len,
                  const uint8_t *blob, uint32_t blob_len)
{
    uint32_t addr;
    uint32_t total;
    uint32_t i;
    uint8_t hdr[12];

    (void)prefix;
    (void)prefix_len;
    if (!g_gc_ready || blob == NULL || blob_len == 0 || blob_len > GEN_CACHE_MAX_BLOB) {
        return 1;
    }

    hdr[0] = GC_MAGIC0;
    hdr[1] = GC_MAGIC1;
    hdr[2] = GC_MAGIC2;
    hdr[3] = GC_MAGIC3;
    hdr[4] = (uint8_t)(blob_len & 0xFF);
    hdr[5] = (uint8_t)((blob_len >> 8) & 0xFF);
    hdr[6] = (uint8_t)((blob_len >> 16) & 0xFF);
    hdr[7] = (uint8_t)((blob_len >> 24) & 0xFF);
    {
        uint32_t crc = gc_crc32(blob, blob_len);
        hdr[8] = (uint8_t)(crc & 0xFF);
        hdr[9] = (uint8_t)((crc >> 8) & 0xFF);
        hdr[10] = (uint8_t)((crc >> 16) & 0xFF);
        hdr[11] = (uint8_t)((crc >> 24) & 0xFF);
    }

    (void)total; /* reserved for future multi-slot layout */
    total = 12u + blob_len;
    /* Per-sector irq windows: a single multi-second critical section starves the
     * scheduler and the watchdog feed task (observed as a device reset on the
     * first XMR sign). Erase one sector, re-enable irqs, feed the WDT, continue. */
    addr = GEN_CACHE_FLASH_BASE;
    for (i = 0; i < GEN_CACHE_SECTORS; i++) {
        __disable_irq();
        gc_rom_erase_sector(addr);
        gc_cache_clean_all();
        __enable_irq();
        addr += GEN_CACHE_SECTOR_SIZE;
        WDT_ReloadCounter();
        osDelay(1);
    }
    /* Program in full 4KB units at 4KB-aligned addresses: AES_Program asserts
     * (addr % 4096) == 0 and the keystone write path always passes exactly one
     * sector (QspiFlashEraseAndWrite asserts len == 4096). The 12B header is
     * fused into block 0 ahead of the blob; the tail block is zero-padded.
     * Buffer lives in PSRAM via the smoke task's heap? No — static SRAM buffer is
     * 4KB; acceptable (SRAM peak 101K/450K). */
    {
        static uint8_t block[4096];
        uint32_t blob_off = 0;
        addr = GEN_CACHE_FLASH_BASE;
        for (uint32_t blk = 0; blk < GEN_CACHE_SECTORS; blk++) {
            uint32_t fill;
            if (blk == 0) {
                memcpy(block, hdr, sizeof(hdr));
                fill = sizeof(hdr);
            } else {
                fill = 0;
            }
            while (fill < 4096u && blob_off < blob_len) {
                block[fill++] = blob[blob_off++];
            }
            while (fill < 4096u) {
                block[fill++] = 0xFFu;
            }
            __disable_irq();
            gc_rom_program_page(addr, 4096u, block);
            gc_cache_clean_all();
            __enable_irq();
            addr += GEN_CACHE_SECTOR_SIZE;
            WDT_ReloadCounter();
            osDelay(1);
        }
        WDT_ReloadCounter();
    }

    /* Read back via XIP and CRC-verify. */
    {
        uint32_t crc = gc_crc32((const uint8_t *)GEN_CACHE_FLASH_BASE + 12, blob_len);
        uint32_t expect = ((uint32_t)hdr[8]) | ((uint32_t)hdr[9] << 8) |
                          ((uint32_t)hdr[10] << 16) | ((uint32_t)hdr[11] << 24);
        if (crc != expect) {
            return 2;
        }
    }
    return 0;
}


/**
 * @brief Diagnostic: report slot state. 0 = load hit; 1 = blank (all 0xFF at header);
 *        2 = non-blank but magic/CRC rejected; 3 = not ready.
 */
uint32_t gc_probe(void)
{
    const uint8_t volatile *base = (const uint8_t volatile *)GEN_CACHE_FLASH_BASE;
    uint32_t i;
    uint8_t all_ff = 1;

    if (!g_gc_ready) {
        return 3;
    }
    for (i = 0; i < 16; i++) {
        if (base[i] != 0xFF) {
            all_ff = 0;
            break;
        }
    }
    if (all_ff) {
        return 1;
    }
    return (gc_load((const uint8_t *)"probe", 5) != NULL) ? 0 : 2;
}
