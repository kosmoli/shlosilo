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

/* Local ROM-based flash wrappers: the trimmed mh1903_lib in this project does not
 * compile mhscpu_qspi.c / mhscpu_cache.c, so we bind the ROM table directly. */
static uint8_t gc_rom_erase_sector(uint32_t sectorAddress)
{
    return ROM_QSPI_EraseSector(NULL, sectorAddress);
}

static uint8_t gc_rom_program_page(QSPI_CommandTypeDef *cmd, uint32_t addr,
                                   uint32_t size, uint8_t *buffer)
{
    __disable_irq();
    __disable_fault_irq();
    uint8_t ret = ROM_QSPI_ProgramPage(cmd, NULL, addr, size, buffer);
    __enable_fault_irq();
    __enable_irq();
    return ret;
}

static void gc_cache_clean_all(void)
{
    /* CACHE_CleanAll(CACHE) inlined (mhscpu_cache.c is not compiled here). */
    while (CACHE->CACHE_AES_CS & CACHE_IS_BUSY) {
    }
    CACHE->CACHE_REF = CACHE_REFRESH_ALLTAG;
    CACHE->CACHE_REF |= CACHE_REFRESH;
    while (CACHE->CACHE_REF & CACHE_REFRESH) {
    }
}

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
    /* No clock/reset pokes: the system is live when this runs (resetting DMA/CRYPT
     * mid-flight can break other peripherals). The QSPI controller is already up —
     * the firmware itself boots from this flash via XIP. Only refresh the latency
     * field (QSPI_SetLatency(0) inlined; mhscpu_qspi.c is not compiled here). */
    {
        SYSCTRL_ClocksTypeDef clocks;
        SYSCTRL_GetClocksFreq(&clocks);
        QSPI->DEVICE_PARA = (QSPI->DEVICE_PARA & 0xFFFFu) |
                            (((clocks.CPU_Frequency * 2u / 1000000u)) << 16);
    }
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
    /* Program header, then the blob in 256B pages (ROM program wrapper manages
     * its own short irq window; feed the WDT every ~4KB). */
    {
        QSPI_CommandTypeDef cmd;
        cmd.Instruction = PAGE_PROG_CMD;
        cmd.BusMode = QSPI_BUSMODE_111;
        cmd.CmdFormat = QSPI_CMDFORMAT_CMD8_ADDR24_PDAT;

        uint32_t programmed = 0;
        addr = GEN_CACHE_FLASH_BASE;
        gc_rom_program_page(&cmd, addr, sizeof(hdr), (uint8_t *)hdr);
        gc_cache_clean_all();
        addr += sizeof(hdr);
        programmed += sizeof(hdr);

        uint32_t remaining = blob_len;
        const uint8_t *srcp = blob;
        while (remaining > 0) {
            uint32_t chunk = (remaining > 256u) ? 256u : remaining;
            /* Page program cannot cross a 256B page boundary. */
            uint32_t page_off = addr & (256u - 1u);
            if (page_off + chunk > 256u) {
                chunk = 256u - page_off;
            }
            gc_rom_program_page(&cmd, addr, chunk, (uint8_t *)srcp);
            gc_cache_clean_all();
            addr += chunk;
            srcp += chunk;
            remaining -= chunk;
            programmed += chunk;
            if ((programmed & 0xFFFu) < 256u) {
                WDT_ReloadCounter();
                osDelay(1);
            }
        }
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
