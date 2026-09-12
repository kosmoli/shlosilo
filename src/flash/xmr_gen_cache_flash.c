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

/* Experiment C (2026-09-11): QSPI DEVICE_PARA snapshots. keystone's
 * QspiFlashInit() calls QSPI_Init(NULL) (sets DEVICE_PARA[7:0]=0x6B:
 * FreqSel/DummyCycles/read timing for the flash bus) before SetLatency(0).
 * This firmware only ever called SetLatency. A conservative boot default in
 * the low byte would slow EVERY flash access, including XIP instruction
 * fetch — printed for A/B comparison. */
uint32_t g_qspi_dp_boot = 0;
uint32_t g_qspi_dp_after_init = 0;
uint32_t g_qspi_dp_after_latency = 0;

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

/* CRC32 (IEEE 802.3, reflected, poly 0xEDB88320, init/xorout 0xFFFFFFFF).
 * Table-driven (same algorithm, same results; host-verified against the
 * bit-by-bit original incl. KAT 0xCBF43926 and the 262144-byte blob size).
 * Project A1: the bit loop cost ~40 instr/byte across 3 full passes per
 * boot (Rust load + 2 gc_probe calls); the table loop is ~5 instr/byte. */
static const uint32_t gc_crc32_table[256] = {
    0x00000000u, 0x77073096u, 0xEE0E612Cu, 0x990951BAu, 0x076DC419u, 0x706AF48Fu, 0xE963A535u, 0x9E6495A3u,
    0x0EDB8832u, 0x79DCB8A4u, 0xE0D5E91Eu, 0x97D2D988u, 0x09B64C2Bu, 0x7EB17CBDu, 0xE7B82D07u, 0x90BF1D91u,
    0x1DB71064u, 0x6AB020F2u, 0xF3B97148u, 0x84BE41DEu, 0x1ADAD47Du, 0x6DDDE4EBu, 0xF4D4B551u, 0x83D385C7u,
    0x136C9856u, 0x646BA8C0u, 0xFD62F97Au, 0x8A65C9ECu, 0x14015C4Fu, 0x63066CD9u, 0xFA0F3D63u, 0x8D080DF5u,
    0x3B6E20C8u, 0x4C69105Eu, 0xD56041E4u, 0xA2677172u, 0x3C03E4D1u, 0x4B04D447u, 0xD20D85FDu, 0xA50AB56Bu,
    0x35B5A8FAu, 0x42B2986Cu, 0xDBBBC9D6u, 0xACBCF940u, 0x32D86CE3u, 0x45DF5C75u, 0xDCD60DCFu, 0xABD13D59u,
    0x26D930ACu, 0x51DE003Au, 0xC8D75180u, 0xBFD06116u, 0x21B4F4B5u, 0x56B3C423u, 0xCFBA9599u, 0xB8BDA50Fu,
    0x2802B89Eu, 0x5F058808u, 0xC60CD9B2u, 0xB10BE924u, 0x2F6F7C87u, 0x58684C11u, 0xC1611DABu, 0xB6662D3Du,
    0x76DC4190u, 0x01DB7106u, 0x98D220BCu, 0xEFD5102Au, 0x71B18589u, 0x06B6B51Fu, 0x9FBFE4A5u, 0xE8B8D433u,
    0x7807C9A2u, 0x0F00F934u, 0x9609A88Eu, 0xE10E9818u, 0x7F6A0DBBu, 0x086D3D2Du, 0x91646C97u, 0xE6635C01u,
    0x6B6B51F4u, 0x1C6C6162u, 0x856530D8u, 0xF262004Eu, 0x6C0695EDu, 0x1B01A57Bu, 0x8208F4C1u, 0xF50FC457u,
    0x65B0D9C6u, 0x12B7E950u, 0x8BBEB8EAu, 0xFCB9887Cu, 0x62DD1DDFu, 0x15DA2D49u, 0x8CD37CF3u, 0xFBD44C65u,
    0x4DB26158u, 0x3AB551CEu, 0xA3BC0074u, 0xD4BB30E2u, 0x4ADFA541u, 0x3DD895D7u, 0xA4D1C46Du, 0xD3D6F4FBu,
    0x4369E96Au, 0x346ED9FCu, 0xAD678846u, 0xDA60B8D0u, 0x44042D73u, 0x33031DE5u, 0xAA0A4C5Fu, 0xDD0D7CC9u,
    0x5005713Cu, 0x270241AAu, 0xBE0B1010u, 0xC90C2086u, 0x5768B525u, 0x206F85B3u, 0xB966D409u, 0xCE61E49Fu,
    0x5EDEF90Eu, 0x29D9C998u, 0xB0D09822u, 0xC7D7A8B4u, 0x59B33D17u, 0x2EB40D81u, 0xB7BD5C3Bu, 0xC0BA6CADu,
    0xEDB88320u, 0x9ABFB3B6u, 0x03B6E20Cu, 0x74B1D29Au, 0xEAD54739u, 0x9DD277AFu, 0x04DB2615u, 0x73DC1683u,
    0xE3630B12u, 0x94643B84u, 0x0D6D6A3Eu, 0x7A6A5AA8u, 0xE40ECF0Bu, 0x9309FF9Du, 0x0A00AE27u, 0x7D079EB1u,
    0xF00F9344u, 0x8708A3D2u, 0x1E01F268u, 0x6906C2FEu, 0xF762575Du, 0x806567CBu, 0x196C3671u, 0x6E6B06E7u,
    0xFED41B76u, 0x89D32BE0u, 0x10DA7A5Au, 0x67DD4ACCu, 0xF9B9DF6Fu, 0x8EBEEFF9u, 0x17B7BE43u, 0x60B08ED5u,
    0xD6D6A3E8u, 0xA1D1937Eu, 0x38D8C2C4u, 0x4FDFF252u, 0xD1BB67F1u, 0xA6BC5767u, 0x3FB506DDu, 0x48B2364Bu,
    0xD80D2BDAu, 0xAF0A1B4Cu, 0x36034AF6u, 0x41047A60u, 0xDF60EFC3u, 0xA867DF55u, 0x316E8EEFu, 0x4669BE79u,
    0xCB61B38Cu, 0xBC66831Au, 0x256FD2A0u, 0x5268E236u, 0xCC0C7795u, 0xBB0B4703u, 0x220216B9u, 0x5505262Fu,
    0xC5BA3BBEu, 0xB2BD0B28u, 0x2BB45A92u, 0x5CB36A04u, 0xC2D7FFA7u, 0xB5D0CF31u, 0x2CD99E8Bu, 0x5BDEAE1Du,
    0x9B64C2B0u, 0xEC63F226u, 0x756AA39Cu, 0x026D930Au, 0x9C0906A9u, 0xEB0E363Fu, 0x72076785u, 0x05005713u,
    0x95BF4A82u, 0xE2B87A14u, 0x7BB12BAEu, 0x0CB61B38u, 0x92D28E9Bu, 0xE5D5BE0Du, 0x7CDCEFB7u, 0x0BDBDF21u,
    0x86D3D2D4u, 0xF1D4E242u, 0x68DDB3F8u, 0x1FDA836Eu, 0x81BE16CDu, 0xF6B9265Bu, 0x6FB077E1u, 0x18B74777u,
    0x88085AE6u, 0xFF0F6A70u, 0x66063BCAu, 0x11010B5Cu, 0x8F659EFFu, 0xF862AE69u, 0x616BFFD3u, 0x166CCF45u,
    0xA00AE278u, 0xD70DD2EEu, 0x4E048354u, 0x3903B3C2u, 0xA7672661u, 0xD06016F7u, 0x4969474Du, 0x3E6E77DBu,
    0xAED16A4Au, 0xD9D65ADCu, 0x40DF0B66u, 0x37D83BF0u, 0xA9BCAE53u, 0xDEBB9EC5u, 0x47B2CF7Fu, 0x30B5FFE9u,
    0xBDBDF21Cu, 0xCABAC28Au, 0x53B39330u, 0x24B4A3A6u, 0xBAD03605u, 0xCDD70693u, 0x54DE5729u, 0x23D967BFu,
    0xB3667A2Eu, 0xC4614AB8u, 0x5D681B02u, 0x2A6F2B94u, 0xB40BBE37u, 0xC30C8EA1u, 0x5A05DF1Bu, 0x2D02EF8Du,
};

static uint32_t gc_crc32(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    uint32_t i;
    for (i = 0; i < len; i++) {
        crc = (crc >> 8) ^ gc_crc32_table[(crc ^ data[i]) & 0xFFu];
    }
    return crc ^ 0xFFFFFFFFu;
}

/* Project A1 diagnostics: milliseconds spent in the last full-blob CRC.
 * The blob is read 3x per boot (Rust load + gc_probe pre/post); the CRC
 * math is one component, the 256KB streaming read the other — this split
 * tells the next step (single-pass CRC in Rust) whether it is worth it. */
static uint32_t g_gc_crc_ms = 0;
uint32_t gc_last_crc_ms(void)
{
    return g_gc_crc_ms;
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
    g_qspi_dp_boot = QSPI->DEVICE_PARA;
    /* Experiment C: mirror keystone QspiFlashInit()'s QSPI_Init(NULL) call.
     * Sets DEVICE_PARA[7:0] = 0x6B (flash read timing: dummy cycles / freq
     * select). Order matches keystone: QSPI_Init(NULL) then SetLatency(0). */
    QSPI_Init(NULL);
    g_qspi_dp_after_init = QSPI->DEVICE_PARA;
    QSPI_SetLatency(0);
    g_qspi_dp_after_latency = QSPI->DEVICE_PARA;
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
    {
        /* Project A1: time the full-blob CRC (math + streaming read). */
        uint32_t t0 = osKernelGetTickCount();
        calc = gc_crc32((const uint8_t *)GEN_CACHE_FLASH_BASE + 12, len);
        g_gc_crc_ms = osKernelGetTickCount() - t0;
    }
    if (calc != crc) {
        return NULL;
    }
    for (i = 0; i < 12; i++) {
        (void)base[i];
    }
    /* Rust adapter expects [len][crc][blob] at the returned pointer —
     * skip the magic. Returning base made the adapter read the magic as
     * len (0x31434758), fail the bound check, and fall into the full
     * decompress path every boot (~2.1s inside BP+ statement init). */
    return (const uint8_t *)GEN_CACHE_FLASH_BASE + 4;
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
