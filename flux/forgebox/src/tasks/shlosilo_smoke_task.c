/* shlosilo_smoke_task.c — P6.2c: shlosilo P6.2 smoke on forgebox-helloworld
 *
 * 干净 L3 宿主：无 keystone 业务逻辑，只验证 shlosilo FFI 全链路。
 * LCD 显示（真机无串口）：
 *   顶部   : "shlosilo P6.2"       (标题)
 *   中部   : 每步结果逐行           (PASS/FAIL)
 *   底部   : 签名耗时 ms            (性能基准)
 */

#include "shlosilo_smoke_task.h"
#include <stdlib.h>
#include "shlosilo.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "cmsis_os.h"
#include "FreeRTOS.h"
#include "task.h"
#include "psram_heap_4.h"
#include "lvgl.h"
#include "helloworld_task.h"
#include "hal_touch.h"
#include "hal_lcd.h"
#include "drv_lcd_bright.h"
#include "user_memory.h"
#include "psram_heap_4.h"
#include "mhscpu.h"
#define SHLOSILO_SMOKE_OK 0 /* ShlosiloErrorCode::Ok */

/* Experiment D (2026-09-11): dependent-add chain. Cortex-M4 executes each
 * dependent ADDS in exactly 1 cycle (single-issue, no dual-issue on M4), so
 * f_core = (8 * iters) / elapsed_s. This is the ground-truth core clock —
 * the SYSCTRL registers describe the CONFIGURED clock, which may differ
 * (HCLKConfig silently forces HCLK = CPU/2 above 102MHz). */
static uint32_t d_alu_chain(uint32_t iters)
{
    uint32_t x = 1;
    __asm volatile(
        "1:\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "subs %1, %1, #1\n\t"
        "bne 1b\n\t"
        : "+l"(x), "+l"(iters)
        :
        : "cc");
    return x;
}

/* 32-add variant: the differential against d_alu_chain cancels the
 * per-iteration branch/loop overhead and directly measures the clock
 * (24 extra ADDS = 24 cycles per iteration). */
static uint32_t d_alu_chain32(uint32_t iters)
{
    uint32_t x = 1;
    __asm volatile(
        "1:\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "adds %0, %0, #1\n\t"
        "subs %1, %1, #1\n\t"
        "bne 1b\n\t"
        : "+l"(x), "+l"(iters)
        :
        : "cc");
    return x;
}


/* device-timing 时钟回调：给 Rust 侧的毫秒计数（定义在文件尾） */
/* xmr_gen_cache_flash.c */
extern void gc_flash_init(void);
extern const uint8_t *gc_load(const uint8_t *prefix, uint32_t prefix_len);
extern uint32_t gc_store(const uint8_t *prefix, uint32_t prefix_len,
                         const uint8_t *blob, uint32_t blob_len);
extern uint32_t gc_probe(void);
extern uint32_t gc_last_crc_ms(void);
extern unsigned int shlosilo_sram_pool_fallback_count(void);
extern unsigned long shlosilo_sram_pool_fallback_max_size(void);
extern unsigned long shlosilo_sram_pool_fallback_total_bytes(void);
extern unsigned long shlosilo_sram_pool_fallback_last_size(void);
extern unsigned long shlosilo_sram_pool_free_total(void);
extern unsigned long shlosilo_sram_pool_free_largest(void);
extern unsigned int shlosilo_sram_pool_block_count(void);
extern unsigned long shlosilo_sram_pool_peak_live(void);
extern unsigned int shlosilo_sram_pool_peak_blocks(void);

/* The Rust (forms) ABI — shlosilo_cn_timing_*, shlosilo_tx_phase_*,
 * shlosilo_perf_*, shlosilo_bp_timing_*, shlosilo_timing_*, the UR entry
 * points — is declared by the generated header shlosilo.h (included above),
 * which the build syncs from the crate. Do not re-declare those here: local
 * `extern unsigned long long f(unsigned int)` forms clash with the header's
 * uint32_t/uint64_t (on arm-none-eabi uint32_t is `unsigned long`). */

static uint32_t smoke_tick_ms(void);
/* SRAM 栈。XMR/ETH 热路径不能把栈放 PSRAM（QSPI 会把 sign 拖到数秒）。
 * 64KB：ETH 实测 used 35K。生成元改为循环 decompress 后不再需要 512KB。 */
/* v21: 64K -> 160K — the Z5.3 chunked/inline paths changed the stack shape
 * (the v20 fault showed a garbage-PC IBUSERR with smashed-looking frames at
 * ~4s into the sign = the deep prove path). 160K fits the 450K SRAM heap. */
#define SHLOSILO_SMOKE_STACK_BYTES (160u * 1024u)

LV_FONT_DECLARE(openSansEnTitle);
LV_FONT_DECLARE(openSansEnText);

/* eth-sign-request fixture（P6.1e 验证过的合法 UR）
 * P1-01（2026-08-26）：payload 从「首字节 tag + raw」私有封装改为真实
 * eth-sign-request CBOR map（ur-registry 形状 {2:sign_data, 3:data_type, 4:chain_id}）。
 * 由库 encode 生成，CRC32 校验通过。*/
static const char *FIXTURE_ETH_SIGN_REQUEST =
    "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmay"
    "mwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxad"
    "aaadrpceaadt";

/* P6.6：idx12 自造 1-input ring16 unsigned_txset UR（host 测过 sign 3458B） */
static const char *FIXTURE_XMR_TX_UNSIGNED =
    "ur:xmr-txunsigned/gtjljtihjpjlcxkpjtjkiniojtihiecxjykscxjkih"
    "jyahpfgrdenezeqzonlohftibejpleldinsabdjoaohgrpdeiyotdnfxoxfz"
    "jetsoymwvogdpsiseedaotdkdmylnllnjkjkwdsrttfghdcegadshgpyhlkp"
    "rptnseyldafshebkfhoyceotehlkceasfdsowyjtlremvwbwsgsbtemwrfft"
    "wtmwaouejzweaeuohysatszeroosfdbswkwfwyglgwbzfytpckhyfzdnldbg"
    "pkdpcknygmaychjlhgghhehlgekiingwfgfseymhbshglsglwylnpkfdtbhh"
    "rsfphkadwfiyfmhsbylanylowpfejpndctcyhhwyrnmkeehkwegavyjlreur"
    "hlhkceutytfnasgebwlgvwsoytkernhdflbwioclfntbnsynvtbnsahlckwn"
    "fejyjsisrnyademhdwlscxcwkobkfzlyvenbskmensrkvthkjprdeodijzem"
    "tovamdiaatfturrnknstylgsieglimvwpftbdmbzbzinfelkhshpgofsvdlk"
    "jkgwrljsnbrpkghlqdrflyptaetsvwsobdspwnuyrnwplpvsfslkgovwtiwl"
    "ctzemdfgdekpvdflcwcajotlptqdcposoyhposoecpfzpdfsfxgsfmcmkbdn"
    "ylguhnwmykaeptlekghywfjkoypfchjolafejlhlgtgakslunnfrmernuega"
    "adaoytetnyahcmesghgwtkuobzwmknbdwltyswaodabylkgobdmkyktsrnpy"
    "mewnfpckspghmwtkltwkcfmygdlkchiewskbbzemrnmtlesgmwenvsgdkkim"
    "wmvdfnzsvtamuodrcxdkspbnsonsjynypepfknkgktlusefstdpmmeztjphe"
    "asckihspmdfthsglrtreldmkghctnnvawtceatfwwzfmgdlnvszowdsghedm"
    "hsbdpsatbtndzedyndvlkscatihkmwtbvwjswpbwlbkstiwspfcygladluyk"
    "lbcxvyiafrspntlkgsahdnpalflurskptptihfjkaefdeosatiimchdpwsis"
    "ynsfvszetldwcpclbefypsprclplbslssagomncwmhjlbkwkhtlnwyythkdw"
    "vduochhtsplplfvecnknrsztfslokorhlkidlkyarpvtdafsrezsceaaemcm"
    "jeykpdckidgotarelsbgtagwgsplnelopswzmyeeiamsnetybywlrpylrynb"
    "hfkifxpfrduoqdfplpmspmossnguzmdshfgssrvabkcmbkkpzojpftdkmtdt"
    "iscfwpftadvamenemwonmwhfdtftkgsegsnnsrvaisfpcstoasfzytdmhtmh"
    "bamopeceehylhpsftlfdbabafsdacpvoptgoesftylhknncsaxtkhebbdydy"
    "tdkbaaneeycxkpbzcngyeturemtbmymhwnbkdrztdrsfvomkytjswfmhgmko"
    "zmctspldgdvwfmihglghvereololkggykbemmdhgplcwosinqdlyvtqdhejz"
    "rhlabbihvosesehyihbyhsoljechptqzhdmstsetceeotnwkeoemrocefdhh"
    "drfdeemefxdpceykonmuuywkpdckhgjngumngatllstsisyachktdacpwyty"
    "aoeygywluyluimyactjywsdliataskoscfzmpteszchkwybkatpsoykotaoe"
    "lgltpmdasorhtibzcmjpimgorfvohegtldmtpsasdkpedmiopsiobtdihtvs"
    "bslybagubwveoshnvtwdmnfeaecxvdcllfwzmnckcavdneprpdaokkcxyags"
    "hsimytltplnybzcabdvtgulkmkmtbwswcektzerfoyloqdbgdkhtzopagezs"
    "rltsjolafximoyperklkpmnefwkiztisztpmglidpkfxfztnlgcsylfelpcs"
    "dakindpmssdafmwmzcrootihjezoeeltadaejeiypsgaghvwmdmevabsmuhy"
    "dprdtacmhpwldtpthymtlrlppfvejsttgdesroprgmeeztroemcfpmnehdon"
    "stolfgndotaxdrksgyzmsscxosjsstaxcsaysecabsmtwmjeehhksbimghgy"
    "jzotpkrlhyvocwnsuedlnyaobecloxemgwaapmchvtjtwtlohflsghltchht"
    "rphgbscyjkwnsgvddnhejnjzdkbndptyfdmkweiehsvoayiantgeasolfthg"
    "eoahplfepeuerysbdefmamieiesnlakohkpayaoxwnmoguemvdhsheqduyvy"
    "kpglctkszofxwkldlrpluehtspfttbmhlnrdplsbielsuymeaegdlkmeclfp"
    "pyldaywyrpykprsbiylacmrdtnqdfyfsdpwzahhgemhfgughskhkrslegykp"
    "koftrhktwpveptbnlketrorhnbrhwnckchdateecjtqzmedncejlehhybgjy"
    "lddlbzjlaxcltonylatovoksztbnrsskmdaaenrsfmvswltakpgrgohgcyrh"
    "prlycapdtkclzscmresteetsdnjzfrflptotjslktoemvypmlrglsfadknsp"
    "vyfrntsnynctkojetnsklteheeolsbhkrerdwnutfhwfbdihcyasbbemflgh"
    "byuypdfhlbaopkbtykiykscftkvysbfshfpaeedkjsehfwssiyaszoytetvt"
    "tyknenfxbknnplgrgalegoetglurgsbwbnwpztvtiovobnetatrpjyotfwdk"
    "cyswgrwdcfaaietbpdhsvomoytdkmthpptimbaaasejldrdtspcprkesdnnb"
    "lkeohsamwsfllauthpgafsdrinzmjonbatfpghgujlnnpkdktkjlhgiogswy"
    "gdcmfzrysovwgmgsdpisbtnyytfzsesnwdgordwftniydngmteamimpsdrro"
    "ytkngoreonkbjyhdhfswjnaemypdaxctfnvtidaasoryynvtpfchbswmmutt"
    "cfnntbdlkbeoihskpdtikowkwljejeadsbhdgumhdraeknlruyclbnhkrfis"
    "wpisdkfxetjnprpfsndnbyfzttoyvybawyrsprssgwgdssmnlrdtvalgaawy"
    "ytbkdw";

static lv_obj_t *g_title = NULL;
static lv_obj_t *g_log   = NULL;
/* 768→2048：cn 探针 +5 行后文本逼近上限，结尾未加保护的 strcat(ALL PASS)
 * 越界写 .bss 邻居 → crash。2048→4096：perf-bench 行加入后总量超 2K。
 * 4096→6144：实验 D（cpu regs / alu / hot / blk32 共 10 行）再加余量。
 * 6144→8192：实验 E（cyccnt / alu diff / cyc×4 / selaff / maddaff / psram cfg）。 */
static char g_logbuf[8192];

/* Diagnostic noinit markers (survive warm reset; .diag_noinit in mh1903b.ld).
 * g_diag_boot_count: incremented per boot — climbing values prove a reset loop.
 * g_diag_progress: last step reached (1=task entry .. 11=version); displayed
 * on the NEXT boot's title so a hang before any log line is still localized. */
extern volatile uint32_t g_fault_log[];
extern volatile uint32_t g_diag_boot_count;
extern volatile uint32_t g_diag_progress;
extern volatile uint32_t g_wdt_cr_readback;

static void res_ckpt(uint32_t p);
static void res_ckpt_msg(uint32_t p, const char *msg);

/* R3 frame fingerprint self-check (2026-10-03): the frames are deterministic
 * (same payload/encoder on every build), so their CRC32s are build-invariant
 * constants captured from the host probe (tests/r3_device_face_probe.rs).
 * The battery compares each frame byte-level against this table - that turns
 * the on-device encoder face into a verified channel and localizes the r3
 * FAIL to encoder vs decoder without any OCR. Table: seq1..6 simple +
 * seq7 mixed (the recovery probe's first frame). */
static uint32_t mp_crc32(const uint8_t *d, uint32_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    uint32_t i;
    int b;
    for (i = 0; i < n; i++) {
        c ^= d[i];
        for (b = 0; b < 8; b++) {
            c = (c & 1u) ? ((c >> 1) ^ 0xEDB88320u) : (c >> 1);
        }
    }
    return ~c;
}

static const uint32_t mp_exp_crc[7] = {
    0x60e35ff9u, 0x5e9dde4cu, 0xcf3ed86au,
    0x7cdab5a2u, 0xca4987c0u, 0x3d1e1c9cu,
    0x855aa8efu,   /* seq7 mixed */
};

/* Raw-LCD liveness square (bypasses LVGL's object tree): 24x24 at the
 * bottom-right, colour derived from the step code. If LVGL rendering dies but
 * the panel path works, this square still moves — separating "smoke task
 * alive, display stack dead" from "smoke task dead".
 * 2026-09-30 v5: LcdDraw is ASYNC (DMA) and not reentrant — v4's fire-and-
 * forget draws collided with LVGL's in-flight flushes and wedged the panel
 * (black screen). Serialize under lvgl_lock and honor the LcdBusy wait, the
 * same discipline LcdFlush uses. */
static void diag_square(uint32_t code)
{
    /* 16x16: 24x24 buffers pushed .bss into .diag_noinit (linker overlap). */
    static uint16_t sq[16 * 16];
    uint16_t color = (uint16_t)((code * 37u) & 0xFFFFu);
    for (unsigned i = 0; i < 16 * 16; i++) {
        sq[i] = color;
    }
    lvgl_lock();
    LcdDraw(464, 784, 479, 799, sq);
    /* v17: bounded wait — a wedged 8080 DMA must not spin here holding the
     * lvgl_lock (it starved the loop's WDT feed and froze the whole system). */
    for (unsigned i = 0; i < 1000u && LcdBusy(); i++) {
        osDelay(1);
    }
    if (LcdBusy()) {
        res_ckpt_msg(88, "lcd-wedge");
    }
    lvgl_unlock();
}


static void diag_prog(uint32_t p)
{
    g_diag_progress = p;
    diag_square(p);
    res_ckpt(p); /* v8: flash checkpoint — localizes hangs/panics across boots */
}

volatile uint32_t g_diag_boot_count __attribute__((section(".diag_noinit")));
volatile uint32_t g_diag_progress __attribute__((section(".diag_noinit")));

/* Backlight liveness channel (diagnostic, 2026-09-30): the backlight is a raw
 * GPIO (PF3), independent of the LCD data path and of LVGL. A dip-pulse with
 * the rest state = ON: if the screen freezes but the backlight keeps pulsing,
 * the system is alive and only the LCD draw path died. Five fast dips at the
 * end = battery finished. */
static void backlight_dip(uint32_t n)
{
    while (n--) {
        SetLcdBright(0);
        osDelay(120);
        SetLcdBright(100);
        osDelay(120);
    }
}

/* ==== v7 flash result record (2026-09-30) ====
 * The LCD draw path dies silently on this board and the product has no
 * UART/USB-device channel — so the battery summary is persisted to one QSPI
 * NOR sector (right after the gencache slot) and replayed as the FIRST log
 * content of the next boot, while the display pipeline is still fresh.
 * Same erase/program discipline as xmr_gen_cache_flash.c (irq window per
 * sector + CACHE_CleanAll + WDT feed). */
#define RES_FLASH_BASE 0x01E41000u /* 4KB sector after the 65-sector gencache slot */
#define RES_PANIC_BASE 0x01E42000u /* v13: panic record lives apart — it must
                                    * never clobber the summary/trail sector */
#define RES_HB_BASE 0x01E43000u /* v18: phase-heartbeat sector (loop-written) */

static uint32_t g_sign_ms, g_xmr_ms, g_gcache_pre;

/* Write one text record (erase + program + checksum). Shared by the summary,
 * the step checkpoints and the panic path. */
/* v19 A/B switch: ALL flash writes off — the QSPI self-write vs XIP/PSRAM
 * arbitration wedge is the prime suspect for the ~4s-into-sign freezes
 * (erase/program runs in __disable_irq windows while the CPU executes from
 * the SAME QSPI flash and the sign hammers PSRAM). Reads stay on (pure XIP). */
#define DIAG_FLASH_WRITES 1 /* v20: writes exonerated by the v19 A/B */

static void res_write_at(uint32_t base, const char *text)
{
#if DIAG_FLASH_WRITES == 0
    (void)base;
    (void)text;
    return;
#endif
    /* AES_Program only asserts the ADDRESS is 4KB-aligned (page program
     * handles any length). 1KB holds the summary + the checkpoint trail in
     * one record (v15: they used to overwrite each other). */
    static uint8_t block[1024];
    uint32_t len;
    uint8_t sum = 0;
    uint32_t i;

    len = (uint32_t)strlen(text);
    if (len > 900u) {
        len = 900u;
    }
    memset(block, 0xFF, sizeof(block));
    block[0] = 'R';
    block[1] = 'S';
    block[2] = 'L';
    block[3] = 'T';
    block[4] = (uint8_t)(len & 0xFF);
    block[5] = (uint8_t)(len >> 8);
    for (i = 0; i < len; i++) {
        block[8 + i] = (uint8_t)text[i];
        sum = (uint8_t)(sum + (uint8_t)text[i]);
    }
    block[6] = sum;
    __disable_irq();
    FLASH_EraseSector(base);
    CACHE_CleanAll(CACHE);
    __enable_irq();
    WDT_ReloadCounter();
    osDelay(1);
    __disable_irq();
    (void)AES_Program(NULL, NULL, base, (uint32_t)sizeof(block), block);
    CACHE_CleanAll(CACHE);
    __enable_irq();
    WDT_ReloadCounter();
}

static void res_write_text(const char *text)
{
    res_write_at(RES_FLASH_BASE, text);
}

/* v10: checkpoint with a data suffix (sizes, alloc verdicts).
 * v11: cumulative trail — every checkpoint APPENDS to one text buffer and the
 * whole trail is persisted, so the next boot sees the full death path (v10's
 * overwrite-per-step lost the sizes when the later steps overwrote ckpt=70). */
static char g_trail[360];

static void res_ckpt_msg(uint32_t p, const char *msg)
{
    char t[64];
    snprintf(t, sizeof(t), " %u:%s", (unsigned)p, msg);
    if (strlen(g_trail) + strlen(t) + 20 < sizeof(g_trail)) {
        strcat(g_trail, t);
    }
    {
        char out[400];
        snprintf(out, sizeof(out), "PREV ckpt trail:%s", g_trail);
        res_write_text(out);
    }
}

static void res_ckpt(uint32_t p)
{
    res_ckpt_msg(p, "");
}

/* Full summary (fired right after the battery core and at the very end). */
static void res_save_now(void)
{
    char text[900];

    snprintf(text, sizeof(text),
             "PREV xmr=%u ms gcache=%u sign=%u\n"
             "PREV bp=%u/%u/%u/%u\n"
             "PREV cn=%u/%u/%u/%u/%u\n"
             "PREV tx=%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u",
             (unsigned)g_xmr_ms, (unsigned)g_gcache_pre, (unsigned)g_sign_ms,
             (unsigned)shlosilo_bp_timing_phase(1),
             (unsigned)shlosilo_bp_timing_phase(2),
             (unsigned)shlosilo_bp_timing_phase(3),
             (unsigned)shlosilo_bp_timing_phase(4),
             (unsigned)shlosilo_cn_timing_phase(1),
             (unsigned)shlosilo_cn_timing_phase(2),
             (unsigned)shlosilo_cn_timing_phase(3),
             (unsigned)shlosilo_cn_timing_phase(4),
             (unsigned)shlosilo_cn_timing_phase(5),
             (unsigned)shlosilo_tx_phase_phase(1),
             (unsigned)shlosilo_tx_phase_phase(2),
             (unsigned)shlosilo_tx_phase_phase(3),
             (unsigned)shlosilo_tx_phase_phase(4),
             (unsigned)shlosilo_tx_phase_phase(5),
             (unsigned)shlosilo_tx_phase_phase(6),
             (unsigned)shlosilo_tx_phase_phase(7),
             (unsigned)shlosilo_tx_phase_phase(8),
             (unsigned)shlosilo_tx_phase_phase(9),
             (unsigned)shlosilo_tx_phase_phase(10),
             (unsigned)shlosilo_tx_phase_phase(11));
    /* v15: carry the checkpoint trail in the SAME record — the summary used
     * to overwrite the trail (and vice versa) in the single record sector. */
    if (text[0] != '\0' && g_trail[0] != '\0') {
        strncat(text, "\nTRAIL:", sizeof(text) - strlen(text) - 1);
        strncat(text, g_trail, sizeof(text) - strlen(text) - 1);
    }
    res_write_text(text);
}

/* v18: phase heartbeat — called from the display_bg loop (~2s cadence,
 * written only when the values CHANGE). The phase accumulators are the
 * in-sign progress; if the sign hangs, the last heartbeat freezes at the
 * death phase and survives in its own sector. Also discriminates the two
 * observed death shapes: heartbeats continuing = the loop lived (screen
 * wedge), heartbeats stopped = the loop died too (WDT-reset shape). */
void diag_heartbeat(void)
{
    static char last[96];
    char now_s[96];
    unsigned cn = shlosilo_cn_timing_phase(5);
    unsigned bp = shlosilo_bp_timing_phase(4);
    unsigned wip = shlosilo_bp_timing_phase(3);
    unsigned tx = shlosilo_tx_phase_phase(4);
    unsigned sg = shlosilo_timing_get_total();
    snprintf(now_s, sizeof(now_s), "hb sg=%u cn=%u bp=%u wip=%u tx=%u",
             sg, cn, bp, wip, tx);
    if (strcmp(now_s, last) != 0) {
        strncpy(last, now_s, sizeof(last) - 1);
        last[sizeof(last) - 1] = '\0';
        res_write_at(RES_HB_BASE, now_s);
    }
}

/* Consume-on-read: returns >0 and fills out with the previous run's record. */
static int res_load_at(uint32_t base, char *out, uint32_t max)
{
    const volatile uint8_t *p = (const volatile uint8_t *)base;
    uint32_t len;
    uint8_t sum = 0;

    if (p[0] != 'R' || p[1] != 'S' || p[2] != 'L' || p[3] != 'T') {
        return 0;
    }
    len = (uint32_t)p[4] | ((uint32_t)p[5] << 8);
    if (len == 0 || len > 4000u || len + 1u > max) {
        return 0;
    }
    for (uint32_t i = 0; i < len; i++) {
        sum = (uint8_t)(sum + p[8 + i]);
    }
    if (sum != p[6]) {
        return 0;
    }
    for (uint32_t i = 0; i < len; i++) {
        out[i] = (char)p[8 + i];
    }
    out[len] = '\0';
    /* consume: erase so the next boot does not replay it */
    __disable_irq();
    FLASH_EraseSector(base);
    CACHE_CleanAll(CACHE);
    __enable_irq();
    WDT_ReloadCounter();
    return 1;
}

static int res_load(char *out, uint32_t max)
{
    return res_load_at(RES_FLASH_BASE, out, max);
}

static void log_line(const char *fmt, ...)
{
    va_list ap;
    char line[96];
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    /* UART0 mirror (diagnostic, 2026-09-30): the LCD draw path dies silently
     * on this board (accounting completes, pixels vanish); the UART keeps the
     * battery readable even with a dead screen. */
    printf("[log] %s\r\n", line);
    if (strlen(g_logbuf) + strlen(line) + 2 < sizeof(g_logbuf)) {
        strcat(g_logbuf, line);
        strcat(g_logbuf, "\n");
        lvgl_lock();
        lv_label_set_text(g_log, g_logbuf);
        lvgl_unlock();
    }
}

static int run_checks(void)
{
    int fail = 0;
    unsigned int actual = 0;
    uint8_t out[256];
    uint8_t mnemonic_buf[24];
    /* Z3.3b: sign workspace — C-side provisioning by runtime query (the
     * capacity is never frozen into the ABI). One-shot diagnostic workspace,
     * freed before return. */
    /* Z5.2b: decompressed generator table storage (BP+ set). Provided ONCE
       and never freed — the buffers must outlive every generator use
       (shlosilo.h contract). Subsequent runs skip (slot is CONSUMED). */
    {
        static uint8_t *gen_g = NULL;
        static uint8_t *gen_h = NULL;
        static uint8_t *gen_blob = NULL;
        if (gen_g == NULL) {
            uint32_t g_sz = 0, h_sz = 0, b_sz = 0;
            diag_prog(6); /* gencache sizes probe */
            if (shlosilo_gencache_table_sizes(1, &g_sz, &h_sz, &b_sz) != 0) {
                log_line("gen table sizes probe failed");
            } else {
                /* v10: bracket every alloc with flash checkpoints + record the
                 * real sizes — v9 died between ckpt 7 and 8 (inside these
                 * mallocs) with no further word. */
                {
                    char m[96];
                    snprintf(m, sizeof(m), "g=%u h=%u b=%u",
                             (unsigned)g_sz, (unsigned)h_sz, (unsigned)b_sz);
                    res_ckpt_msg(70, m);
                }
                diag_prog(7); /* sizes ok, mallocs */
                /* v11 escape hatch: absurd sizes = ABI/unit disease — skip the
                 * provision instead of feeding them to malloc (v10 died inside
                 * malloc(h_sz)), so the battery still delivers xmr/phase data. */
                if (g_sz == 0 || g_sz > 2u * 1024u * 1024u ||
                    h_sz == 0 || h_sz > 2u * 1024u * 1024u ||
                    b_sz > 4u * 1024u * 1024u) {
                    res_ckpt_msg(75, "SIZES-INSANE skip");
                    log_line("gen sizes INSANE, provision skipped");
                } else {
                {
                    /* v15 FIX: PsramMalloc (the 8MB PSRAM heap_4) — the only
                     * domain that can hold these buffers. (v12 routed them to
                     * `RustMalloc`, which is a legacy shim: it lands in the
                     * 450KB SRAM FreeRTOS heap, NOT the Rust allocator glue —
                     * 2.8MB ws and 576KB tables could never fit. The plain
                     * `malloc` of v9-v11 was the newlib sbrk trap instead.) */
                    void *tiny = PsramMalloc(16);
                    res_ckpt_msg(69, tiny ? "tiny=ok" : "tiny=NULL");
                    PsramFree(tiny);
                }
                gen_g = (uint8_t *)PsramMalloc(g_sz);
                {
                    char m[40];
                    snprintf(m, sizeof(m), "gg=%p", (void *)gen_g);
                    res_ckpt_msg(71, m);
                }
                gen_h = (uint8_t *)PsramMalloc(h_sz);
                {
                    char m[40];
                    snprintf(m, sizeof(m), "gh=%p", (void *)gen_h);
                    res_ckpt_msg(72, m);
                }
                gen_blob = (uint8_t *)PsramMalloc(b_sz);
                {
                    char m[40];
                    snprintf(m, sizeof(m), "gb=%p", (void *)gen_blob);
                    res_ckpt_msg(73, m);
                }
                }
                if (gen_g != NULL && gen_h != NULL && gen_blob != NULL) {
                    uint32_t gs = g_sz, hs = h_sz, bs = b_sz;
                    diag_prog(8); /* provide_table (decompress into caller storage) */
                    int32_t grc = shlosilo_gencache_provide_table(
                        1, gen_g, &gs, gen_h, &hs, gen_blob, &bs);
                    diag_prog(9); /* provide done */
                    log_line("gen table provide rc=%d (g=%u h=%u b=%u)",
                             (int)grc, (unsigned)gs, (unsigned)hs, (unsigned)bs);
                } else {
                    log_line("gen table malloc failed");
                }
            }
        }
    }

    diag_prog(10); /* sign workspace */
    unsigned ws_need = shlosilo_sign_ws_len();
    /* v15: same allocator fix as the provision buffers (PSRAM heap_4). */
    uint8_t *sign_ws = (uint8_t *)PsramMalloc(ws_need);
    {
        char m[40];
        snprintf(m, sizeof(m), "ws=%p need=%u", (void *)sign_ws, (unsigned)ws_need);
        res_ckpt_msg(10, m);
    }
    if (sign_ws == NULL) {
        log_line("sign ws: alloc fail (%u bytes)", ws_need);
        return 1;
    }
    /* P1-04（2026-08-29）：seed 不跨 FFI——restore 步骤删除，新增 export
     * (mnemonic 入口) 替代。测试项：version/cabi/create/export/sign/bad-uri */
    /* P1-05（2026-08-26）：restore/sign 现在校验 BIP-39 checksum——旧 idx12
     * {3,5,1,6,2,4,3,5,1,6,2,4} checksum 非法会被拒绝。改用 entropy 0x11×16
     * 的合法 12 词索引（python BIP-39 独立验证 checksum 通过）。*/
    uint16_t idx12[12] = {136, 1092, 546, 273, 136, 1092, 546, 273, 136, 1092, 546, 283};
    /* dice rolls 是 u8/roll；idx12 是 u16 mnemonic 索引——两个不同类型，勿混用
     * P0-01 审计整改：12 词需 ≥minimum_rolls(6,128)=64 次 d6，12 次会被拒绝 */
    uint8_t rolls64[64];
    for (int i = 0; i < 64; i++) { rolls64[i] = (uint8_t)(i % 6) + 1; }

    /* 1. version */
    diag_prog(11); /* version check */
    if (shlosilo_version() != NULL) {
        log_line("version: %s", shlosilo_version());
    } else {
        fail++;
        log_line("version: FAIL");
    }

    /* 2. cabi check */
    if (shlosilo_cabi_check(SHLOSILO_CABI_VERSION_MAJOR,
                            SHLOSILO_CABI_VERSION_MINOR,
                            SHLOSILO_CABI_VERSION_PATCH) == 0) {
        log_line("cabi: PASS");
    } else {
        fail++;
        log_line("cabi: FAIL");
    }

    /* 3. create account (dice entropy) — P1-04：无 seed 输出 */
    memset(mnemonic_buf, 0, sizeof(mnemonic_buf));
    if (shlosilo_create_account_ffi(12, 6, rolls64, sizeof(rolls64), NULL, 0,
                                    mnemonic_buf, sizeof(mnemonic_buf)) == 0) {
        log_line("create: PASS");
    } else {
        fail++;
        log_line("create: FAIL");
    }

    /* 4. export_readonly (mnemonic 入口，替代原 restore 步骤) */
    log_line("export: start...");
    {
        uint32_t path_elems[5] = {44u | 0x80000000u, 0u | 0x80000000u,
                                  0u | 0x80000000u, 0u, 0u};
        uint8_t export_buf[512];
        unsigned export_len = 0;
        if (shlosilo_export_readonly_ffi(idx12, 12, NULL, 0, 0 /* mainnet */,
                                         path_elems, 5, 0 /* CryptoHdKey */,
                                         export_buf, sizeof(export_buf),
                                         &export_len) == 0 &&
            export_len > 20) {
            log_line("export: PASS (%u bytes)", export_len);
        } else {
            fail++;
            log_line("export: FAIL");
        }
        memset(export_buf, 0, sizeof(export_buf));
        memset(path_elems, 0, sizeof(path_elems));
    }

    /* 5. sign_ur — 真实 EIP-1559 签名 + 耗时基准 */
    log_line("sign: start...");
    /* device-timing: 注册 ms 时钟（weak 符号，production .a 为 no-op） */
    shlosilo_timing_reset();
    shlosilo_timing_set_clock_fn(smoke_tick_ms);
    uint32_t t0 = osKernelGetTickCount();
    int rc = shlosilo_sign_ur_ffi(FIXTURE_ETH_SIGN_REQUEST, idx12, 12,
                                  NULL, 0, 0, NULL, 0, out, sizeof(out), &actual,
                                  sign_ws, ws_need);
    uint32_t dt = osKernelGetTickCount() - t0;
    if (rc == 0 && actual > 0 && out[0] == 0x02) {
        log_line("sign: PASS (%u bytes, type=0x%02x)", actual, out[0]);
        log_line("sign time: %u ms", dt);
        g_sign_ms = dt;
        log_line("t1 ur_decode: %u", shlosilo_timing_get_stage(1));
        log_line("t2 pbkdf2: %u", shlosilo_timing_get_stage(2));
        log_line("t3 bip32: %u", shlosilo_timing_get_stage(3));
        log_line("t5 keccak: %u", shlosilo_timing_get_stage(5));
        log_line("t6 ecdsa_hi: %u", shlosilo_timing_get_stage(6));
        log_line("t7 ecdsa_lo: %u", shlosilo_timing_get_stage(7));
        log_line("t8 yparity: %u", shlosilo_timing_get_stage(8));
        log_line("t4 rlp_ser: %u", shlosilo_timing_get_stage(4));

        /* XIP cache/布局效应实验：连跑第二次（热 I-cache/D-cache）。
         * 若 t2 显著变小 → PBKDF2 差异来自 flash XIP cache 冷启动，而非代码回退。 */
        shlosilo_timing_reset();
        uint32_t t0b = osKernelGetTickCount();
        int rc2 = shlosilo_sign_ur_ffi(FIXTURE_ETH_SIGN_REQUEST, idx12, 12,
                                       NULL, 0, 0, NULL, 0, out, sizeof(out), &actual,
                                       sign_ws, ws_need);
        uint32_t dt2 = osKernelGetTickCount() - t0b;
        if (rc2 == 0 && actual > 0) {
            log_line("run2: %u ms (t2 pbkdf2: %u)",
                     dt2, shlosilo_timing_get_stage(2));
        } else {
            log_line("run2: FAIL rc=%d", rc2);
        }
    } else {
        fail++;
        log_line("sign: FAIL rc=%d", rc);
    }

    /* 6. bad URI 拒绝 */
    if (shlosilo_sign_ur_ffi("not-a-ur", idx12, 12, NULL, 0, 0, NULL, 0,
                             out, sizeof(out), &actual,
                             sign_ws, ws_need) != 0) {
        log_line("bad-uri: PASS (rejected)");
    } else {
        fail++;
        log_line("bad-uri: FAIL (accepted!)");
    }

    /* P6.4 v2-安全 §5：C L3 敏感缓冲用后清零（mnemonic 索引属敏感材料；
     * out 是公开输出，一并清零是廉价纵深；export_buf/idx12 在各自作用域清） */
    memset(out, 0, sizeof(out));
    memset(mnemonic_buf, 0, sizeof(mnemonic_buf));

        /* 7. R3 typed multipart UR roundtrip (2026-08-31) */
    log_line("r3 multipart: start...");
    {
        static uint8_t mp_payload[1024];
        for (int i = 0; i < 1024; i++) mp_payload[i] = (uint8_t)(i % 251);
        /* Z3.3c: handle workspaces — runtime query, C-side provisioning */
        unsigned enc_ws_need = shlosilo_ur_encode_ws_len();
        unsigned dec_ws_need = shlosilo_ur_decode_ws_len();
        /* v16: PSRAM heap_4 — the bare `malloc` (newlib sbrk at 0x20097e60)
         * grows INTO the K2-D pool and the diag region (the v9-v11 trap). */
        uint8_t *enc_ws = (uint8_t *)PsramMalloc(enc_ws_need);
        uint8_t *dec_ws = (uint8_t *)PsramMalloc(dec_ws_need);
        if (enc_ws == NULL || dec_ws == NULL) {
            log_line("mp: ws alloc fail (%u/%u)", enc_ws_need, dec_ws_need);
            fail++;
            PsramFree(enc_ws);
            PsramFree(dec_ws);
            return fail;
        }
        UrMultipartEncoder *enc = shlosilo_ur_encode_begin(
            "xmr-txunsigned", mp_payload, sizeof(mp_payload), 200,
            enc_ws, enc_ws_need);
        UrMultipartDecoder *dec = shlosilo_ur_decode_new(dec_ws, dec_ws_need);
        static uint8_t frame[1024]; /* FRAME_BUF_MAX_LEN 对齐 poc4 c_abi */
        unsigned int flen = 0;
        int mp_fail = 0;    /* 0 ok; 1 enc/feed err; 2 guard; 3 handle NULL */
        int fail_rc = 0, fail_seq = 0, fail_acc = -1;
        int enc_bad = 0, enc_bad_seq = 0;
        unsigned int enc_bad_exp = 0, enc_bad_got = 0;
        int guard = 0;
        if (enc == NULL || dec == NULL) {
            mp_fail = 3;
            log_line("mp: FAIL handle NULL (enc=%d dec=%d)",
                     enc != NULL, dec != NULL);
            res_ckpt_msg(80, "mp FAIL handle-NULL");
        }
        while (mp_fail == 0 && !shlosilo_ur_decode_complete(dec)) {
            unsigned int acc = 9;
            int erc = shlosilo_ur_encode_next(enc, frame, sizeof(frame), &flen);
            int frc;
            if (erc != SHLOSILO_SMOKE_OK) {
                mp_fail = 1; fail_rc = erc; fail_seq = guard + 1;
                break;
            }
            frc = shlosilo_ur_decode_feed(dec, (const char *)frame, &acc);
            if (guard < 7) {
                unsigned int fc = mp_crc32(frame, flen);
                int okc = (fc == mp_exp_crc[guard]);
                if (!okc) {
                    enc_bad++;
                    enc_bad_seq = guard + 1;
                    enc_bad_exp = mp_exp_crc[guard];
                    enc_bad_got = fc;
                }
                log_line("mp f%d: len=%u crc=%08x %s p=%d",
                         guard + 1, flen, (unsigned)fc, okc ? "OK" : "BAD",
                         shlosilo_ur_decode_progress(dec));
            } else if (guard < 12) {
                log_line("mp f%d: len=%u feed=%d acc=%u p=%d",
                         guard + 1, flen, frc, acc,
                         shlosilo_ur_decode_progress(dec));
            }
            if (frc != SHLOSILO_SMOKE_OK) {
                mp_fail = 1; fail_rc = frc; fail_seq = guard + 1;
                fail_acc = (int)acc;
                break;
            }
            if (++guard > 500) { mp_fail = 2; break; }
        }
        static uint8_t mp_out[1024];
        unsigned int mp_len = 0;
        if (!mp_fail &&
            shlosilo_ur_decode_payload(dec, mp_out, sizeof(mp_out), &mp_len) == SHLOSILO_SMOKE_OK &&
            mp_len == sizeof(mp_payload) &&
            memcmp(mp_out, mp_payload, mp_len) == 0) {
            log_line("r3 multipart: PASS (%d frames)", guard);
            res_ckpt_msg(80, "mp PASS");
        } else {
            char rv[64];
            fail++;
            if (mp_fail == 1) {
                snprintf(rv, sizeof(rv), "mp FAIL enc/feed rc=%d seq=%d acc=%d",
                         fail_rc, fail_seq, fail_acc);
            } else if (mp_fail == 2) {
                snprintf(rv, sizeof(rv), "mp FAIL guard p=%d",
                         shlosilo_ur_decode_progress(dec));
            } else if (mp_fail == 3) {
                snprintf(rv, sizeof(rv), "mp FAIL handle NULL");
            } else {
                unsigned int k = 0;
                while (k < mp_len && k < sizeof(mp_payload) &&
                       mp_out[k] == mp_payload[k]) {
                    k++;
                }
                snprintf(rv, sizeof(rv), "mp FAIL len=%u byte@%u",
                         mp_len, (unsigned)k);
            }
            log_line("%s", rv);
            res_ckpt_msg(80, rv);
        }
        if (enc_bad) {
            char rv[64];
            snprintf(rv, sizeof(rv), "mp ENC-FACE seq=%d exp=%08x got=%08x",
                     enc_bad_seq, enc_bad_exp, enc_bad_got);
            log_line("%s", rv);
            res_ckpt_msg(80, rv);
        } else {
            log_line("mp enc-face: crc 1-6 OK");
            res_ckpt_msg(80, "mp enc crc OK");
        }
        /* cyclic frame smoke: SHLOSILO_SMOKE_OK return only */
        if (shlosilo_ur_encode_next_cyclic(enc, frame, sizeof(frame), &flen) != SHLOSILO_SMOKE_OK) {
            fail++;
            log_line("r3 cyclic: FAIL");
        }
        shlosilo_ur_encode_free(enc);
        shlosilo_ur_decode_free(dec);

        /* Mixed-redundancy recovery probe (2026-10-03): the roundtrip above
         * completes on seq 1..count SIMPLE parts only - the same shape the
         * product flow proved on real frames. The seq>count fountain mixing
         * path is device-UNTESTED and matches both observed failure modes
         * (wrong payload / guard never satisfied). Probe: fresh decoder gets
         * frames 1..5 (6 withheld), then mixed frames 7.. - fragment 6 must
         * arrive via mixed recovery. Handles live in the ws, so this runs
         * only after the frees above. */
        {
            /* NOTE: reuse `frame` (free in this window) - smoke .bss has <210B
             * of headroom under the .diag_noinit ceiling, a fresh 1KB static
             * overflows it (linker caught it: .bss 0x2009832f > 0x20098000). */
            UrMultipartEncoder *enc2 = shlosilo_ur_encode_begin(
                "xmr-txunsigned", mp_payload, sizeof(mp_payload), 200,
                enc_ws, enc_ws_need);
            UrMultipartDecoder *dec2 = shlosilo_ur_decode_new(dec_ws, dec_ws_need);
            unsigned int flen2 = 0, acc2 = 0;
            int mg_fail = 0, mg = 0;
            if (enc2 == NULL || dec2 == NULL) {
                mg_fail = 1;
            }
            while (!mg_fail && mg < 5 &&
                   shlosilo_ur_encode_next(enc2, frame, sizeof(frame),
                                           &flen2) == SHLOSILO_SMOKE_OK &&
                   shlosilo_ur_decode_feed(dec2, (const char *)frame,
                                           &acc2) == SHLOSILO_SMOKE_OK) {
                mg++;
            }
            /* Discard the seq-6 frame (the withheld fragment): everything the
             * decoder sees from now on is seq>count MIXED redundancy, which
             * must reconstruct fragment 5 (the message tail). */
            if (!mg_fail) {
                (void)shlosilo_ur_encode_next(enc2, frame, sizeof(frame),
                                              &flen2);
            }
            while (!mg_fail && !shlosilo_ur_decode_complete(dec2)) {
                int erc = shlosilo_ur_encode_next(enc2, frame, sizeof(frame),
                                                  &flen2);
                int frc;
                if (erc != SHLOSILO_SMOKE_OK) { mg_fail = 2; break; }
                frc = shlosilo_ur_decode_feed(dec2, (const char *)frame, &acc2);
                if (mg < 12) {
                    log_line("mp mx%d: feed=%d acc=%u p=%d", mg + 1, frc, acc2,
                             shlosilo_ur_decode_progress(dec2));
                }
                if (frc != SHLOSILO_SMOKE_OK) { mg_fail = 3; break; }
                if (mg == 5) {
                    /* first mixed frame (seq 7) - byte-level encoder check */
                    unsigned int fc = mp_crc32(frame, flen);
                    if (fc != mp_exp_crc[6]) {
                        log_line("mp mx seq7 crc BAD exp=%08x got=%08x",
                                 (unsigned)mp_exp_crc[6], (unsigned)fc);
                        mg_fail = 5;
                        break;
                    }
                    log_line("mp mx seq7: crc OK");
                }
                if (++mg > 500) { mg_fail = 4; break; }
            }
            {
                char rv[64];
                if (!mg_fail && shlosilo_ur_decode_complete(dec2)) {
                    snprintf(rv, sizeof(rv), "mp mixed: PASS (%d fr)", mg);
                } else {
                    snprintf(rv, sizeof(rv), "mp mixed: FAIL %d p=%d", mg_fail,
                             dec2 ? shlosilo_ur_decode_progress(dec2) : -1);
                    fail++;
                }
                log_line("%s", rv);
                res_ckpt_msg(80, rv);
            }
            shlosilo_ur_encode_free(enc2);
            shlosilo_ur_decode_free(dec2);
            memset(frame, 0, sizeof(frame));
        }

        PsramFree(enc_ws);
        PsramFree(dec_ws);
        memset(mp_payload, 0, sizeof(mp_payload));
        memset(mp_out, 0, sizeof(mp_out));
        memset(frame, 0, sizeof(frame));
    }

    /* 8. XMR 1-input BP+（P6.6 MCU 峰值；idx12 自造 ring16，非真实资金） */
    /* BP+ generator cache: register flash backend (no-op against a production
     * .a without the generator-cache-ffi feature). */
    gc_flash_init();
    shlosilo_gen_cache_set_hooks(gc_load, gc_store);
    /* Cache state probe: 0=hit 1=blank 2=corrupt 3=not-ready */
    g_gcache_pre = gc_probe();
    log_line("gencache pre: %u", (unsigned)g_gcache_pre);
    /* A2 diagnostics: CRC time in the pre-sign context (the post value is printed
     * after the XMR block). Same 256 KB blob, two different cache states. */
    log_line("gc crc pre: %u ms", (unsigned)gc_last_crc_ms());
    {
        extern uint32_t g_qspi_dp_boot, g_qspi_dp_after_init, g_qspi_dp_after_latency;
        log_line("qspi dp: boot=%08X init=%08X lat=%08X",
                 (unsigned)g_qspi_dp_boot, (unsigned)g_qspi_dp_after_init,
                 (unsigned)g_qspi_dp_after_latency);
    }
    /* BP+ prove-phase timing: same clock as device-timing. */
    shlosilo_bp_timing_set_clock(smoke_tick_ms);
    shlosilo_bp_timing_reset();
    shlosilo_cn_timing_set_clock(smoke_tick_ms);
    shlosilo_cn_timing_reset();
    shlosilo_tx_phase_set_clock(smoke_tick_ms);
    shlosilo_tx_phase_reset();
    log_line("xmr: start...");
    {
        static uint8_t xmr_out[4096];
        uint8_t entropy[32];
        unsigned xmr_len = 0;
        int i;
        for (i = 0; i < 32; i++) {
            entropy[i] = 0x77;
        }
        log_line("stk pre-xmr: %uW",
                 (unsigned)uxTaskGetStackHighWaterMark(NULL));
        diag_prog(12); /* v8: pre-xmr checkpoint (outside the timed window) */
        uint32_t t0 = osKernelGetTickCount();
        int rc = shlosilo_sign_ur_ffi(FIXTURE_XMR_TX_UNSIGNED, idx12, 12,
                                      NULL, 0, 0, entropy, sizeof(entropy),
                                      xmr_out, sizeof(xmr_out), &xmr_len,
                                      sign_ws, ws_need);
        uint32_t dt = osKernelGetTickCount() - t0;
        diag_prog(13); /* v8: post-xmr checkpoint (outside the timed window) */
        if (rc == 0 && xmr_len > 64) {
            log_line("xmr: PASS (%u bytes)", xmr_len);
            log_line("xmr time: %u ms", dt);
            g_xmr_ms = dt;
            /* BP+ phase decomposition: 1=initial multiexp 2=A_hat 3=WIP rounds
             * 4=total prove (ms, accumulated). */
            log_line("bp1 commit: %u ms", (unsigned)shlosilo_bp_timing_phase(1));
            log_line("bp2 ahat: %u ms", (unsigned)shlosilo_bp_timing_phase(2));
            log_line("bp3 wip: %u ms", (unsigned)shlosilo_bp_timing_phase(3));
            log_line("bp4 total: %u ms", (unsigned)shlosilo_bp_timing_phase(4));
            log_line("bp5 l_r: %u ms", (unsigned)shlosilo_bp_timing_phase(5));
            log_line("bp6 fold: %u ms", (unsigned)shlosilo_bp_timing_phase(6));
            log_line("b7 wrapcmt: %u ms", (unsigned)shlosilo_bp_timing_phase(7));
            log_line("b8 stmt: %u ms", (unsigned)shlosilo_bp_timing_phase(8));
            log_line("b9 consist: %u ms", (unsigned)shlosilo_bp_timing_phase(9));
            log_line("sram fallback: %u max=%luK bytes=%luK last=%luB",
                     (unsigned)shlosilo_sram_pool_fallback_count(),
                     shlosilo_sram_pool_fallback_max_size() / 1024u,
                     shlosilo_sram_pool_fallback_total_bytes() / 1024u,
                     shlosilo_sram_pool_fallback_last_size());
            log_line("sram pool: free=%luK hole=%luK blocks=%u",
                     shlosilo_sram_pool_free_total() / 1024u,
                     shlosilo_sram_pool_free_largest() / 1024u,
                     shlosilo_sram_pool_block_count());
            log_line("sram pool: peak live=%luK blocks=%u cap=396K thr=48K ch=36",
                     shlosilo_sram_pool_peak_live() / 1024u,
                     shlosilo_sram_pool_peak_blocks());
            log_line("cn1 keccak: %u ms", (unsigned)shlosilo_cn_timing_phase(1));
            log_line("cn2 fill: %u ms", (unsigned)shlosilo_cn_timing_phase(2));
            log_line("cn3 loop: %u ms", (unsigned)shlosilo_cn_timing_phase(3));
            log_line("cn4 final: %u ms", (unsigned)shlosilo_cn_timing_phase(4));
            log_line("cn5 total: %u ms", (unsigned)shlosilo_cn_timing_phase(5));
            log_line("x1 decrypt: %u ms", (unsigned)shlosilo_tx_phase_phase(1));
            log_line("x2 outderiv: %u ms", (unsigned)shlosilo_tx_phase_phase(2));
            log_line("x3 prefix+rct: %u ms", (unsigned)shlosilo_tx_phase_phase(3));
            log_line("x4 clsag: %u ms", (unsigned)shlosilo_tx_phase_phase(4));
            log_line("x5 wire: %u ms", (unsigned)shlosilo_tx_phase_phase(5));
            log_line("x6 keyimg: %u ms", (unsigned)shlosilo_tx_phase_phase(6));
            log_line("x7 encrypt: %u ms", (unsigned)shlosilo_tx_phase_phase(7));
            log_line("x8 commits: %u ms", (unsigned)shlosilo_tx_phase_phase(8));
            log_line("x9 bp+wrap: %u ms", (unsigned)shlosilo_tx_phase_phase(9));
            log_line("x10 bpsig: %u ms", (unsigned)shlosilo_tx_phase_phase(10));
            log_line("x11 rctbase: %u ms", (unsigned)shlosilo_tx_phase_phase(11));
            log_line("gencache post: %u", (unsigned)gc_probe());
            log_line("gc crc post: %u ms", (unsigned)gc_last_crc_ms());
        } else {
            fail++;
            log_line("xmr: FAIL rc=%d", rc);
        }
        memset(xmr_out, 0, sizeof(xmr_out));
        memset(entropy, 0, sizeof(entropy));
    }

    PsramFree(sign_ws); /* v16: sign_ws is a PsramMalloc block — never newlib-free */
    return fail;
}


/* ====== CMSIS-RTOS task 创建入口 ====== */
void CreateShlosiloSmokeTask(void) {
    const osThreadAttr_t smoke_attr = {
        .name = "shlosilo_smoke",
        .stack_size = SHLOSILO_SMOKE_STACK_BYTES,
        .priority = (osPriority_t)osPriorityNormal,
    };
    osThreadId_t tid = osThreadNew(ShlosiloSmokeTask, NULL, &smoke_attr);
    if (tid == NULL) {
        while (1) { __asm__("wfi"); }
    }
}

/* shlosilo_panic_hook — L3 panic 显示（embedded_alloc.rs 的 panic handler 调用）
 * 恢复中断（panic 可能在 critical section 内）→ LCD 红字显示消息 → 保持 LVGL 刷新 + 喂狗
 */
#include "mhscpu_wdt.h"
void shlosilo_panic_hook(const uint8_t *msg, size_t len)
{
    __asm__ volatile("cpsie i"); /* 恢复中断，防止 panic 于 critical section 内导致 tick 停摆 */

    char tmp[192];
    size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, msg, n);
    tmp[n] = '\0';

    /* v8: persist the panic text to the flash record FIRST (the screen may
     * already be dead and this loop never returns — without this the panic is
     * invisible and the battery dies silently).
     * v13: write to the PANIC sector — the v12 panic record clobbered the
     * summary sector AFTER the battery had already saved the xmr results. */
    {
        char rec[208];
        gc_flash_init();
        snprintf(rec, sizeof(rec), "PREV PANIC: %s", tmp);
        res_write_at(RES_PANIC_BASE, rec);
    }

    if (g_log != NULL) {
        char line[224];
        snprintf(line, sizeof(line), "PANIC: %s", tmp);
        lvgl_lock();
        lv_label_set_text(g_log, line);
        lvgl_unlock();
    }

    for (;;) {
        lvgl_lock();
        lv_task_handler();   /* 保持屏幕刷新（panic 消息可见） */
        lvgl_unlock();
        WDT_ReloadCounter(); /* 喂狗防复位 */
        osDelay(5);
    }
}

/* device-timing 时钟回调：给 Rust 侧的毫秒计数 */
static uint32_t smoke_tick_ms(void);
static uint32_t smoke_tick_ms(void)
{
    return (uint32_t)osKernelGetTickCount();
}

void ShlosiloSmokeTask(void *argument)
{
    (void)argument;
    /* v9: consume the PREVIOUS run's record FIRST, before any checkpoint
     * write — v8 read it after ckpt(1)/ckpt(2), so the replay showed this
     * boot's own checkpoint and erased the real death record (ordering bug). */
    /* locals (stack), not statics — .bss is guarded against the diag region */
    char g_prev_rec[420];
    char g_prev_panic[220];
    char g_prev_hb[110];
    int g_prev_len = 0;
    int g_prev_panic_len = 0;
    int g_prev_hb_len = 0;
    gc_flash_init(); /* QSPI write access for ckpt writes + consume-erase */
    g_prev_len = res_load(g_prev_rec, sizeof(g_prev_rec));
    g_prev_panic_len =
        res_load_at(RES_PANIC_BASE, g_prev_panic, sizeof(g_prev_panic));
    g_prev_hb_len = res_load_at(RES_HB_BASE, g_prev_hb, sizeof(g_prev_hb));
    g_diag_boot_count += 1;
    uint32_t prev_prog = g_diag_progress;
    diag_prog(1); /* task entry */
    osDelay(500); /* 等 LVGL/helloworld task 初始化 */
    lvgl_lock();
    g_title = lv_label_create(lv_scr_act());
    /* r = warm boot count (climbing = reset loop), p = where the PREVIOUS
     * boot got to (see diag_prog markers; 1..11). */
    char title[64];
    snprintf(title, sizeof(title), "shlosilo P6.2 r=%lu p=%lu",
             (unsigned long)g_diag_boot_count, (unsigned long)prev_prog);
    lv_label_set_text(g_title, title);
    lv_obj_align(g_title, LV_ALIGN_TOP_LEFT, 10, 10);
    lv_obj_set_style_text_color(g_title, lv_color_hex(0x00FF00), 0);

    /* 可滚动日志容器：测试行数已超出一屏，触摸滑动查看（indev 注册于 helloworld_task） */
    lv_obj_t *scroll = lv_obj_create(lv_scr_act());
    lv_obj_set_size(scroll, 480, 800 - 60);
    lv_obj_align(scroll, LV_ALIGN_TOP_LEFT, 0, 60);
    lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(scroll, 0, 0);
    lv_obj_set_style_pad_all(scroll, 0, 0);
    lv_obj_set_scrollbar_mode(scroll, LV_SCROLLBAR_MODE_AUTO);

    g_log = lv_label_create(scroll);
    lv_label_set_text(g_log, "running...");
    lv_obj_align(g_log, LV_ALIGN_TOP_LEFT, 10, 0);
    lv_label_set_long_mode(g_log, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(g_log, 460);
    /* Same fluorescent green as the title for readability on the black background */
    lv_obj_set_style_text_color(g_log, lv_color_hex(0x00FF00), 0);
    lvgl_unlock();

    memset(g_logbuf, 0, sizeof(g_logbuf));
    diag_prog(2); /* UI setup done */

    /* Fault record FIRST (it used to sit behind the touch-probe line, so a
     * hang before that line hid exactly the evidence needed). */
    if (g_fault_log[0] == 0x464C5444U) {
        log_line("FAULT cfsr=%08x hfsr=%08x",
                 (unsigned)g_fault_log[1], (unsigned)g_fault_log[2]);
        log_line("FAULT bfar=%08x pc=%08x lr=%08x",
                 (unsigned)g_fault_log[3], (unsigned)g_fault_log[4],
                 (unsigned)g_fault_log[5]);
        /* 清除，避免下次开机误报 */
        for (int i = 0; i < 7; i++) {
            g_fault_log[i] = 0;
        }
    } else {
        log_line("no fault record (boot r=%lu)",
                 (unsigned long)g_diag_boot_count);
    }
    log_line("wdt cr=%08x (0 = never armed)", (unsigned)g_wdt_cr_readback);

    /* v7/v9: replay the PREVIOUS run's record (read at task entry, before the
     * checkpoint writes — displayed now, one label update = one draw). */
    if (g_prev_len > 0 || g_prev_panic_len > 0 || g_prev_hb_len > 0) {
        if (g_prev_len > 0) {
            printf("[rec] %s\r\n", g_prev_rec);
            if (strlen(g_logbuf) + strlen(g_prev_rec) + 2 < sizeof(g_logbuf)) {
                strcat(g_logbuf, g_prev_rec);
                strcat(g_logbuf, "\n");
            }
        }
        if (g_prev_panic_len > 0) {
            printf("[rec] %s\r\n", g_prev_panic);
            if (strlen(g_logbuf) + strlen(g_prev_panic) + 2 < sizeof(g_logbuf)) {
                strcat(g_logbuf, g_prev_panic);
                strcat(g_logbuf, "\n");
            }
        }
        if (g_prev_hb_len > 0) {
            printf("[rec] %s\r\n", g_prev_hb);
            if (strlen(g_logbuf) + strlen(g_prev_hb) + 2 < sizeof(g_logbuf)) {
                strcat(g_logbuf, g_prev_hb);
                strcat(g_logbuf, "\n");
            }
        }
        lvgl_lock();
        lv_label_set_text(g_log, g_logbuf);
        lvgl_unlock();
    }

    diag_prog(3); /* pre touch-probe delay */
    /* 触摸探测结果屏显（build D 诊断）。TouchInit 位bang扫 128 地址
     * ~1s，helloworld/smoke 两任务并发，等 3s 保证探测已完成。
     * 2026-09-30: split into 6 heartbeats so a death inside the wait window
     * leaves a visible trail (the old firmware died somewhere in here). */
    for (int w = 1; w <= 6; w++) {
        log_line("wait %d/6", w);
        diag_square(3);
        backlight_dip(1); /* liveness channel independent of the LCD path */
        osDelay(260);
    }
    diag_prog(4); /* post delay, first log_line about to run */
    log_line("touch probe: addr=0x%02X ok=%d",
             (unsigned)g_touch_probe_addr, (int)g_touch_probe_ok);
    diag_prog(5); /* first log_line through log+LVGL path */
    extern volatile uint16_t g_touch_diag_x;
    extern volatile uint16_t g_touch_diag_y;
    extern volatile uint32_t g_touch_diag_err;
    extern volatile uint32_t g_touch_diag_press;

    int fail = run_checks();
    /* v7: persist the key numbers as soon as the battery core is done. */
    res_save_now();

    /* 触摸诊断汇总：run_checks 期间(~45s)的按下次数/错误/末次坐标 */
    log_line("touch diag: press=%u err=%u x=%u y=%u",
             (unsigned)g_touch_diag_press, (unsigned)g_touch_diag_err,
             (unsigned)g_touch_diag_x, (unsigned)g_touch_diag_y);

    /* Phase 6.6：MCU 峰值（heap_4 min-ever = 自启动以来的高水位）。
     * PSRAM = LCD framebuffer + shlosilo Rust alloc；SRAM = FreeRTOS/LVGL。
     * 本 smoke 含 ETH sign + multipart + XMR 1-input BP+。 */
    {
        const size_t psram_total = PsramGetTotalSize();
        const size_t psram_min   = PsramGetMinimumEverFreeHeapSize();
        const size_t psram_free  = PsramGetFreeHeapSize();
        const size_t sram_total  = (size_t)configTOTAL_HEAP_SIZE;
        const size_t sram_min    = xPortGetMinimumEverFreeHeapSize();
        const size_t sram_free   = xPortGetFreeHeapSize();
        const UBaseType_t stk_remain_w = uxTaskGetStackHighWaterMark(NULL);
        const unsigned stk_remain_b =
            (unsigned)stk_remain_w * (unsigned)sizeof(StackType_t);
        const unsigned stk_used_b =
            (SHLOSILO_SMOKE_STACK_BYTES > stk_remain_b)
                ? (unsigned)SHLOSILO_SMOKE_STACK_BYTES - stk_remain_b
                : 0u;
        const unsigned psram_peak_k =
            (psram_total >= psram_min)
                ? (unsigned)((psram_total - psram_min) / 1024)
                : 0u;
        const unsigned sram_peak_k =
            (sram_total >= sram_min)
                ? (unsigned)((sram_total - sram_min) / 1024)
                : 0u;
        log_line("psram peak %uK/%uK free %uK",
                 psram_peak_k,
                 (unsigned)(psram_total / 1024),
                 (unsigned)(psram_free / 1024));
        log_line("sram  peak %uK/%uK free %uK",
                 sram_peak_k,
                 (unsigned)(sram_total / 1024),
                 (unsigned)(sram_free / 1024));
        log_line("stk   used %uK remain %uW",
                 stk_used_b / 1024,
                 (unsigned)stk_remain_w);
    }

    /* ---- device primitive perf-bench (feature perf-bench-ffi) ----
     * Raw per-primitive costs, timed with the kernel tick. Zero when the .a
     * lacks the feature (stubs). Digests prove the calls ran (deterministic
     * across boots); the numbers calibrate the loop models. */
    {
        uint32_t t, b0;
        unsigned long long dfm, dfs, dsel, dmad, dquad, dct, dvt;

        b0 = osKernelGetTickCount();
        dfm = shlosilo_perf_fmul(20000);
        t = osKernelGetTickCount() - b0;
        log_line("bench fmul 20k: %u ms", (unsigned)t);
        b0 = osKernelGetTickCount();
        dfs = shlosilo_perf_fsq(20000);
        t = osKernelGetTickCount() - b0;
        log_line("bench fsq 20k: %u ms", (unsigned)t);
        b0 = osKernelGetTickCount();
        dsel = shlosilo_perf_select(5000);
        t = osKernelGetTickCount() - b0;
        log_line("bench select 5k: %u ms", (unsigned)t);
        b0 = osKernelGetTickCount();
        dmad = shlosilo_perf_madd(4000);
        t = osKernelGetTickCount() - b0;
        log_line("bench madd 4k: %u ms", (unsigned)t);
        b0 = osKernelGetTickCount();
        dquad = shlosilo_perf_quadruple(800);
        t = osKernelGetTickCount() - b0;
        log_line("bench quad 800: %u ms", (unsigned)t);
        b0 = osKernelGetTickCount();
        dct = shlosilo_perf_ct_chunk(36, 2);
        t = osKernelGetTickCount() - b0;
        log_line("bench ct36 x2: %u ms", (unsigned)t);
        b0 = osKernelGetTickCount();
        dvt = shlosilo_perf_vartime_2term(4);
        t = osKernelGetTickCount() - b0;
        log_line("bench vart2 x4: %u ms", (unsigned)t);
        log_line("bench dig: %02x %02x %02x %02x %02x %02x %02x",
                 (unsigned)(dfm & 0xff), (unsigned)(dfs & 0xff),
                 (unsigned)(dsel & 0xff), (unsigned)(dmad & 0xff),
                 (unsigned)(dquad & 0xff), (unsigned)(dct & 0xff),
                 (unsigned)(dvt & 0xff));

        /* Experiment C: linear-read bandwidth, SRAM vs PSRAM vs XIP flash.
         * 128KB per pass, u32 strided reads (one load per 4 bytes; both this
         * loop's own code and the data come from their respective regions).
         * If flash read cost dwarfs SRAM (~10x+), the XIP path explains the
         * device-wide slowdown; if comparable, flash fetch is NOT the issue. */
        {
            static const struct { const char *name; const uint8_t *base; } regions[3] = {
                { "sram", (const uint8_t *)0x20099000u },   /* .sram_pool (SRAM) */
                { "psram", (const uint8_t *)0x80000000u },  /* PSRAM heap */
                { "xip", (const uint8_t *)0x01081000u },    /* firmware image (flash) */
            };
            int ri, rep;
            for (ri = 0; ri < 3; ri++) {
                for (rep = 0; rep < 2; rep++) {
                    uint32_t acc = 0;
                    uint32_t t0b = osKernelGetTickCount();
                    uint32_t i;
                    for (i = 0; i < 131072u; i += 4) {
                        acc += *(volatile const uint32_t *)(regions[ri].base + i);
                    }
                    t = osKernelGetTickCount() - t0b;
                    log_line("bench rd128K %s#%d: %u ms (a=%08X)",
                             regions[ri].name, rep + 1, (unsigned)t, (unsigned)acc);
                }
            }
        }

        /* Experiment D: configured-clock registers + ground-truth core clock.
         * FREQ_SEL raw; HCLK_1MS_VAL / PCLK_1MS_VAL are hardware counters
         * (cycles per ms — divide by 1000 for MHz). Then the dependent-add
         * chain: 8 adds x iters, M4 = 1 cycle per dependent add. */
        log_line("cpu regs: freq_sel=%08X hclk_ms=%u pclk_ms=%u",
                 (unsigned)SYSCTRL->FREQ_SEL,
                 (unsigned)SYSCTRL->HCLK_1MS_VAL,
                 (unsigned)SYSCTRL->PCLK_1MS_VAL);
        {
            uint32_t ta = osKernelGetTickCount();
            uint32_t dv = d_alu_chain(4000000u);
            ta = osKernelGetTickCount() - ta;
            /* 4e6 iters x 8 dependent adds = 32e6 core cycles minimum.
             * A tick-based derivative: kcyc/ms = 32000/ta (if ta>0). */
            log_line("bench alu 4Mx8: %u ms (d=%u kcyc/ms=%u)",
                     (unsigned)ta, (unsigned)(dv & 0xff),
                     (unsigned)(ta ? (32000u / ta) : 0u));
        }

        /* Experiment D: repeated read of ONE word (data-cache test).
         * 65536 reads of the same address: if a data cache exists, this is
         * a few cycles/read; if not, every read pays the full bus cost. */
        {
            const uint8_t *spots[3] = {
                (const uint8_t *)0x20099000u, (const uint8_t *)0x80000000u,
                (const uint8_t *)0x01081000u,
            };
            static const char *spot_names[3] = { "sram", "psram", "xip" };
            int si;
            for (si = 0; si < 3; si++) {
                uint32_t acc = 0;
                uint32_t i;
                uint32_t th = osKernelGetTickCount();
                for (i = 0; i < 65536u; i++) {
                    acc += *(volatile const uint32_t *)spots[si];
                }
                th = osKernelGetTickCount() - th;
                log_line("bench hot %s: %u ms (a=%08X)", spot_names[si],
                         (unsigned)th, (unsigned)acc);
            }
        }

        /* Experiment D: 32-byte block reads (8 words per iteration, the
         * compiler sees the full row so it can issue the loads back to back).
         * Compare against the 4-byte-stride rd128K above: if block reads are
         * much faster, the bus rewards locality/pipelining; if equal, each
         * 4-byte access is a fixed-latency transaction. */
        {
            static const struct { const char *name; const uint8_t *base; } bregions[3] = {
                { "sram", (const uint8_t *)0x20099000u },
                { "psram", (const uint8_t *)0x80000000u },
                { "xip", (const uint8_t *)0x01081000u },
            };
            int bi;
            for (bi = 0; bi < 3; bi++) {
                volatile const uint32_t *p = (volatile const uint32_t *)bregions[bi].base;
                uint32_t acc = 0;
                uint32_t blk;
                uint32_t tb = osKernelGetTickCount();
                for (blk = 0; blk < 4096u; blk++) {   /* 4096 x 32B = 128KB */
                    acc += p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7];
                    p += 8;
                }
                tb = osKernelGetTickCount() - tb;
                log_line("bench blk32 %s: %u ms (a=%08X)", bregions[bi].name,
                         (unsigned)tb, (unsigned)acc);
            }
        }

        /* Experiment E: DWT CYCCNT ground-truth cycles (no clock
         * assumption) + differential core-clock measurement + PSRAM
         * controller config dump. */
        log_line("psram cfg: cmd=%08X devpara=%08X",
                 (unsigned)PSRAM->PSRAM_CMD, (unsigned)PSRAM->DEVICE_PARA);
        {
            int cyc_ok;
            uint32_t cc0, cc1;
            CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
            DWT->CYCCNT = 0;
            DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
            cc0 = DWT->CYCCNT;
            (void)d_alu_chain(1000u);
            cc1 = DWT->CYCCNT;
            cyc_ok = (cc1 != cc0);
            log_line("cyccnt: %s (ctrl=%08X)",
                     cyc_ok ? "alive" : "dead", (unsigned)DWT->CTRL);

            /* Differential clock: the extra 24 ADDS per iteration of the
             * 32-add chain cost exactly 4e6 x 24 = 96e6 core cycles; the
             * per-iteration branch/loop overhead cancels in the delta. */
            {
                uint32_t ta8, ta32;
                ta8 = osKernelGetTickCount();
                (void)d_alu_chain(4000000u);
                ta8 = osKernelGetTickCount() - ta8;
                ta32 = osKernelGetTickCount();
                (void)d_alu_chain32(4000000u);
                ta32 = osKernelGetTickCount() - ta32;
                log_line("alu diff: t8=%u t32=%u dt=%u MHz~%u",
                         (unsigned)ta8, (unsigned)ta32,
                         (unsigned)(ta32 - ta8),
                         (unsigned)((ta32 > ta8) ? (96000u / (ta32 - ta8)) : 0u));
            }

            if (cyc_ok) {
                cc0 = DWT->CYCCNT;
                (void)d_alu_chain(1000000u);
                cc1 = DWT->CYCCNT;
                log_line("cyc alu 1Mx8: %u", (unsigned)(cc1 - cc0));
                cc0 = DWT->CYCCNT; (void)shlosilo_perf_fmul(20000); cc1 = DWT->CYCCNT;
                log_line("cyc fmul 20k: %u", (unsigned)(cc1 - cc0));
                cc0 = DWT->CYCCNT; (void)shlosilo_perf_select(5000); cc1 = DWT->CYCCNT;
                log_line("cyc select 5k: %u", (unsigned)(cc1 - cc0));
                cc0 = DWT->CYCCNT; (void)shlosilo_perf_madd(4000); cc1 = DWT->CYCCNT;
                log_line("cyc madd 4k: %u", (unsigned)(cc1 - cc0));
            }
        }

        /* Experiment E: affine-niels table variants (96B/entry vs 160B:
         * 40% less scan + conditional-select work). Zero when the .a lacks
         * the feature. */
        {
            uint32_t t2, b2;
            b2 = osKernelGetTickCount();
            (void)shlosilo_perf_select_affine(5000);
            t2 = osKernelGetTickCount() - b2;
            log_line("bench selaff 5k: %u ms", (unsigned)t2);
            b2 = osKernelGetTickCount();
            (void)shlosilo_perf_madd_affine(4000);
            t2 = osKernelGetTickCount() - b2;
            log_line("bench maddaff 4k: %u ms", (unsigned)t2);
        }
    }

    /* panic 检测：Rust panic handler 写过 0xDEADBEEF 到 0x2000F000 */
    if (*(volatile uint32_t *)0x2000F000 == 0xDEADBEEF) {
        strcat(g_logbuf, "== RUST PANIC DETECTED ==\n");
    }

    if (fail == 0) {
        if (strlen(g_logbuf) + 14 < sizeof(g_logbuf)) {
            strcat(g_logbuf, "== ALL PASS ==");
        }
    } else {
        char tail[32];
        snprintf(tail, sizeof(tail), "== FAIL n=%d ==", fail);
        if (strlen(g_logbuf) + strlen(tail) + 1 < sizeof(g_logbuf)) {
            strcat(g_logbuf, tail);
        }
    }
    lvgl_lock();
    lv_label_set_text(g_log, g_logbuf);
    lvgl_unlock();

    /* Battery finished: 5 fast backlight dips = "done" even with a dead
     * screen (diagnostic channel, 2026-09-30). */
    res_save_now();
    backlight_dip(5);

    for (;;) {
        osDelay(10000); /* 常驻：结果留在屏幕上，WDT 由 helloworld task 喂 */
    }
}
