/* shlosilo_smoke_task.c — P6.2c: shlosilo P6.2 smoke on forgebox-helloworld
 *
 * 干净 L3 宿主：无 keystone 业务逻辑，只验证 shlosilo FFI 全链路。
 * LCD 显示（真机无串口）：
 *   顶部   : "shlosilo P6.2"       (标题)
 *   中部   : 每步结果逐行           (PASS/FAIL)
 *   底部   : 签名耗时 ms            (性能基准)
 */

#include "shlosilo_smoke_task.h"
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
#define SHLOSILO_SMOKE_OK 0 /* ShlosiloErrorCode::Ok */

/* device-timing 时钟回调：给 Rust 侧的毫秒计数（定义在文件尾） */
/* xmr_gen_cache_flash.c */
extern void gc_flash_init(void);
extern const uint8_t *gc_load(const uint8_t *prefix, uint32_t prefix_len);
extern uint32_t gc_store(const uint8_t *prefix, uint32_t prefix_len,
                         const uint8_t *blob, uint32_t blob_len);
extern uint32_t gc_probe(void);
extern unsigned int shlosilo_sram_pool_fallback_count(void);
extern unsigned long shlosilo_sram_pool_fallback_max_size(void);
extern unsigned long shlosilo_sram_pool_fallback_total_bytes(void);
extern unsigned long shlosilo_sram_pool_fallback_last_size(void);
extern unsigned long shlosilo_sram_pool_free_total(void);
extern unsigned long shlosilo_sram_pool_free_largest(void);
extern unsigned int shlosilo_sram_pool_block_count(void);
extern unsigned long shlosilo_sram_pool_peak_live(void);
extern unsigned int shlosilo_sram_pool_peak_blocks(void);
extern void shlosilo_cn_timing_set_clock(unsigned int clock_fptr);
extern void shlosilo_cn_timing_reset(void);
extern unsigned int shlosilo_cn_timing_phase(unsigned char phase);
extern void shlosilo_tx_phase_set_clock(unsigned int clock_fptr);
extern void shlosilo_tx_phase_reset(void);
extern unsigned int shlosilo_tx_phase_phase(unsigned char phase);

static unsigned int smoke_tick_ms(void);
/* SRAM 栈。XMR/ETH 热路径不能把栈放 PSRAM（QSPI 会把 sign 拖到数秒）。
 * 64KB：ETH 实测 used 35K。生成元改为循环 decompress 后不再需要 512KB。 */
#define SHLOSILO_SMOKE_STACK_BYTES (64u * 1024u)

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
 * 越界写 .bss 邻居 → crash。SRAM 池后仍有 ~65KB 余量，2048B 无压力。 */
static char g_logbuf[2048];

static void log_line(const char *fmt, ...)
{
    va_list ap;
    char line[96];
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
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
    shlosilo_timing_set_clock_fn((unsigned int)smoke_tick_ms);
    uint32_t t0 = osKernelGetTickCount();
    int rc = shlosilo_sign_ur_ffi(FIXTURE_ETH_SIGN_REQUEST, idx12, 12,
                                  NULL, 0, 0, NULL, 0, out, sizeof(out), &actual);
    uint32_t dt = osKernelGetTickCount() - t0;
    if (rc == 0 && actual > 0 && out[0] == 0x02) {
        log_line("sign: PASS (%u bytes, type=0x%02x)", actual, out[0]);
        log_line("sign time: %u ms", dt);
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
                                       NULL, 0, 0, NULL, 0, out, sizeof(out), &actual);
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
                             out, sizeof(out), &actual) != 0) {
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
        UrMultipartEncoder *enc = shlosilo_ur_encode_begin(
            "xmr-txunsigned", mp_payload, sizeof(mp_payload), 200);
        UrMultipartDecoder *dec = shlosilo_ur_decode_new();
        static uint8_t frame[1024]; /* FRAME_BUF_MAX_LEN 对齐 poc4 c_abi */
        unsigned int flen = 0;
        int mp_fail = 0;
        int guard = 0;
        while (!shlosilo_ur_decode_complete(dec)) {
            if (shlosilo_ur_encode_next(enc, frame, sizeof(frame), &flen) != SHLOSILO_SMOKE_OK ||
                shlosilo_ur_decode_feed(dec, (const char *)frame, NULL) != SHLOSILO_SMOKE_OK) {
                mp_fail = 1;
                break;
            }
            if (++guard > 500) { mp_fail = 1; break; }
        }
        static uint8_t mp_out[1024];
        unsigned int mp_len = 0;
        if (!mp_fail &&
            shlosilo_ur_decode_payload(dec, mp_out, sizeof(mp_out), &mp_len) == SHLOSILO_SMOKE_OK &&
            mp_len == sizeof(mp_payload) &&
            memcmp(mp_out, mp_payload, mp_len) == 0) {
            log_line("r3 multipart: PASS (%d frames)", guard);
        } else {
            fail++;
            log_line("r3 multipart: FAIL");
        }
        /* cyclic frame smoke: SHLOSILO_SMOKE_OK return only */
        if (shlosilo_ur_encode_next_cyclic(enc, frame, sizeof(frame), &flen) != SHLOSILO_SMOKE_OK) {
            fail++;
            log_line("r3 cyclic: FAIL");
        }
        shlosilo_ur_encode_free(enc);
        shlosilo_ur_decode_free(dec);
        memset(mp_payload, 0, sizeof(mp_payload));
        memset(mp_out, 0, sizeof(mp_out));
        memset(frame, 0, sizeof(frame));
    }

    /* 8. XMR 1-input BP+（P6.6 MCU 峰值；idx12 自造 ring16，非真实资金） */
    /* BP+ generator cache: register flash backend (no-op against a production
     * .a without the generator-cache-ffi feature). */
    gc_flash_init();
    shlosilo_gen_cache_set_hooks((unsigned int)gc_load, (unsigned int)gc_store);
    /* Cache state probe: 0=hit 1=blank 2=corrupt 3=not-ready */
    log_line("gencache pre: %u", (unsigned)gc_probe());
    /* BP+ prove-phase timing: same clock as device-timing. */
    shlosilo_bp_timing_set_clock((unsigned int)smoke_tick_ms);
    shlosilo_bp_timing_reset();
    shlosilo_cn_timing_set_clock((unsigned int)smoke_tick_ms);
    shlosilo_cn_timing_reset();
    shlosilo_tx_phase_set_clock((unsigned int)smoke_tick_ms);
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
        uint32_t t0 = osKernelGetTickCount();
        int rc = shlosilo_sign_ur_ffi(FIXTURE_XMR_TX_UNSIGNED, idx12, 12,
                                      NULL, 0, 0, entropy, sizeof(entropy),
                                      xmr_out, sizeof(xmr_out), &xmr_len);
        uint32_t dt = osKernelGetTickCount() - t0;
        if (rc == 0 && xmr_len > 64) {
            log_line("xmr: PASS (%u bytes)", xmr_len);
            log_line("xmr time: %u ms", dt);
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
            log_line("sram pool: peak live=%luK blocks=%u cap=400K thr=48K ch=36",
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
        } else {
            fail++;
            log_line("xmr: FAIL rc=%d", rc);
        }
        memset(xmr_out, 0, sizeof(xmr_out));
        memset(entropy, 0, sizeof(entropy));
    }

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
static unsigned int smoke_tick_ms(void);
static unsigned int smoke_tick_ms(void)
{
    return (unsigned int)osKernelGetTickCount();
}

void ShlosiloSmokeTask(void *argument)
{
    (void)argument;
    osDelay(500); /* 等 LVGL/helloworld task 初始化 */
    lvgl_lock();
    g_title = lv_label_create(lv_scr_act());
    lv_label_set_text(g_title, "shlosilo P6.2");
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

    /* 触摸探测结果屏显（build D 诊断）。TouchInit 位bang扫 128 地址
     * ~1s，helloworld/smoke 两任务并发，等 3s 保证探测已完成。 */
    osDelay(3000);
    log_line("touch probe: addr=0x%02X ok=%d",
             (unsigned)g_touch_probe_addr, (int)g_touch_probe_ok);
    extern volatile uint16_t g_touch_diag_x;
    extern volatile uint16_t g_touch_diag_y;
    extern volatile uint32_t g_touch_diag_err;
    extern volatile uint32_t g_touch_diag_press;

    /* K2-D 诊断：上次复位的 HardFault 捕获记录（hardfault_diag.c 写入） */
    {
        extern const volatile uint32_t *const g_fault_log;
        if (g_fault_log[0] == 0x464C5444U) {
            log_line("FAULT cfsr=%08x hfsr=%08x",
                     (unsigned)g_fault_log[1], (unsigned)g_fault_log[2]);
            log_line("FAULT bfar=%08x pc=%08x lr=%08x",
                     (unsigned)g_fault_log[3], (unsigned)g_fault_log[4],
                     (unsigned)g_fault_log[5]);
            /* 清除，避免下次开机误报 */
            for (int i = 0; i < 7; i++) {
                ((volatile uint32_t *)g_fault_log)[i] = 0;
            }
        }
    }

    int fail = run_checks();

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

    for (;;) {
        osDelay(10000); /* 常驻：结果留在屏幕上，WDT 由 helloworld task 喂 */
    }
}
