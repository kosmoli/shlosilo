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
#include <string.h>
#include "cmsis_os.h"
#include "lvgl.h"
#include "hal_lcd.h"

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

static lv_obj_t *g_title = NULL;
static lv_obj_t *g_log   = NULL;
static char g_logbuf[512];

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
        lv_label_set_text(g_log, g_logbuf);
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
    uint32_t t0 = osKernelGetTickCount();
    int rc = shlosilo_sign_ur_ffi(FIXTURE_ETH_SIGN_REQUEST, idx12, 12,
                                  NULL, 0, 0, NULL, 0, out, sizeof(out), &actual);
    uint32_t dt = osKernelGetTickCount() - t0;
    if (rc == 0 && actual > 0 && out[0] == 0x02) {
        log_line("sign: PASS (%u bytes, type=0x%02x)", actual, out[0]);
        log_line("sign time: %u ms", dt);
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
        shlosilo_ur_encoder_t *enc = shlosilo_ur_encode_begin(
            "xmr-txunsigned", mp_payload, sizeof(mp_payload), 200);
        shlosilo_ur_decoder_t *dec = shlosilo_ur_decode_new();
        static uint8_t frame[SHLOSILO_MULTIPART_FRAME_BUF_MAX_LEN];
        unsigned int flen = 0;
        int mp_fail = 0;
        int guard = 0;
        while (!shlosilo_ur_decode_complete(dec)) {
            if (shlosilo_ur_encode_next(enc, frame, sizeof(frame), &flen) != OK ||
                shlosilo_ur_decode_feed(dec, (const char *)frame, NULL) != OK) {
                mp_fail = 1;
                break;
            }
            if (++guard > 500) { mp_fail = 1; break; }
        }
        static uint8_t mp_out[1024];
        unsigned int mp_len = 0;
        if (!mp_fail &&
            shlosilo_ur_decode_payload(dec, mp_out, sizeof(mp_out), &mp_len) == OK &&
            mp_len == sizeof(mp_payload) &&
            memcmp(mp_out, mp_payload, mp_len) == 0) {
            log_line("r3 multipart: PASS (%d frames)", guard);
        } else {
            fail++;
            log_line("r3 multipart: FAIL");
        }
        /* cyclic frame smoke: OK return only */
        if (shlosilo_ur_encode_next_cyclic(enc, frame, sizeof(frame), &flen) != OK) {
            fail++;
            log_line("r3 cyclic: FAIL");
        }
        shlosilo_ur_encode_free(enc);
        shlosilo_ur_decode_free(dec);
        memset(mp_payload, 0, sizeof(mp_payload));
        memset(mp_out, 0, sizeof(mp_out));
        memset(frame, 0, sizeof(frame));
    }

return fail;
}


/* ====== CMSIS-RTOS task 创建入口 ====== */
void CreateShlosiloSmokeTask(void) {
    const osThreadAttr_t smoke_attr = {
        .name = "shlosilo_smoke",
        .stack_size = 65536, /* 64KB: export(PBKDF2+BIP32 chain) + sign(ECDSA, no precomputed-tables) deep call stacks */
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
        lv_label_set_text(g_log, line);
    }

    for (;;) {
        lv_task_handler();   /* 保持屏幕刷新（panic 消息可见） */
        WDT_ReloadCounter(); /* 喂狗防复位 */
        osDelay(5);
    }
}

void ShlosiloSmokeTask(void const *argument)
{
    (void)argument;
    osDelay(500); /* 等 LVGL/helloworld task 初始化 */

    g_title = lv_label_create(lv_scr_act());
    lv_label_set_text(g_title, "shlosilo P6.2");
    lv_obj_align(g_title, LV_ALIGN_TOP_LEFT, 10, 10);
    lv_obj_set_style_text_color(g_title, lv_color_hex(0x00FF00), 0);

    g_log = lv_label_create(lv_scr_act());
    lv_label_set_text(g_log, "running...");
    lv_obj_align(g_log, LV_ALIGN_TOP_LEFT, 10, 50);

    memset(g_logbuf, 0, sizeof(g_logbuf));

    int fail = run_checks();

    /* panic 检测：Rust panic handler 写过 0xDEADBEEF 到 0x2000F000 */
    if (*(volatile uint32_t *)0x2000F000 == 0xDEADBEEF) {
        strcat(g_logbuf, "== RUST PANIC DETECTED ==\n");
    }

    if (fail == 0) {
        strcat(g_logbuf, "== ALL PASS ==");
    } else {
        char tail[32];
        snprintf(tail, sizeof(tail), "== FAIL n=%d ==", fail);
        strcat(g_logbuf, tail);
    }
    lv_label_set_text(g_log, g_logbuf);

    for (;;) {
        osDelay(10000); /* 常驻：结果留在屏幕上，WDT 由 helloworld task 喂 */
    }
}
