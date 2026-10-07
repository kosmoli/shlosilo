#include "se_smoke.h"
#include "string.h"
#include "stdio.h"
#include "stdarg.h"
#include "cmsis_os.h"
#include "err_code.h"
#include "user_utils.h"
#include "user_memory.h"
#include "drv_atecc608b.h"
#include "cryptoauthlib.h"
#include "drv_ds28s60.h"
#include "drv_trng.h"
#include "drv_otp.h"
#include "drv_mpu.h"
#include "hash_and_salt.h"
#include "se_manager.h"
#include "assert.h"

/*
 * se_smoke.c - SE smoke battery + gated provisioning console (Task 7).
 * See se_smoke.h for the hardware safety gate rationale. Screen text is
 * English (the smoke LVGL font is Latin-only); the operator checklist with
 * the Chinese annotations lives in flux/forgebox/docs/se-keystore-checklist.md.
 */

/* console input, filled by CmdIsrRcvByte (main.c). Sized (the shared
 * TEST_CMD_MAX_LENGTH contract in se_smoke.h) so the consumer can wipe the
 * WHOLE buffer after draining it - not just the bytes it copied out. */
extern uint8_t g_testCmdRcvBuffer[TEST_CMD_MAX_LENGTH];
extern volatile uint32_t g_testCmdReady;

/* Password hygiene (gap 3): volatile walk, dead-store-elimination-proof -
 * the same idiom as product_task.c's seed_plate_wipe (pool item #22
 * direction). A plain memset could be elided on the password copies. */
static void WipeVolatile(void *buf, uint32_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    uint32_t i;

    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

static void (*g_logSink)(const char *line) = NULL;

#define SE_PROV_TEST_PWD    "shlosilo-se-smoke"
#define SE_WRONG_PWD        "shlosilo-se-wrong-pwd"
#define SE_ARM_WINDOW_MS    60000u

#define SE_ARM_NONE         0
#define SE_ARM_PROVISION    1
#define SE_ARM_SLOTS        2

static uint8_t g_armed;
static uint32_t g_armTick;

static void Log(const char *fmt, ...)
{
    char line[112];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    printf("[se] %s\r\n", line);
    if (g_logSink != NULL) {
        g_logSink(line);
    }
}

void SeSmokeSetLog(void (*fn)(const char *line))
{
    g_logSink = fn;
}

/* ---- OTP helpers (read-only probe side) ---- */

static bool OtpAreaProvisioned(uint32_t addr, uint32_t len)
{
    bool provisioned;

    MpuSetOtpProtection(false);
    OTP_PowerOn();
    provisioned = CheckEntropy((const uint8_t *)addr, len);
    MpuSetOtpProtection(true);
    return provisioned;
}

static void OtpBurn(uint32_t addr, const char *what, uint32_t len)
{
    uint8_t buf[96];
    bool rb_ok;

    if (len > sizeof(buf)) {
        len = sizeof(buf);
    }
    TrngGet(buf, len);
    MpuSetOtpProtection(false);
    OTP_PowerOn();
    /* Loud: a silently failed burn would make every later derivation use a
     * different piece (same discipline as keystore.c CombineInnerAesKey). */
    ASSERT(SUCCESS_CODE == WriteOtpData(addr, buf, len));
    /* Post-burn readback (OTP is memory-mapped, protection still off): a burn
     * that did not land must die HERE, not surface much later as a wrong key
     * derivation. Byte-exact readback is proven on this part (drv_otp.c
     * ReadTamperFlag compares the same mapped bytes). */
    rb_ok = (memcmp((const void *)addr, buf, len) == 0);
    MpuSetOtpProtection(true);
    CLEAR_ARRAY(buf);
    Log("%s: BURNED (%u bytes, PERMANENT)", what, (unsigned)len);
    if (!rb_ok) {
        Log("%s: READBACK FAIL (burn did not land!)", what);
    }
    ASSERT(rb_ok);
    Log("%s: readback: OK", what);
}

/* ---- read-only battery ---- */

static void Hex(char *out, const uint8_t *d, int len)
{
    static const char *h = "0123456789ABCDEF";
    for (int i = 0; i < len; i++) {
        out[2 * i] = h[d[i] >> 4];
        out[2 * i + 1] = h[d[i] & 0xF];
    }
    out[2 * len] = '\0';
}

int SeSmokeProbe(void)
{
    int fail = 0;
    uint8_t sn[9], buf[32];
    DS28S60_Info_t info;
    int32_t ret;

    Log("== SE probe (read-only) ==");

    /* ATECC608B: identify + comm verify WITHOUT binding (Atecc608bInit would
     * burn the OTP binding keys on a first-start unit) */
    ret = Atecc608bProbeInit();
    if (ret == SUCCESS_CODE) {
        ret = Atecc608bReadSerial(sn);
        if (ret == SUCCESS_CODE) {
            char hex[19];
            Hex(hex, sn, 9);
            Log("atecc608b: OK sn=%s", hex);
        } else {
            fail++;
            Log("atecc608b: FAIL serial rc=%d", (int)ret);
        }
        ret = Atecc608bGetRng(buf, 32);
        if (ret != ATCA_SUCCESS) {
            fail++;
            Log("atecc608b rng: FAIL rc=%d", (int)ret);
        } else {
            Log("atecc608b rng: OK");
        }
    } else {
        fail++;
        Log("atecc608b: FAIL comm rc=%d", (int)ret);
    }

    /* DS28S60: identify via ROM option page WITHOUT binding (DS28S60_Init
     * would burn the OTP binding keys on a first-start unit) */
    DS28S60_Open();
    ret = DS28S60ProbeInfo(&info);
    if (ret == SUCCESS_CODE) {
        char hex[17];
        Hex(hex, info.ROMID, 8);
        Log("ds28s60: OK romid=%s man=%02X%02X", hex, info.MANID[0], info.MANID[1]);
    } else {
        fail++;
        Log("ds28s60: FAIL comm rc=%d", (int)ret);
    }
    ret = DS28S60_GetRng(buf, 32);
    if (ret != SUCCESS_CODE) {
        fail++;
        Log("ds28s60 rng: FAIL rc=%d", (int)ret);
    } else {
        Log("ds28s60 rng: OK");
    }

    /* OTP provisioning status (read-only) */
    Log("otp salt: %s", OtpAreaProvisioned(OTP_ADDR_SALT, 32) ? "provisioned" : "BLANK");
    Log("otp aes piece: %s", OtpAreaProvisioned(OTP_ADDR_AES_KEY, 32) ? "provisioned" : "BLANK");
    Log("otp atecc keys: %s", OtpAreaProvisioned(OTP_ADDR_ATECC608B, 96) ? "provisioned" : "BLANK");
    Log("otp ds28s60 keys: %s", OtpAreaProvisioned(OTP_ADDR_DS28S60, 96) ? "provisioned" : "BLANK");

    CLEAR_ARRAY(buf);
    Log("probe done: %d failures", fail);
    return fail;
}

int SeSmokeKdfChecks(const char *password)
{
    int fail = 0;
    uint8_t pieceA[KEY_PIECE_LEN], pieceB[KEY_PIECE_LEN], tmp[KEY_PIECE_LEN * 2];
    int32_t ret;

    Log("== SE kdf checks (read-only) ==");

    /* Nothing here may run before the salt exists: HashWithSalt lazily BURNS
     * the OTP salt on first use, which is a write path. */
    if (!OtpAreaProvisioned(OTP_ADDR_SALT, 32)) {
        Log("kdf: SKIP (otp salt blank - run 'se provision' first)");
        return 0;
    }

    /* wrong-password piece comparison: two different passwords must derive
     * two different DS28S60 pieces (that half has no auth gate - 1:1) */
    if (GetKeyPieceFromDs28s60(0, pieceA, SE_WRONG_PWD) != SUCCESS_CODE ||
        GetKeyPieceFromDs28s60(0, pieceB, "shlosilo-se-other-pwd") != SUCCESS_CODE) {
        fail++;
        Log("ds piece derive: FAIL");
    } else if (memcmp(pieceA, pieceB, KEY_PIECE_LEN) != 0) {
        Log("ds wrong-piece differs: PASS");
    } else {
        fail++;
        Log("ds wrong-piece differs: FAIL (collision!)");
    }

    /* GetKeyPiece failure normalization: a wrong password must surface as
     * ERR_KEYSTORE_AUTH (folded from ATCA_CHECKMAC_VERIFY_FAILED) */
    ret = GetKeyPieceFromSE(0, tmp, SE_WRONG_PWD);
    if (ret == ERR_KEYSTORE_AUTH) {
        Log("kdf auth gate: PASS (rc=%d)", (int)ret);
    } else {
        fail++;
        Log("kdf auth gate: FAIL rc=%d (want %d)", (int)ret, (int)ERR_KEYSTORE_AUTH);
    }

    /* optional leg: the operator's own password must actually unlock */
    if (password != NULL && password[0] != '\0') {
        ret = GetKeyPieceFromSE(0, tmp, password);
        if (ret == SUCCESS_CODE) {
            Log("kdf right-pwd get: PASS");
        } else {
            fail++;
            Log("kdf right-pwd get: FAIL rc=%d (slots set with this pwd?)", (int)ret);
        }
    }

    CLEAR_ARRAY(pieceA);
    CLEAR_ARRAY(pieceB);
    CLEAR_ARRAY(tmp);
    Log("kdf done: %d failures", fail);
    return fail;
}

/* ---- gated write flows (explicit trigger only!) ----
 * noinline: these are the irreversible-write paths and the arm state
 * machine - they must stay identifiable symbols in the image (nm/audit +
 * crash forensics), not folded into SeConsolePoll by LTO. */
static void __attribute__((noinline)) RunProvision(void)
{
    Log("!! EXECUTING PERMANENT OTP WRITES !!");
    if (!OtpAreaProvisioned(OTP_ADDR_SALT, 32)) {
        OtpBurn(OTP_ADDR_SALT, "otp salt", 32);
    } else {
        Log("otp salt: already provisioned (skip)");
    }
    if (!OtpAreaProvisioned(OTP_ADDR_AES_KEY, 32)) {
        OtpBurn(OTP_ADDR_AES_KEY, "otp aes piece", 32);
    } else {
        Log("otp aes piece: already provisioned (skip)");
    }
    /* First-start chip binding: burns OTP_ADDR_ATECC608B / OTP_ADDR_DS28S60
     * and configures/locks the chips (drv Atecc608bInit / DS28S60_Init).
     * Both ASSERT on failure (keystone3 behaviour - loud). */
    Atecc608bInit();
    Log("atecc608b binding: done");
    DS28S60_Init();
    Log("ds28s60 binding: done");
    Log("provision complete - now: se slots CONFIRM <password>");
}

static void __attribute__((noinline)) RunSlots(const char *password)
{
    int fail = 0;

    Log("!! EXECUTING SE WRITES (3 accounts) !!");
    for (uint8_t a = 0; a < 3; a++) {
        uint8_t pieces[KEY_PIECE_LEN * 2], check[KEY_PIECE_LEN * 2];
        int32_t ret = SetNewKeyPieceToSE(a, pieces, password);
        if (ret != SUCCESS_CODE) {
            fail++;
            Log("slot %u write: FAIL rc=%d", (unsigned)a, (int)ret);
        } else {
            ret = GetKeyPieceFromSE(a, check, password);
            if (ret == SUCCESS_CODE && memcmp(pieces, check, sizeof(pieces)) == 0) {
                Log("slot %u write/readback: PASS", (unsigned)a);
            } else {
                fail++;
                Log("slot %u readback: FAIL rc=%d", (unsigned)a, (int)ret);
            }
        }
        CLEAR_ARRAY(pieces);
        CLEAR_ARRAY(check);
    }
    Log("slots done: %d failures - see 'se kdf' for the read-only checks", fail);
}

/* ---- Task 8: SE unlock / lock (password -> signing session) ---- */

/* product_task.c owns the g_key_session sign route - PRODUCT flavor only.
 * Weak references so the smoke flavor (no product_task.c) still links: the
 * console reports the route as not wired there instead of failing the link. */
extern int ProductKeySeUnlock(const char *password) __attribute__((weak));
extern void ProductKeyLock(void) __attribute__((weak));

/* 'se unlock <password>': READ-ONLY (no write path, no burn) - it self-runs
 * without the arm gate. The safety story here is disclosure, not an arm: the
 * password just transited the serial console in CLEARTEXT, so say so LOUDLY
 * every single time. DEV CONVENIENCE ONLY - the product entry is the P4 UI. */
static void __attribute__((noinline)) RunUnlock(const char *password)
{
    int rc;

    Log("WARNING: the password was just sent over the serial console");
    Log("WARNING: cleartext on UART0 = DEV CONVENIENCE ONLY");
    Log("WARNING: the product entry is the P4 UI (not this console)");
    if (ProductKeySeUnlock == NULL) {
        Log("unlock: key route not wired in this flavor");
        return;
    }
    if (password == NULL || password[0] == '\0') {
        Log("usage: se unlock <password>");
        return;
    }
    rc = ProductKeySeUnlock(password);
    if (rc == 0) {
        Log("unlock: key session live (sign route)");
    } else if (rc == -23) {
        Log("unlock: refused, session already live ('se lock' first)");
    } else if (rc == -24) {
        Log("unlock: AUTH FAILED (wrong password?) - one shot, not retried");
    } else {
        Log("unlock: FAIL rc=%d", rc);
    }
}

/* 'se lock': close (zeroize) the live key session (QR or SE - one shared
 * teardown). Read-only, idempotent. */
static void __attribute__((noinline)) RunLock(void)
{
    if (ProductKeyLock == NULL) {
        Log("lock: key route not wired in this flavor");
        return;
    }
    ProductKeyLock();
    Log("lock: key session closed (zeroized)");
}

/* ---- UART0 command console ---- */

static void PrintWarning(const char *cmd, const char *confirm, const char *what)
{
    Log("WARNING: %s", what);
    Log("WARNING: OTP BURN IS PERMANENT");
    Log("this cannot be undone or re-flashed");
    Log("to proceed type: %s", confirm);
    Log("(any other command aborts; 60s window)");
    (void)cmd;
}

static void __attribute__((noinline)) Dispatch(char *line)
{
    char *argv[4];
    int argc = 0;
    char *p = line;

    while (argc < 4 && *p != '\0') {
        while (*p == ' ') {
            *p++ = '\0';
        }
        if (*p == '\0') {
            break;
        }
        argv[argc++] = p;
        while (*p != '\0' && *p != ' ') {
            p++;
        }
        if (*p == ' ') {
            /* terminate EVERY token at its trailing space (the skip loop
             * covers non-final tokens; this covers the last one, so a
             * 4-token argv[3] is a single-word password like argv[2]) */
            *p = '\0';
        }
    }

    if (argc == 0) {
        /* "any other command aborts" covers whitespace-only lines too */
        g_armed = SE_ARM_NONE;
        return;
    }

    /* the CONFIRM forms are the only commands that may consume an arm */
    if (argc >= 2 && strcmp(argv[0], "se") == 0 && strcmp(argv[1], "provision") == 0 &&
        argc == 3 && strcmp(argv[2], "CONFIRM") == 0 && g_armed == SE_ARM_PROVISION) {
        if ((osKernelGetTickCount() - g_armTick) > SE_ARM_WINDOW_MS) {
            g_armed = SE_ARM_NONE;
            Log("provision: window expired, aborted (nothing written)");
            return;
        }
        g_armed = SE_ARM_NONE;
        RunProvision();
        return;
    }
    if (argc >= 2 && strcmp(argv[0], "se") == 0 && strcmp(argv[1], "slots") == 0 &&
        argc == 4 && strcmp(argv[2], "CONFIRM") == 0 && g_armed == SE_ARM_SLOTS) {
        if ((osKernelGetTickCount() - g_armTick) > SE_ARM_WINDOW_MS) {
            g_armed = SE_ARM_NONE;
            Log("slots: window expired, aborted (nothing written)");
            return;
        }
        g_armed = SE_ARM_NONE;
        RunSlots(argv[3]);
        return;
    }

    /* P2 fix (fail-closed): the arm warning promises "any other command
     * aborts". Only the matching CONFIRM forms above may consume an arm;
     * everything else cancels it first. A CONFIRM aimed at the wrong
     * flow/state (or missing its password) must also cancel - and must never
     * fall through into the arm commands below, which would re-arm off a
     * CONFIRM. */
    if (argc >= 3 && strcmp(argv[2], "CONFIRM") == 0) {
        if (g_armed != SE_ARM_NONE) {
            Log("arm aborted: CONFIRM does not match the armed flow");
        } else {
            Log("confirm ignored: nothing armed");
        }
        g_armed = SE_ARM_NONE;
        return;
    }
    if (g_armed != SE_ARM_NONE) {
        Log("arm aborted (any non-CONFIRM command cancels; nothing written)");
        g_armed = SE_ARM_NONE;
    }

    if (argc >= 2 && strcmp(argv[0], "se") == 0) {
        if (strcmp(argv[1], "probe") == 0) {
            (void)SeSmokeProbe();
        } else if (strcmp(argv[1], "kdf") == 0) {
            (void)SeSmokeKdfChecks(argc >= 3 ? argv[2] : NULL);
        } else if (strcmp(argv[1], "provision") == 0) {
            g_armed = SE_ARM_PROVISION;
            g_armTick = osKernelGetTickCount();
            PrintWarning("se provision", "se provision CONFIRM",
                         "one-time device provisioning (OTP + SE binding)");
        } else if (strcmp(argv[1], "slots") == 0) {
            g_armed = SE_ARM_SLOTS;
            g_armTick = osKernelGetTickCount();
            PrintWarning("se slots", "se slots CONFIRM <password>",
                         "SE write: overwrites the 3 account key pieces");
        } else if (strcmp(argv[1], "unlock") == 0) {
            /* READ-ONLY, self-running - no arm gate (it writes nothing).
             * RunUnlock prints the password-over-UART warning EVERY time. */
            RunUnlock(argc >= 3 ? argv[2] : NULL);
        } else if (strcmp(argv[1], "lock") == 0) {
            /* READ-ONLY, idempotent: the shared zeroizing teardown. */
            RunLock();
        } else if (strcmp(argv[1], "help") == 0) {
            Log("se probe | se kdf <pwd> | se provision | se slots");
            Log("se unlock <pwd> | se lock");
        } else {
            Log("unknown: %s (try 'se help')", argv[1]);
        }
        return;
    }
    Log("unknown command (try 'se help')");
}

void SeConsolePoll(void)
{
    char line[128];
    uint32_t n;

    if (!g_testCmdReady) {
        return;
    }
    /* Copy FIRST, release the ISR last: while g_testCmdReady stays set the
     * ISR drops incoming bytes, so the buffer is stable through the copy
     * and no freshly published line can be wiped by the stale-line clear. */
    n = strlen((const char *)g_testCmdRcvBuffer);
    if (n >= sizeof(line)) {
        n = sizeof(line) - 1;
    }
    memcpy(line, g_testCmdRcvBuffer, n);
    line[n] = '\0';
    /* Password hygiene (gap 3): the console line can carry a password
     * ('se unlock <password>' / 'se kdf <pwd>'), so the shared buffer is
     * volatile-wiped in FULL - the stale tail of an earlier, longer command
     * can still hold an older password, so clearing byte 0 (the old
     * behaviour) was not enough. Runs while g_testCmdReady is still set: the
     * ISR keeps dropping bytes and cannot race the wipe. */
    WipeVolatile(g_testCmdRcvBuffer, TEST_CMD_MAX_LENGTH);
    g_testCmdReady = 0;
    Dispatch(line);
    /* ... and the stack copy dies here too: the WHOLE line buffer, not just
     * the used bytes (argv tokens point into `line`; Dispatch has consumed
     * them all by now). */
    WipeVolatile(line, sizeof(line));
}
