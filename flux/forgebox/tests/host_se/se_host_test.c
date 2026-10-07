#include "se_manager.h"
#include "err_code.h"
#include "string.h"
#include "stdio.h"
#include "sha256.h"
#include "hmac.h"
#include "drv_atecc608b.h"
#include "se_shims.h"
#include "golden_se_vectors.h"
#include "atca_status.h"

/*
 * Host test for the SE communication plane (Task 7). Builds the PRODUCTION
 * se_manager.c against the behavioural driver shims (se_shims.c) and pins
 * everything that does not need real silicon:
 *
 *   1. slot/page map    - GetAccountSlot + the SLOT_* constants (keystone3
 *                         drv_atecc608b.h values, verbatim)
 *   2. state machine    - exact driver-call sequence of SetNewKeyPieceToSE /
 *                         GetKeyPieceFromSE (order, slots, blocks, pages)
 *   3. KDF composition  - piece bytes against the independent Python oracle
 *                         (oracle_se.py), including the rollKdf roll
 *   4. auth failure     - wrong password => ERR_KEYSTORE_AUTH, folded from
 *                         ATCA_CHECKMAC_VERIFY_FAILED by NormalizeAteccAuthError
 *   5. error mapping    - driver failures per family (ATECC => ERR_GENERAL_FAIL
 *                         except the auth passthrough; DS28S60 => verbatim
 *                         ERR_DS28S60_*)
 *   6. wrong piece      - the DS28S60 half derives a DIFFERENT piece for a
 *                         wrong password (1:1: that half has no auth gate)
 *   7. account map      - accounts 0/1/2 hit slots (3,4,5)/(6,7,9)/(10,11,12)
 *                         and pages 7/19/31
 *
 * Real chip timing/protocol is device-only - see
 * flux/forgebox/docs/se-keystore-checklist.md.
 */

static int g_failures;
static int g_checks;

static void Check(int cond, const char *name)
{
    g_checks++;
    if (!cond) {
        g_failures++;
        printf("FAIL: %s\n", name);
    }
}

static void CheckMem(const void *got, const void *want, size_t len, const char *name)
{
    g_checks++;
    if (memcmp(got, want, len) != 0) {
        g_failures++;
        printf("FAIL: %s\n", name);
    }
}

static void CheckLog(int i, SeLogEvent_t ev, uint8_t a, uint8_t b, const char *name)
{
    SeLogEntry_t e = SeShimLogAt(i);
    g_checks++;
    if (e.event != ev || e.a != a || e.b != b) {
        g_failures++;
        printf("FAIL: %s (log[%d]=%d,%u,%u want %d,%u,%u)\n", name, i,
               (int)e.event, e.a, e.b, (int)ev, a, b);
    }
}

/* ---- 1. slot/page map pins (keystone3 drv_atecc608b.h / se_manager.h) ---- */
_Static_assert(SLOT_AUTH_KEY_1 == 3 && SLOT_ROLL_KDF_KEY_1 == 4 && SLOT_HOST_KDF_KEY_1 == 5, "keystone3 drv_atecc608b.h");
_Static_assert(SLOT_AUTH_KEY_2 == 6 && SLOT_ROLL_KDF_KEY_2 == 7 && SLOT_HOST_KDF_KEY_2 == 9, "keystone3 drv_atecc608b.h");
_Static_assert(SLOT_AUTH_KEY_3 == 10 && SLOT_ROLL_KDF_KEY_3 == 11 && SLOT_HOST_KDF_KEY_3 == 12, "keystone3 drv_atecc608b.h");
_Static_assert(PAGE_INDEX_KEY_PIECE == 7, "keystone3 se_manager.h");
_Static_assert(KEY_PIECE_LEN == 32, "keystone3 se_manager.h");

static void TestAccountSlotMap(void)
{
    AccountSlot_t s;

    GetAccountSlot(&s, 0);
    Check(s.auth == 3 && s.rollKdf == 4 && s.hostKdf == 5, "slot map account 0");
    GetAccountSlot(&s, 1);
    Check(s.auth == 6 && s.rollKdf == 7 && s.hostKdf == 9, "slot map account 1");
    GetAccountSlot(&s, 2);
    Check(s.auth == 10 && s.rollKdf == 11 && s.hostKdf == 12, "slot map account 2");
}

/* ---- 2/3. Set state machine + piece composition vs oracle ---- */
static void TestSetFlow(void)
{
    uint8_t pieces[KEY_PIECE_LEN * 2];
    int32_t ret;

    SeShimsReset();
    SeShimsSeedSalt(GV_SE_SALT);
    SeShimLogClear();

    ret = SetNewKeyPieceToSE(1, pieces, GV_SE_PASSWORD);
    Check(ret == SUCCESS_CODE, "SetNewKeyPieceToSE ret 0");

    /* exact call sequence: keystone3 se_manager.c:30-90 */
    Check(SeShimLogCount() == 8, "Set log length 8");
    CheckLog(0, SE_LOG_ATECC_ENCRYPT_WRITE, 6, 0, "set: write auth slot");
    CheckLog(1, SE_LOG_ATECC_DERIVE_KEY, 7, 0, "set: roll deriveKey");
    CheckLog(2, SE_LOG_TRNG_GET, 32, 0, "set: trng hostRandom");
    CheckLog(3, SE_LOG_ATECC_ENCRYPT_WRITE, 9, 0, "set: write hostKdf slot");
    CheckLog(4, SE_LOG_ATECC_KDF, 7, 32, "set: kdf rollKdf");
    CheckLog(5, SE_LOG_ATECC_KDF, 9, 32, "set: kdf hostKdf");
    CheckLog(6, SE_LOG_TRNG_GET, 32, 0, "set: trng ds28s60 randomKey");
    CheckLog(7, SE_LOG_DS_WRITE, 1 * 12 + 7, 0, "set: ds key-piece page");

    CheckMem(pieces, GV_SE_PIECE0_SET, 32, "set: atecc piece vs oracle");
    CheckMem(pieces + 32, GV_SE_PIECE1_SET, 32, "set: ds piece (randomKey) vs oracle");
    CheckMem(SeShimPage(1 * 12 + 7), GV_SE_DS_PAGE1, 32, "set: ds page xData vs oracle");
    /* rollKdf slot was rolled by DeriveKey - it must NOT still hold the
     * blank key (the Get flow's golden depends on the rolled value). */
    Check(SeShimSlot(7)[0] != 0 || SeShimSlot(7)[31] != 0, "set: rollKdf slot rolled");
}

/* ---- 2/3. Get round-trip (rolled state) + no-write/no-trng pins ---- */
static void TestGetRoundTrip(void)
{
    uint8_t pieces[KEY_PIECE_LEN * 2], setPieces[KEY_PIECE_LEN * 2];

    /* fresh Set so this test owns its chip state */
    SeShimsReset();
    SeShimsSeedSalt(GV_SE_SALT);
    (void)SetNewKeyPieceToSE(1, setPieces, GV_SE_PASSWORD);
    SeShimLogClear();

    Check(GetKeyPieceFromSE(1, pieces, GV_SE_PASSWORD) == SUCCESS_CODE,
          "GetKeyPieceFromSE ret 0");
    Check(SeShimLogCount() == 3, "Get log length 3 (no writes, no trng)");
    CheckLog(0, SE_LOG_ATECC_KDF, 7, 32, "get: kdf rollKdf");
    CheckLog(1, SE_LOG_ATECC_KDF, 9, 32, "get: kdf hostKdf");
    CheckLog(2, SE_LOG_DS_READ, 1 * 12 + 7, 0, "get: ds key-piece page");

    CheckMem(pieces, GV_SE_PIECE0_GET, 32, "get: atecc piece (rolled) vs oracle");
    CheckMem(pieces + 32, setPieces + 32, 32, "get: ds piece == set randomKey");
    /* the assembled 64-byte piece must round-trip the Set output exactly */
    CheckMem(pieces + 32, GV_SE_PIECE1_SET, 32, "get: ds piece vs oracle");
}

/* ---- 4/5/6. auth failure + error mapping + wrong-piece comparison ---- */
static void TestAuthAndErrors(void)
{
    uint8_t piece[KEY_PIECE_LEN * 2], pieceWrong[KEY_PIECE_LEN * 2];
    int32_t ret;

    SeShimsReset();
    SeShimsSeedSalt(GV_SE_SALT);
    (void)SetNewKeyPieceToSE(1, piece, GV_SE_PASSWORD);
    SeShimLogClear();

    /* wrong password: the ATECC KDF auth gate fails -> ERR_KEYSTORE_AUTH,
     * and the flow must abort before touching the DS28S60 */
    ret = GetKeyPieceFromSE(1, pieceWrong, GV_SE_PASSWORD_WRONG);
    Check(ret == ERR_KEYSTORE_AUTH, "wrong password => ERR_KEYSTORE_AUTH");
    Check(SeShimLogCount() == 1, "wrong password: aborted after 1 call");
    CheckLog(0, SE_LOG_ATECC_KDF, 7, 32, "wrong password: failed at rollKdf kdf");

    /* the DS28S60 half has no gate: a wrong password derives a DIFFERENT
     * piece (1:1 keystone3) - the keystore HMAC gate rejects it downstream */
    {
        uint8_t right[KEY_PIECE_LEN], wrong[KEY_PIECE_LEN];
        Check(GetKeyPieceFromDs28s60(1, right, GV_SE_PASSWORD) == SUCCESS_CODE,
              "ds piece right password");
        Check(GetKeyPieceFromDs28s60(1, wrong, GV_SE_PASSWORD_WRONG) == SUCCESS_CODE,
              "ds piece wrong password (no gate)");
        CheckMem(wrong, GV_SE_PIECE1_GET_WRONG, 32, "ds wrong piece vs oracle");
        Check(memcmp(wrong, right, 32) != 0, "ds wrong piece != right piece");
    }

    /* fault injection: raw ATCA_CHECKMAC_VERIFY_FAILED folds to
     * ERR_KEYSTORE_AUTH, any other ATECC failure to ERR_GENERAL_FAIL */
    SeShimFailAteccKdf(ATCA_CHECKMAC_VERIFY_FAILED);
    ret = GetKeyPieceFromAtecc608b(1, pieceWrong, GV_SE_PASSWORD);
    Check(ret == ERR_KEYSTORE_AUTH, "ATECC checkmac fail => ERR_KEYSTORE_AUTH");
    SeShimFailAteccKdf(ATCA_GEN_FAIL);
    ret = GetKeyPieceFromAtecc608b(1, pieceWrong, GV_SE_PASSWORD);
    Check(ret == ERR_GENERAL_FAIL, "ATECC generic fail => ERR_GENERAL_FAIL");
    SeShimFailAteccKdf(0);
    SeShimFailAteccEncryptWrite(ATCA_GEN_FAIL);
    ret = SetNewKeyPieceToAtecc608b(1, pieceWrong, GV_SE_PASSWORD);
    Check(ret == ERR_GENERAL_FAIL, "ATECC write fail => ERR_GENERAL_FAIL");
    SeShimFailAteccEncryptWrite(0);

    /* DS28S60 family passes its own Error_Code through verbatim */
    SeShimFailDsWrite(ERR_DS28S60_OVERTIME);
    ret = SetNewKeyPieceToDs28s60(1, pieceWrong, GV_SE_PASSWORD);
    Check(ret == ERR_DS28S60_OVERTIME, "DS write fail passthrough");
    SeShimFailDsWrite(0);
    SeShimFailDsRead(ERR_DS28S60_AUTH);
    ret = GetKeyPieceFromDs28s60(1, pieceWrong, GV_SE_PASSWORD);
    Check(ret == ERR_DS28S60_AUTH, "DS read fail passthrough");
    SeShimFailDsRead(0);

    /* re-provision with a new password: the old password must now fail auth
     * (the group auth slot was overwritten) */
    {
        uint8_t piece2[KEY_PIECE_LEN * 2];
        Check(SetNewKeyPieceToSE(1, piece2, GV_SE_PASSWORD_WRONG) == SUCCESS_CODE,
              "re-provision ret 0");
        Check(GetKeyPieceFromSE(1, piece2, GV_SE_PASSWORD) == ERR_KEYSTORE_AUTH,
              "old password after re-provision => ERR_KEYSTORE_AUTH");
        Check(GetKeyPieceFromSE(1, piece2, GV_SE_PASSWORD_WRONG) == SUCCESS_CODE,
              "new password after re-provision ok");
    }
}

/* ---- 7. per-account slot/page routing ---- */
static void TestAccountRouting(void)
{
    static const uint8_t expSlot[3][3] = {{3, 4, 5}, {6, 7, 9}, {10, 11, 12}};
    uint8_t pieces[KEY_PIECE_LEN * 2];

    SeShimsReset();
    SeShimsSeedSalt(GV_SE_SALT);
    for (int a = 0; a < 3; a++) {
        SeShimLogClear();
        Check(SetNewKeyPieceToSE((uint8_t)a, pieces, GV_SE_PASSWORD) == SUCCESS_CODE,
              "routing: set ret 0");
        CheckLog(0, SE_LOG_ATECC_ENCRYPT_WRITE, expSlot[a][0], 0, "routing: auth slot");
        CheckLog(1, SE_LOG_ATECC_DERIVE_KEY, expSlot[a][1], 0, "routing: rollKdf slot");
        CheckLog(3, SE_LOG_ATECC_ENCRYPT_WRITE, expSlot[a][2], 0, "routing: hostKdf slot");
        CheckLog(7, SE_LOG_DS_WRITE, (uint8_t)(a * 12 + 7), 0, "routing: key-piece page");
    }
}

/* ---- SE_* wrapper surface: RNG passthroughs + page IO mapping ---- */
static void TestSeInterfaceWrappers(void)
{
    uint8_t buf[40], data[32];

    SeShimsReset();
    memset(data, 0xA5, sizeof(data));
    Check(SE_HmacEncryptWrite(data, 88) == SUCCESS_CODE, "SE_HmacEncryptWrite ok");
    memset(buf, 0, sizeof(buf));
    Check(SE_HmacEncryptRead(buf, 88) == SUCCESS_CODE, "SE_HmacEncryptRead ok");
    CheckMem(buf, data, 32, "SE page round-trip");

    Check(SE_GetAtecc608bRng(buf, 40) == SUCCESS_CODE, "SE_GetAtecc608bRng ok");
    Check(SE_GetDS28S60Rng(buf, 40) == SUCCESS_CODE, "SE_GetDS28S60Rng ok");
    SE_GetTRng(buf, 40);
    Check(SeShimLogCount() == 5, "wrapper calls logged (write/read/atecc-rng/ds-rng/trng)");

    SeShimFailDsRead(ERR_DS28S60_UNEXPECTLEN);
    Check(SE_HmacEncryptRead(buf, 88) == ERR_DS28S60_UNEXPECTLEN,
          "SE_HmacEncryptRead fail passthrough");
    SeShimFailDsRead(0);
}

int main(void)
{
    printf("=== SE communication-plane host test (Task 7) ===\n");
    TestAccountSlotMap();
    TestSetFlow();
    TestGetRoundTrip();
    TestAuthAndErrors();
    TestAccountRouting();
    TestSeInterfaceWrappers();

    printf("%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
