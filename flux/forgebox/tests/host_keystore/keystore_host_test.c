#include "keystore.h"
#include "se_manager.h"
#include "string.h"
#include "stdio.h"
#include "stddef.h"
#include "sha256.h"
#include "sha512.h"
#include "hmac.h"
#include "hash_and_salt.h"
#include "ctaes.h"
#include "host_shims.h"
#include "golden_vectors.h"

/*
 * Host test for the keystore data plane (Task 6). Runs the PRODUCTION
 * keystore.c / hash_and_salt.c / ctaes objects against the in-memory SE/OTP
 * sim (host_shims.c) and pins them to the independent Python/OpenSSL oracle
 * (oracle_golden.py -> golden_vectors.h).
 *
 * Coverage:
 *   1. layout pins   - block accounting / offsets / HMAC domain (static)
 *   2. primitive KATs - SHA-256/512 "abc", RFC4231 HMAC-SHA-256, HashWithSalt
 *   3. pipeline KAT  - SaveAccountSecret pages byte-exact vs oracle
 *   4. round-trip    - Save -> Load returns the original secret
 *   5. auth failure  - wrong password / tampered ciphertext => ERR_KEYSTORE_AUTH
 *   6. account flag  - AccountExists via IV page entropy
 *   7. OTP third factor - inner AES piece generated + burned on first use
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

/* ---- 1. layout pins (keystone3 keystore.h:13-27, verbatim accounting) ---- */
_Static_assert(AES_BLOCK_SIZE == 16, "keystone3 keystore.h:11");
_Static_assert(AES_KEY_LEN == 32 && AUTH_KEY_LEN == 32, "keystone3 keystore.h:15-16");
_Static_assert(AES_IV_LEN == 32, "keystone3 keystore.h:18 (16B used, 16B reserved)");
_Static_assert(ENTROPY_MAX_LEN == 32 && SEED_LEN == 64, "keystone3 keystore.h:19-22");
_Static_assert(SLIP39_EMS_LEN == 32 && SE_DATA_RESERVED_LEN == 32, "keystone3 keystore.h:23-24");
_Static_assert(HMAC_LEN == 32, "keystone3 keystore.h:25");
_Static_assert(ACCOUNT_TOTAL_LEN == 224, "keystone3 keystore.h:26");
_Static_assert(ACCOUNT_TOTAL_LEN - HMAC_LEN == 192, "HMAC domain length");
_Static_assert(ENTROPY_MAX_LEN % AES_BLOCK_SIZE == 0, "entropy is block aligned");
_Static_assert(SEED_LEN % AES_BLOCK_SIZE == 0, "seed is block aligned");
_Static_assert(SLIP39_EMS_LEN % AES_BLOCK_SIZE == 0, "ems is block aligned");
_Static_assert(SE_DATA_RESERVED_LEN % AES_BLOCK_SIZE == 0, "reserved is block aligned");
_Static_assert(offsetof(AccountSecret_t, entropy) == 0, "AccountSecret_t layout");
_Static_assert(offsetof(AccountSecret_t, seed) == 32, "AccountSecret_t layout");
_Static_assert(offsetof(AccountSecret_t, slip39EmsOrTonEntropyL32) == 96, "AccountSecret_t layout");
_Static_assert(offsetof(AccountSecret_t, reservedData) == 128, "AccountSecret_t layout");
_Static_assert(offsetof(AccountSecret_t, entropyLen) == 160, "AccountSecret_t layout");
/* page map (keystone3 se_manager.h:10-23) */
_Static_assert(PAGE_NUM_PER_ACCOUNT == 12, "page map");
_Static_assert(PAGE_INDEX_IV == 0 && PAGE_INDEX_ENTROPY_OR_TON_ENTROPY_H32 == 1, "page map");
_Static_assert(PAGE_INDEX_SEED_H32 == 2 && PAGE_INDEX_SEED_L32 == 3, "page map");
_Static_assert(PAGE_INDEX_SLIP39_EMS_OR_TON_ENTROPY_L32 == 4, "page map");
_Static_assert(PAGE_INDEX_RESERVED == 5 && PAGE_INDEX_HMAC == 6, "page map");
_Static_assert(PAGE_INDEX_KEY_PIECE == 7 && PAGE_INDEX_PARAM == 9, "page map");

static void FillSecret(AccountSecret_t *s)
{
    memset(s, 0, sizeof(*s));
    for (int i = 0; i < ENTROPY_MAX_LEN; i++) {
        s->entropy[i] = (uint8_t)((0xE0 + i) & 0xFF);
    }
    for (int i = 0; i < SEED_LEN; i++) {
        s->seed[i] = (uint8_t)i;
    }
    for (int i = 0; i < SLIP39_EMS_LEN; i++) {
        s->slip39EmsOrTonEntropyL32[i] = (uint8_t)((0x70 + i) & 0xFF);
    }
    for (int i = 0; i < SE_DATA_RESERVED_LEN; i++) {
        s->reservedData[i] = (uint8_t)((0xA5 + i) & 0xFF);
    }
    s->entropyLen = 32;
}

/* ---- 2. primitive KATs ---- */
static void TestPrimitives(void)
{
    struct sha256 h256;
    struct sha512 h512;
    uint8_t out[64];
    uint8_t key20[20];
    AES256_CBC_ctx ctx;

    /* HashWithSalt pulls the OTP salt - seed the fake OTP first. */
    HostShimsReset();
    HostShimsSeedOtp(GV_SALT, GV_OTP_AES_PIECE);

    sha256(&h256, "abc", 3);
    CheckMem(h256.u.u8, GV_SHA256_ABC, 32, "sha256(\"abc\") FIPS 180-4");

    sha512(&h512, "abc", 3);
    CheckMem(h512.u.u8, GV_SHA512_ABC, 64, "sha512(\"abc\") FIPS 180-4");

    memset(key20, 0x0B, sizeof(key20));
    hmac_sha256(key20, sizeof(key20), (const unsigned char *)"Hi There", 8, out);
    CheckMem(out, GV_HMAC_RFC4231_1, 32, "hmac_sha256 RFC4231 case 1");

    /* HashWithSalt: HMAC(otp salt, in) then HMAC(salt string, .) - pins the
     * KDF chain of keystore.c "combine two pieces" (hash_and_salt.c:44-79). */
    HashWithSalt(out, GV_HASHWITHSALT_IN, sizeof(GV_HASHWITHSALT_IN), "combine two pieces");
    CheckMem(out, GV_HASHWITHSALT_OUT, 32, "HashWithSalt vs oracle");

    /* AES-256-CBC primitive (ctaes) against the OpenSSL oracle vector. */
    AES256_CBC_init(&ctx, GV_OTP_AES_PIECE, GV_SALT);
    AES256_CBC_encrypt(&ctx, 2, out, GV_HASHWITHSALT_IN);
    AES256_CBC_init(&ctx, GV_OTP_AES_PIECE, GV_SALT);
    AES256_CBC_decrypt(&ctx, 2, out + 32, out);
    CheckMem(out + 32, GV_HASHWITHSALT_IN, 32, "AES256_CBC encrypt/decrypt round-trip");
}

/* ---- 3. pipeline KAT: SaveAccountSecret pages byte-exact vs oracle ---- */
static void TestPipelineGolden(void)
{
    AccountSecret_t s;

    HostShimsReset();
    HostShimsSeedOtp(GV_SALT, GV_OTP_AES_PIECE);
    FillSecret(&s);
    Check(SaveAccountSecret(0, &s, (const char *)GV_PASSWORD, false) == SUCCESS_CODE,
          "SaveAccountSecret golden run");
    for (int i = 0; i < 7; i++) {
        char name[64];
        snprintf(name, sizeof(name), "SaveAccountSecret page %d vs oracle", i);
        CheckMem(HostSePage((uint8_t)i), GV_SAVE_PAGES[i], 32, name);
    }
}

/* ---- 4. round-trip ---- */
static void TestRoundTrip(void)
{
    AccountSecret_t s, loaded;

    HostShimsReset();
    HostShimsSeedOtp(GV_SALT, GV_OTP_AES_PIECE);
    FillSecret(&s);
    Check(SaveAccountSecret(1, &s, (const char *)GV_PASSWORD, false) == SUCCESS_CODE,
          "SaveAccountSecret round-trip run");
    /* keystore.c:660 branches on the PAGE_INDEX_PARAM entropyLen byte
     * (== 0 => default 32). SaveAccountSecret itself does not write that page
     * (keystone3 keeps "// param[0] = ..." commented out; the account manager
     * owns it), so emulate both page states here. */
    memset(HostSePage(1 * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_PARAM), 0, 32);
    memset(&loaded, 0, sizeof(loaded));
    Check(LoadAccountSecret(1, &loaded, (const char *)GV_PASSWORD) == SUCCESS_CODE,
          "LoadAccountSecret round-trip run");
    CheckMem(loaded.entropy, s.entropy, ENTROPY_MAX_LEN, "round-trip entropy");
    CheckMem(loaded.seed, s.seed, SEED_LEN, "round-trip seed");
    CheckMem(loaded.slip39EmsOrTonEntropyL32, s.slip39EmsOrTonEntropyL32, SLIP39_EMS_LEN,
             "round-trip slip39Ems/ton");
    CheckMem(loaded.reservedData, s.reservedData, SE_DATA_RESERVED_LEN, "round-trip reserved");
    Check(loaded.entropyLen == 32, "entropyLen default 32 (param byte 0)");

    /* PAGE_INDEX_PARAM carries entropyLen (keystore.c:660); set 16 like the
     * account manager would and re-load. */
    HostSePage(1 * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_PARAM)[0] = 16;
    Check(LoadAccountSecret(1, &loaded, (const char *)GV_PASSWORD) == SUCCESS_CODE,
          "LoadAccountSecret with param");
    Check(loaded.entropyLen == 16, "entropyLen from param page");
}

/* ---- 5. auth failure ---- */
static void TestAuthFailures(void)
{
    AccountSecret_t s, loaded;
    uint8_t saved;

    HostShimsReset();
    HostShimsSeedOtp(GV_SALT, GV_OTP_AES_PIECE);
    FillSecret(&s);
    Check(SaveAccountSecret(2, &s, (const char *)GV_PASSWORD, false) == SUCCESS_CODE,
          "SaveAccountSecret auth-fail run");

    Check(LoadAccountSecret(2, &loaded, "wrong password") == ERR_KEYSTORE_AUTH,
          "wrong password => ERR_KEYSTORE_AUTH");

    /* tamper with the ciphertext: HMAC covers pages 0..5 + iv, must trip */
    saved = HostSePage(2 * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_ENTROPY_OR_TON_ENTROPY_H32)[5];
    HostSePage(2 * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_ENTROPY_OR_TON_ENTROPY_H32)[5] ^= 0x01;
    Check(LoadAccountSecret(2, &loaded, (const char *)GV_PASSWORD) == ERR_KEYSTORE_AUTH,
          "tampered ciphertext => ERR_KEYSTORE_AUTH");
    HostSePage(2 * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_ENTROPY_OR_TON_ENTROPY_H32)[5] = saved;
    Check(LoadAccountSecret(2, &loaded, (const char *)GV_PASSWORD) == SUCCESS_CODE,
          "restored ciphertext loads again");
}

/* ---- 6. account flag ---- */
static void TestAccountExists(void)
{
    AccountSecret_t s;
    bool exists = true;

    HostShimsReset();
    HostShimsSeedOtp(GV_SALT, GV_OTP_AES_PIECE);
    Check(AccountExists(0, &exists) == SUCCESS_CODE && exists == false,
          "blank slot => account does not exist");
    FillSecret(&s);
    SaveAccountSecret(0, &s, (const char *)GV_PASSWORD, false);
    Check(AccountExists(0, &exists) == SUCCESS_CODE && exists == true,
          "written slot => account exists");
}

/* ---- 7. OTP third factor: generated + burned on first use ---- */
static void TestOtpInnerAesGeneration(void)
{
    AccountSecret_t s, loaded;

    HostShimsReset();
    HostShimsSeedOtp(GV_SALT, GV_OTP_AES_PIECE);
    HostShimsBlankOtpAesPiece();
    FillSecret(&s);
    Check(SaveAccountSecret(0, &s, (const char *)GV_PASSWORD, false) == SUCCESS_CODE,
          "SaveAccountSecret with blank inner AES piece");
    memset(&loaded, 0, sizeof(loaded));
    /* If CombineInnerAesKey had not burned the generated piece into OTP, the
     * load path would derive a different enKey and the plaintext would not
     * match. */
    Check(LoadAccountSecret(0, &loaded, (const char *)GV_PASSWORD) == SUCCESS_CODE,
          "LoadAccountSecret after piece generation");
    CheckMem(loaded.entropy, s.entropy, ENTROPY_MAX_LEN,
             "round-trip entropy across generated OTP piece");
}

int main(void)
{
    TestPrimitives();
    TestPipelineGolden();
    TestRoundTrip();
    TestAuthFailures();
    TestAccountExists();
    TestOtpInnerAesGeneration();

    printf("keystore host test: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
