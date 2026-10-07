#include "se_shims.h"
#include "string.h"
#include "stdio.h"
#include "stdlib.h"
#include "sys/mman.h"
#include "sha256.h"
#include "hmac.h"
#include "drv_atecc608b.h"
#include "drv_ds28s60.h"
#include "drv_otp.h"
#include "atca_status.h"

/*
 * Behavioural shims for drv_atecc608b / drv_ds28s60 / drv_trng + the OTP/MPU/
 * assert plumbing. Contract: see se_shims.h (mirrored by oracle_se.py).
 */

static uint8_t g_slots[SE_SHIM_SLOT_COUNT][SE_SHIM_PAGE_LEN];
static uint8_t g_pages[SE_SHIM_PAGE_COUNT][SE_SHIM_PAGE_LEN];
static uint32_t g_rngTrng, g_rngAtecc, g_rngDs;
static uint8_t *g_otpWindow;
static int32_t g_failAteccWrite, g_failAteccDerive, g_failAteccKdf;
static int32_t g_failDsWrite, g_failDsRead;
static SeLogEntry_t g_log[128];
static int g_logCount;

#define OTP_WINDOW_BASE     0x40009000UL
#define OTP_WINDOW_SIZE     0x1000U

static void OtpWindowInit(void)
{
    if (g_otpWindow != NULL) {
        return;
    }
    g_otpWindow = mmap((void *)OTP_WINDOW_BASE, OTP_WINDOW_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (g_otpWindow != (void *)OTP_WINDOW_BASE) {
        fprintf(stderr, "se_shims: mmap of fake OTP window failed\n");
        exit(1);
    }
}

static void Log(SeLogEvent_t event, uint8_t a, uint8_t b)
{
    if (g_logCount < (int)(sizeof(g_log) / sizeof(g_log[0]))) {
        g_log[g_logCount].event = event;
        g_log[g_logCount].a = a;
        g_log[g_logCount].b = b;
        g_logCount++;
    }
}

static void RngStream(uint8_t *out, uint32_t num, const char *label, uint32_t *counter)
{
    uint32_t done = 0;
    size_t labelLen = strlen(label);

    while (done < num) {
        uint8_t msg[32];
        struct sha256 h;
        uint32_t chunk = (num - done > 32) ? 32 : (num - done);

        memcpy(msg, label, labelLen);
        msg[labelLen + 0] = (uint8_t)(*counter);
        msg[labelLen + 1] = (uint8_t)(*counter >> 8);
        msg[labelLen + 2] = (uint8_t)(*counter >> 16);
        msg[labelLen + 3] = (uint8_t)(*counter >> 24);
        sha256(&h, msg, labelLen + 4);
        memcpy(out + done, h.u.u8, chunk);
        done += chunk;
        (*counter)++;
    }
}

void SeShimsReset(void)
{
    OtpWindowInit();
    memset(g_slots, 0x00, sizeof(g_slots));
    memset(g_pages, 0xFF, sizeof(g_pages));
    memset(g_otpWindow, 0xFF, OTP_WINDOW_SIZE);
    g_rngTrng = g_rngAtecc = g_rngDs = 0;
    g_failAteccWrite = g_failAteccDerive = g_failAteccKdf = 0;
    g_failDsWrite = g_failDsRead = 0;
    g_logCount = 0;
}

uint8_t *SeShimSlot(uint8_t slot)
{
    return g_slots[slot];
}

uint8_t *SeShimPage(uint8_t page)
{
    return g_pages[page];
}

int SeShimLogCount(void)
{
    return g_logCount;
}

SeLogEntry_t SeShimLogAt(int i)
{
    return g_log[i];
}

void SeShimLogClear(void)
{
    g_logCount = 0;
}

void SeShimFailAteccEncryptWrite(int32_t code) { g_failAteccWrite = code; }
void SeShimFailAteccDeriveKey(int32_t code)    { g_failAteccDerive = code; }
void SeShimFailAteccKdf(int32_t code)          { g_failAteccKdf = code; }
void SeShimFailDsWrite(int32_t code)           { g_failDsWrite = code; }
void SeShimFailDsRead(int32_t code)            { g_failDsRead = code; }

/* ---- OTP / MPU / assert plumbing (for hash_and_salt.c) ---- */

void OTP_PowerOn(void)
{
}

void MpuSetOtpProtection(bool noAccess)
{
    (void)noAccess;
}

int32_t WriteOtpData(uint32_t addr, const uint8_t *data, uint32_t len)
{
    OtpWindowInit();
    if (addr < OTP_WINDOW_BASE || addr + len > OTP_WINDOW_BASE + OTP_WINDOW_SIZE) {
        return -1;
    }
    memcpy(g_otpWindow + (addr - OTP_WINDOW_BASE), data, len);
    return 0;
}

void ShowAssert(const char *file, uint32_t line)
{
    fprintf(stderr, "se_shims: ASSERT failed at %s:%u\n", file, line);
    exit(1);
}

/* Seed the fake OTP salt (32B) so HashWithSalt never triggers the lazy
 * generate-and-burn path. */
void SeShimsSeedSalt(const uint8_t *salt)
{
    OtpWindowInit();
    memcpy(g_otpWindow + (OTP_ADDR_SALT - OTP_WINDOW_BASE), salt, 32);
}

/* ---- drv_trng.h ---- */

void TrngInit(void)
{
}

void TrngGet(void *buf, uint32_t len)
{
    Log(SE_LOG_TRNG_GET, (uint8_t)len, 0);
    RngStream((uint8_t *)buf, len, "shlosilo-host-sim-trng", &g_rngTrng);
}

/* ---- drv_atecc608b.h (behavioural model, see se_shims.h) ---- */

static uint8_t AteccAuthSlot(uint8_t keySlot)
{
    if (keySlot == 4 || keySlot == 5) {
        return 3;
    }
    if (keySlot == 7 || keySlot == 9) {
        return 6;
    }
    if (keySlot == 11 || keySlot == 12) {
        return 10;
    }
    return 255;
}

static int32_t AteccAuthorize(uint8_t keySlot, const uint8_t *authKey)
{
    uint8_t authSlot = AteccAuthSlot(keySlot);

    if (authSlot == 255) {
        return ERR_ATECC608B_SLOT_NUM_ERR;
    }
    return (memcmp(authKey, g_slots[authSlot], 32) == 0)
               ? ATCA_SUCCESS : ATCA_CHECKMAC_VERIFY_FAILED;
}

int32_t Atecc608bEncryptWrite(uint8_t slot, uint8_t block, const uint8_t *data)
{
    Log(SE_LOG_ATECC_ENCRYPT_WRITE, slot, block);
    if (g_failAteccWrite != 0) {
        return g_failAteccWrite;
    }
    memcpy(g_slots[slot], data, 32);
    return ATCA_SUCCESS;
}

int32_t Atecc608bDeriveKey(uint8_t slot, const uint8_t *authKey)
{
    static const char deriveLabel[] = "shlosilo-host-sim-derive"; /* 24 chars */
    uint8_t msg[sizeof(deriveLabel) - 1 + 32], out[32];
    int32_t ret;

    Log(SE_LOG_ATECC_DERIVE_KEY, slot, 0);
    if (g_failAteccDerive != 0) {
        return g_failAteccDerive;
    }
    ret = AteccAuthorize(slot, authKey);
    if (ret != ATCA_SUCCESS) {
        return ret;
    }
    memcpy(msg, deriveLabel, sizeof(deriveLabel) - 1);
    memcpy(msg + sizeof(deriveLabel) - 1, authKey, 32);
    hmac_sha256(g_slots[slot], 32, msg, sizeof(msg), out);
    memcpy(g_slots[slot], out, 32);
    return ATCA_SUCCESS;
}

int32_t Atecc608bKdf(uint8_t slot, const uint8_t *authKey, const uint8_t *inData, uint32_t inLen, uint8_t *outData)
{
    int32_t ret;

    Log(SE_LOG_ATECC_KDF, slot, (uint8_t)inLen);
    if (g_failAteccKdf != 0) {
        return g_failAteccKdf;
    }
    ret = AteccAuthorize(slot, authKey);
    if (ret != ATCA_SUCCESS) {
        return ret;
    }
    hmac_sha256(g_slots[slot], 32, inData, inLen, outData);
    return ATCA_SUCCESS;
}

int32_t Atecc608bGetRng(uint8_t *rngArray, uint32_t num)
{
    Log(SE_LOG_ATECC_GET_RNG, (uint8_t)num, 0);
    RngStream(rngArray, num, "shlosilo-host-sim-atecc-rng", &g_rngAtecc);
    return ATCA_SUCCESS;
}

/* ---- drv_ds28s60.h (behavioural model: plain page store) ---- */

int32_t DS28S60_HmacEncryptRead(uint8_t *data, uint8_t page)
{
    Log(SE_LOG_DS_READ, page, 0);
    if (g_failDsRead != 0) {
        return g_failDsRead;
    }
    memcpy(data, g_pages[page], SE_SHIM_PAGE_LEN);
    return SUCCESS_CODE;
}

int32_t DS28S60_HmacEncryptWrite(const uint8_t *data, uint8_t page)
{
    Log(SE_LOG_DS_WRITE, page, 0);
    if (g_failDsWrite != 0) {
        return g_failDsWrite;
    }
    memcpy(g_pages[page], data, SE_SHIM_PAGE_LEN);
    return SUCCESS_CODE;
}

int32_t DS28S60_GetRng(uint8_t *rngArray, uint32_t num)
{
    Log(SE_LOG_DS_GET_RNG, (uint8_t)num, 0);
    RngStream(rngArray, num, "shlosilo-host-sim-ds-rng", &g_rngDs);
    return SUCCESS_CODE;
}
