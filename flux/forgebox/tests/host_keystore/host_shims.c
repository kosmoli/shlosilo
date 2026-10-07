#include "host_shims.h"
#include "string.h"
#include "stdio.h"
#include "stdlib.h"
#include "sys/mman.h"
#include "sha256.h"
#include "drv_otp.h"
#include "se_manager.h"

/*
 * Host SE/OTP/TRNG sim - see host_shims.h for the determinism contract that
 * oracle_golden.py mirrors. Task-6 boundary: no real SE chip is touched here;
 * the real ATECC608B + DS28S60 communication lands in Task 7.
 */

static uint8_t g_pages[HOST_SIM_PAGE_COUNT][HOST_SIM_PAGE_LEN];
static uint32_t g_trngBlock;
static uint8_t *g_otpWindow;
static int g_failWritePage = -1;

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
        fprintf(stderr, "host_shims: mmap of fake OTP window failed\n");
        exit(1);
    }
}

void HostShimsReset(void)
{
    OtpWindowInit();
    memset(g_pages, 0xFF, sizeof(g_pages));
    memset(g_otpWindow, 0xFF, OTP_WINDOW_SIZE);
    g_trngBlock = 0;
    g_failWritePage = -1;
}

void HostShimsFailSeWritePage(uint8_t page)
{
    g_failWritePage = (int)page;
}

void HostShimsSeedOtp(const uint8_t *salt, const uint8_t *aesPiece)
{
    OtpWindowInit();
    memcpy(g_otpWindow + (OTP_ADDR_SALT - OTP_WINDOW_BASE), salt, 32);
    memcpy(g_otpWindow + (OTP_ADDR_AES_KEY - OTP_WINDOW_BASE), aesPiece, 32);
}

void HostShimsBlankOtpAesPiece(void)
{
    OtpWindowInit();
    memset(g_otpWindow + (OTP_ADDR_AES_KEY - OTP_WINDOW_BASE), 0xFF, 32);
}

uint8_t *HostSePage(uint8_t page)
{
    return g_pages[page];
}

/* ---- drv_trng.h: deterministic TRNG ---- */

void TrngInit(void)
{
}

void TrngGet(void *buf, uint32_t len)
{
    uint8_t *out = (uint8_t *)buf;
    uint32_t done = 0;

    while (done < len) {
        uint8_t msg[26];
        struct sha256 h;
        uint32_t chunk = (len - done > 32) ? 32 : (len - done);

        memcpy(msg, "shlosilo-host-sim-trng", 22);
        msg[22] = (uint8_t)(g_trngBlock);
        msg[23] = (uint8_t)(g_trngBlock >> 8);
        msg[24] = (uint8_t)(g_trngBlock >> 16);
        msg[25] = (uint8_t)(g_trngBlock >> 24);
        sha256(&h, msg, sizeof(msg));
        memcpy(out + done, h.u.u8, chunk);
        done += chunk;
        g_trngBlock++;
    }
}

/* ---- drv_otp.h / drv_mpu.h / assert.h / mhscpu_otp.h shims ---- */

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
    fprintf(stderr, "host_shims: ASSERT failed at %s:%u\n", file, line);
    exit(1);
}

/* ---- se_manager.h SE sim (Task-7 stubs replaced at link level) ---- */

static void HashPiece(uint8_t *out, const char *label, const char *password)
{
    uint8_t msg[128];
    size_t labelLen = strlen(label);
    size_t pwdLen = strlen(password);
    struct sha256 h;

    memcpy(msg, label, labelLen);
    memcpy(msg + labelLen, password, pwdLen);
    sha256(&h, msg, labelLen + pwdLen);
    memcpy(out, h.u.u8, 32);
}

int32_t SetNewKeyPieceToSE(uint8_t accountIndex, uint8_t *piece, const char *password)
{
    (void)accountIndex;
    HashPiece(piece, "shlosilo-host-sim-atecc-piece", password);
    HashPiece(piece + KEY_PIECE_LEN, "shlosilo-host-sim-ds28s60-piece", password);
    return 0;
}

int32_t GetKeyPieceFromSE(uint8_t accountIndex, uint8_t *piece, const char *password)
{
    return SetNewKeyPieceToSE(accountIndex, piece, password);
}

int32_t SE_HmacEncryptRead(uint8_t *data, uint8_t page)
{
    memcpy(data, g_pages[page], HOST_SIM_PAGE_LEN);
    return 0;
}

int32_t SE_HmacEncryptWrite(const uint8_t *data, uint8_t page)
{
    if ((int)page == g_failWritePage) {
        return HOST_SIM_WRITE_ERR;  /* fault injection: reject without storing */
    }
    memcpy(g_pages[page], data, HOST_SIM_PAGE_LEN);
    return 0;
}
