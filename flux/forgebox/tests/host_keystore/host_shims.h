#ifndef _HOST_SHIMS_H
#define _HOST_SHIMS_H

/*
 * Host-test harness for the keystore data plane (Task 6).
 *
 * These shims stand in for the hardware touch-points that the Task-6 boundary
 * deliberately does NOT implement against real chips (SE comm is Task 7):
 *   - TrngGet (drv_trng.c)              -> deterministic counter keystream
 *   - OTP window + WriteOtpData         -> mmap()ed fake at the real MH1903
 *                                          OTP addresses (drv_otp.h layout)
 *   - SetNewKeyPieceToSE/GetKeyPieceFromSE/SE_HmacEncrypt* (se_manager.c
 *     Task-7 stubs)                     -> in-memory SE sim
 *
 * Determinism contract - shared with oracle_golden.py (the independent
 * Python oracle). ANY change here must be mirrored there:
 *   TrngGet block j  = SHA256("shlosilo-host-sim-trng" || le32(j)), blocks of
 *                      32 bytes, global counter reset by HostShimsReset().
 *   key piece 0      = SHA256("shlosilo-host-sim-atecc-piece"  || password)
 *   key piece 1      = SHA256("shlosilo-host-sim-ds28s60-piece" || password)
 *   SE pages         = 256 x 32 bytes, blank 0xFF (DS28S60-style page store)
 */
#include "stdint.h"
#include "stdbool.h"

#define HOST_SIM_PAGE_COUNT     256
#define HOST_SIM_PAGE_LEN       32

/* Reset SE page store (all 0xFF), TRNG block counter, OTP window (all 0xFF). */
void HostShimsReset(void);

/* Seed the fake OTP with the per-device salt and inner AES piece (32B each). */
void HostShimsSeedOtp(const uint8_t *salt, const uint8_t *aesPiece);

/* Blank the inner AES piece area to 0xFF (exercises the generate-and-burn path). */
void HostShimsBlankOtpAesPiece(void);

/* Direct access to the SE page store for assertions / fault injection. */
uint8_t *HostSePage(uint8_t page);

/* Write-fault injection: while armed, SE_HmacEncryptWrite to `page` fails
 * with HOST_SIM_WRITE_ERR and does NOT store. HostShimsReset() disarms.
 * Lets the tests pin the save path's terminal slot state + return code when
 * one of the seven slot pages rejects its write. */
#define HOST_SIM_WRITE_ERR      (-23)
void HostShimsFailSeWritePage(uint8_t page);

#endif
