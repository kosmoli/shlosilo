#ifndef _SE_SHIMS_H
#define _SE_SHIMS_H

/*
 * Host driver shims for the SE communication plane (Task 7).
 *
 * Layering (the important part): the PRODUCTION se_manager.c is compiled in
 * and tested; these shims replace the DRIVERS it calls (drv_atecc608b /
 * drv_ds28s60 / drv_trng) plus the OTP/MPU/assert plumbing. So the host suite
 * pins the protocol GLUE in se_manager.c - the call state machine, the error
 * mapping and the KDF composition - while real chip timing/protocol stays
 * device-only (flux/forgebox/docs/se-keystore-checklist.md).
 *
 * Determinism contract - mirrored value-for-value by oracle_se.py. ANY change
 * here must be changed there too:
 *   ATECC608B Kdf(slot, authKey, in)   = HMAC-SHA256(key=slot_key, msg=in)
 *   ATECC608B DeriveKey(slot, authKey) = slot_key = HMAC-SHA256(
 *                                          key=old_slot_key,
 *                                          "shlosilo-host-sim-derive"||authKey)
 *   ATECC608B auth gate                = authKey == group auth slot key, else
 *                                        ATCA_CHECKMAC_VERIFY_FAILED (0xD1)
 *   ATECC608B auth-slot map            = {4,5}->3, {7,9}->6, {11,12}->10
 *                                        (same as drv_atecc608b.c GetAuthSlot)
 *   blank ATECC slot                   = 32 x 0x00
 *   DS28S60 page store                 = 256 x 32 bytes, blank 0xFF
 *   TRNG block j                       = SHA256("shlosilo-host-sim-trng"||le32(j))
 *   ATECC RNG block j                  = SHA256("shlosilo-host-sim-atecc-rng"||le32(j))
 *   DS28S60 RNG block j                = SHA256("shlosilo-host-sim-ds-rng"||le32(j))
 */
#include "stdint.h"
#include "stdbool.h"

#define SE_SHIM_PAGE_COUNT      256
#define SE_SHIM_PAGE_LEN        32
#define SE_SHIM_SLOT_COUNT      16

typedef enum {
    SE_LOG_NONE = 0,
    SE_LOG_ATECC_ENCRYPT_WRITE,
    SE_LOG_ATECC_DERIVE_KEY,
    SE_LOG_ATECC_KDF,
    SE_LOG_ATECC_GET_RNG,
    SE_LOG_DS_WRITE,
    SE_LOG_DS_READ,
    SE_LOG_DS_GET_RNG,
    SE_LOG_TRNG_GET,
} SeLogEvent_t;

typedef struct {
    SeLogEvent_t event;
    uint8_t a;      /* slot / page */
    uint8_t b;      /* block */
} SeLogEntry_t;

/* Reset slot/page stores (0x00 / 0xFF), RNG counters, fault injection, log. */
void SeShimsReset(void);

/* Seed the fake OTP salt (32B) so HashWithSalt never triggers its lazy
 * generate-and-burn path. */
void SeShimsSeedSalt(const uint8_t *salt);

/* Direct access for assertions. */
uint8_t *SeShimSlot(uint8_t slot);
uint8_t *SeShimPage(uint8_t page);

/* Call log (state-machine pins). */
int SeShimLogCount(void);
SeLogEntry_t SeShimLogAt(int i);
void SeShimLogClear(void);

/* Fault injection: the armed op returns `code` and does not store/read.
 * Pass 0 to disarm one op; SeShimsReset disarms everything. */
void SeShimFailAteccEncryptWrite(int32_t code);
void SeShimFailAteccDeriveKey(int32_t code);
void SeShimFailAteccKdf(int32_t code);
void SeShimFailDsWrite(int32_t code);
void SeShimFailDsRead(int32_t code);

#endif
