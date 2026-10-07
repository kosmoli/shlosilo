#ifndef _KEYSTORE_H
#define _KEYSTORE_H

/*
 * keystore.h - shlosilo keystore data plane, ported 1:1 from keystone3-firmware.
 *
 * Provenance: keystone3-firmware src/managers/keystore.h:1-73. Every size
 * constant, the AccountSecret_t layout and the AES/HMAC block accounting below
 * are copied verbatim from keystone3 - the encrypted account-slot format is the
 * interop contract with Keystone3 Pro (interface decision doc 3.3/3.4).
 */

#include "stdint.h"
#include "stdbool.h"
#include "err_code.h"

#define ACCOUNT_INDEX_LOGOUT                    255
#define AES_BLOCK_SIZE                          16

#define KEY_PIECE_LEN                           32

#define AES_KEY_LEN                             32
#define AUTH_KEY_LEN                            32

#define AES_IV_LEN                              32              //Use first 16 bytes for AES key, last 16 bytes reserved for future features.
#define ENTROPY_MAX_LEN                         32
#define TRNG_RANDOMNESS_LEN                     32
#define TON_ENTROPY_LEN                         64
#define SEED_LEN                                64
#define SLIP39_EMS_LEN                          32
#define SE_DATA_RESERVED_LEN                    32
#define HMAC_LEN                                32
#define ACCOUNT_TOTAL_LEN                       (AES_IV_LEN + ENTROPY_MAX_LEN + SEED_LEN + SLIP39_EMS_LEN + SE_DATA_RESERVED_LEN + HMAC_LEN)
#define PARAM_LEN                               32

#define MIN_PASSWORD_LEN                        6
#define TON_MNEMONIC_WORDS_COUNT                24

#define ITERATION_TIME                          700

typedef struct {
    uint8_t entropy[ENTROPY_MAX_LEN];
    uint8_t seed[SEED_LEN];
    uint8_t slip39EmsOrTonEntropyL32[SLIP39_EMS_LEN];
    uint8_t reservedData[SE_DATA_RESERVED_LEN];
    uint8_t entropyLen;
} AccountSecret_t;

/*
 * Head of the PAGE_INDEX_PARAM page. keystone3 reads it through
 * AccountInfo_t (src/managers/account_manager.h:33-47) whose FIRST member is
 * entropyLen; the keystore data plane touches nothing else in that page.
 */
typedef struct {
    uint8_t entropyLen;
} AccountParamHead_t;

/*
 * Data-plane core. keystone3 keeps SaveAccountSecret/LoadAccountSecret/
 * CombineInnerAesKey file-static (keystone3 keystore.c:46-53); they are
 * exported here so the host test can drive the production code directly.
 * Algorithm semantics are unchanged.
 */
int32_t SaveAccountSecret(uint8_t accountIndex, const AccountSecret_t *accountSecret, const char *password, bool newAccount);
int32_t LoadAccountSecret(uint8_t accountIndex, AccountSecret_t *accountSecret, const char *password);
void CombineInnerAesKey(uint8_t *aesKey);
int32_t AccountExists(uint8_t accountIndex, bool *exists);

#endif
