#ifndef _SE_MANAGER_H_
#define _SE_MANAGER_H_

/*
 * se_manager.h - shlosilo keystore port of keystone3-firmware.
 *
 * Provenance: keystone3-firmware src/managers/se_manager.h:1-60 (page map,
 * slot struct, interface declarations) and src/hardware_interface/se_interface.h:7-14
 * (SE comm surface). Values are copied verbatim from keystone3 - do not "fix"
 * or renumber: the on-SE page layout is the interop contract with Keystone3 Pro.
 *
 * v1 scope note (interface decision doc 3.2): only the subset the keystore data
 * plane depends on is declared here; the fingerprint/wallet-hash family
 * (SetFpEncryptedPassword etc.) rides along with a later task if needed.
 */

#include "stdint.h"
#include "stdbool.h"

#define KEY_PIECE_LEN                               32

//DS28S60 page map (keystone3 se_manager.h:9-33, 逐值照抄)
#define PAGE_NUM_PER_ACCOUNT                        12
#define PAGE_INDEX_IV                               0
#define PAGE_INDEX_ENTROPY_OR_TON_ENTROPY_H32       1
#define PAGE_INDEX_SEED_H32                         2
#define PAGE_INDEX_SEED_L32                         3
//page 4/5 reserved
#define PAGE_INDEX_SLIP39_EMS_OR_TON_ENTROPY_L32    4
#define PAGE_INDEX_RESERVED                         5
#define PAGE_INDEX_HMAC                             6
#define PAGE_INDEX_KEY_PIECE                        7
// Don't use this page in the future usage, it is only for legacy password hash
#define PAGE_INDEX_LEGACY_PASSWORD_HASH             8
#define PAGE_INDEX_PARAM                            9
#define PAGE_INDEX_MULTISIG_CONFIG_HASH             10
//page 76~85 encrypted password
#define PAGE_PF_ENCRYPTED_PASSWORD                  72
#define PAGE_PF_AES_KEY                             82
#define PAGE_PF_RESET_KEY                           83
#define PAGE_PF_INFO                                84
#define PAGE_WALLET1_PUB_KEY_HASH                   85
#define PAGE_WALLET2_PUB_KEY_HASH                   86
#define PAGE_WALLET3_PUB_KEY_HASH                   87

#define PAGE_PUBLIC_INFO                            88

typedef struct {
    uint8_t auth;
    uint8_t rollKdf;
    uint8_t hostKdf;
} AccountSlot_t;

/*
 * SE communication surface (keystone3 se_interface.h:7-14). All of these are
 * communication-plane: implemented against the real ATECC608B + DS28S60 in
 * Task 7. This task ships stubs in se_manager.c that return
 * ERR_KEYSTORE_UNAVAILABLE - the keystore data plane is exercised against an
 * in-memory SE sim in tests/host_keystore instead of the real chips.
 */
int32_t SE_EncryptWrite(uint8_t slot, uint8_t block, const uint8_t *data);
int32_t SE_Kdf(uint8_t slot, const uint8_t *authKey, const uint8_t *inData, uint32_t inLen, uint8_t *outData);
int32_t SE_DeriveKey(uint8_t slot, const uint8_t *authKey);
int32_t SE_HmacEncryptRead(uint8_t *data, uint8_t page);
int32_t SE_HmacEncryptWrite(const uint8_t *data, uint8_t page);
int32_t SE_GetDS28S60Rng(uint8_t *rngArray, uint32_t num);
void SE_GetTRng(void *buf, uint32_t len);
int32_t SE_GetAtecc608bRng(uint8_t *rngArray, uint32_t num);

/* key-piece supply (keystone3 se_manager.h:41-42, bodies in Task 7) */
void GetAccountSlot(AccountSlot_t *accountSlot, uint8_t accountIndex);
int32_t GetKeyPieceFromSE(uint8_t accountIndex, uint8_t *piece, const char *password);
int32_t SetNewKeyPieceToSE(uint8_t accountIndex, uint8_t *piece, const char *password);

#endif
