#include "se_manager.h"
#include "define.h"
#include "assert.h"
#include "drv_atecc608b.h"
#include "err_code.h"

/*
 * se_manager.c - shlosilo keystore port of keystone3-firmware.
 *
 * Provenance: keystone3-firmware src/managers/se_manager.c.
 *   GetAccountSlot       <- keystone3 se_manager.c:145-170 (1:1, data-plane slot map)
 *   SetNewKeyPieceToSE   <- keystone3 se_manager.c:188-200 (STUB, Task 7)
 *   GetKeyPieceFromSE    <- keystone3 se_manager.c:172-186 (STUB, Task 7)
 *   SE_HmacEncryptRead/Write <- keystone3 se_interface.c (STUB, Task 7)
 *
 * Task 6 boundary: the keystore data plane (keystore.c) must not touch the
 * real SE chips. Everything in this file that is communication-plane is a stub
 * returning ERR_KEYSTORE_UNAVAILABLE; the real ATECC608B + DS28S60 pieces and
 * page I/O (SetNewKeyPieceToAtecc608b/Ds28s60, GetKeyPieceFromAtecc608b/
 * Ds28s60, HKDF slot derivation) land in Task 7. Host tests substitute an
 * in-memory SE sim for these symbols (tests/host_keystore/host_shims.c).
 */

/// @brief Map account index to its ATECC608B slot group.
///        keystone3 se_manager.c:145-170.
/// @param[out] accountSlot Slot ids for this account.
/// @param[in] accountIndex Account index, 0~2.
void GetAccountSlot(AccountSlot_t *accountSlot, uint8_t accountIndex)
{
    ASSERT(accountIndex <= 2);
    switch (accountIndex) {
    case 0: {
        accountSlot->auth = SLOT_AUTH_KEY_1;
        accountSlot->rollKdf = SLOT_ROLL_KDF_KEY_1;
        accountSlot->hostKdf = SLOT_HOST_KDF_KEY_1;
    }
    break;
    case 1: {
        accountSlot->auth = SLOT_AUTH_KEY_2;
        accountSlot->rollKdf = SLOT_ROLL_KDF_KEY_2;
        accountSlot->hostKdf = SLOT_HOST_KDF_KEY_2;
    }
    break;
    case 2: {
        accountSlot->auth = SLOT_AUTH_KEY_3;
        accountSlot->rollKdf = SLOT_ROLL_KDF_KEY_3;
        accountSlot->hostKdf = SLOT_HOST_KDF_KEY_3;
    }
    break;
    default:
        break;
    }
}

/* ---- Task 7 communication-plane stubs ---- */

/// @brief STUB (Task 7): keystone3 se_manager.c:188-200.
int32_t SetNewKeyPieceToSE(uint8_t accountIndex, uint8_t *piece, const char *password)
{
    UNUSED(accountIndex);
    UNUSED(piece);
    UNUSED(password);
    return ERR_KEYSTORE_UNAVAILABLE;
}

/// @brief STUB (Task 7): keystone3 se_manager.c:172-186.
int32_t GetKeyPieceFromSE(uint8_t accountIndex, uint8_t *piece, const char *password)
{
    UNUSED(accountIndex);
    UNUSED(piece);
    UNUSED(password);
    return ERR_KEYSTORE_UNAVAILABLE;
}

/// @brief STUB (Task 7): keystone3 se_interface.c SE_HmacEncryptRead.
int32_t SE_HmacEncryptRead(uint8_t *data, uint8_t page)
{
    UNUSED(data);
    UNUSED(page);
    return ERR_KEYSTORE_UNAVAILABLE;
}

/// @brief STUB (Task 7): keystone3 se_interface.c SE_HmacEncryptWrite.
int32_t SE_HmacEncryptWrite(const uint8_t *data, uint8_t page)
{
    UNUSED(data);
    UNUSED(page);
    return ERR_KEYSTORE_UNAVAILABLE;
}

/// @brief STUB (Task 7): keystone3 se_interface.c SE_EncryptWrite.
int32_t SE_EncryptWrite(uint8_t slot, uint8_t block, const uint8_t *data)
{
    UNUSED(slot);
    UNUSED(block);
    UNUSED(data);
    return ERR_KEYSTORE_UNAVAILABLE;
}

/// @brief STUB (Task 7): keystone3 se_interface.c SE_Kdf.
int32_t SE_Kdf(uint8_t slot, const uint8_t *authKey, const uint8_t *inData, uint32_t inLen, uint8_t *outData)
{
    UNUSED(slot);
    UNUSED(authKey);
    UNUSED(inData);
    UNUSED(inLen);
    UNUSED(outData);
    return ERR_KEYSTORE_UNAVAILABLE;
}

/// @brief STUB (Task 7): keystone3 se_interface.c SE_DeriveKey.
int32_t SE_DeriveKey(uint8_t slot, const uint8_t *authKey)
{
    UNUSED(slot);
    UNUSED(authKey);
    return ERR_KEYSTORE_UNAVAILABLE;
}

/// @brief STUB (Task 7): keystone3 se_interface.c SE_GetDS28S60Rng.
int32_t SE_GetDS28S60Rng(uint8_t *rngArray, uint32_t num)
{
    UNUSED(rngArray);
    UNUSED(num);
    return ERR_KEYSTORE_UNAVAILABLE;
}

/// @brief STUB (Task 7): keystone3 se_interface.c SE_GetAtecc608bRng.
int32_t SE_GetAtecc608bRng(uint8_t *rngArray, uint32_t num)
{
    UNUSED(rngArray);
    UNUSED(num);
    return ERR_KEYSTORE_UNAVAILABLE;
}

/// @brief STUB (Task 7): keystone3 se_interface.c SE_GetTRng.
void SE_GetTRng(void *buf, uint32_t len)
{
    UNUSED(buf);
    UNUSED(len);
}
