#include "se_manager.h"
#include "define.h"
#include "string.h"
#include "stdio.h"
#include "assert.h"
#include "err_code.h"
#include "user_utils.h"
#include "user_memory.h"
#include "hash_and_salt.h"
#include "sha256.h"
#include "drv_trng.h"
#include "drv_atecc608b.h"
#include "drv_ds28s60.h"
#include "atca_status.h"

/*
 * se_manager.c - shlosilo keystore SE communication plane, ported 1:1 from
 * keystone3-firmware. Task 6 shipped the data plane + stubs here; Task 7
 * replaces the stubs with the real dual-SE flows.
 *
 * Provenance (keystone3-firmware source -> this file):
 *   NormalizeAteccAuthError     se_manager.c:25-28   (1:1)
 *   SetNewKeyPieceToAtecc608b   se_manager.c:30-67   (1:1; see deviation 2)
 *   SetNewKeyPieceToDs28s60     se_manager.c:69-90   (1:1; see deviation 2)
 *   GetKeyPieceFromAtecc608b    se_manager.c:92-123  (1:1; see deviation 2)
 *   GetKeyPieceFromDs28s60      se_manager.c:125-143 (1:1; see deviation 2)
 *   GetAccountSlot              se_manager.c:145-170 (1:1, Task 6)
 *   GetKeyPieceFromSE           se_manager.c:172-186 (1:1)
 *   SetNewKeyPieceToSE          se_manager.c:188-200 (1:1)
 *   SE_* interface wrappers     se_interface.c:11-70 (1:1 call mapping, see
 *                               deviations 1/3)
 *
 * Every derivation parameter is copied verbatim from keystone3 - the KDF
 * domain strings ("auth_key", "password_atecc608b", "ds28s60 digest"), the
 * SHA256_COUNT=3 tail, the rollKdf/hostKdf two-stage KDF order, the DS28S60
 * XOR split (piece = randomKey, page holds passwordHash ^ randomKey) and the
 * slot/page addresses (drv_atecc608b.h slot map, se_manager.h page map).
 *
 * Deviations from keystone3 (documented; derivation semantics unchanged):
 *   1. keystone3 se_interface.c ASSERTs every non-auth driver failure and
 *      returns SUCCESS_CODE. shlosilo returns ERR_GENERAL_FAIL (ATECC) or the
 *      driver's own Error_Code (DS28S60 family already returns ERR_DS28S60_*)
 *      instead: the smoke battery must be able to REPORT a dead chip, not hang
 *      in an assert. The ATCA_CHECKMAC_VERIFY_FAILED passthrough (which
 *      NormalizeAteccAuthError folds into ERR_KEYSTORE_AUTH) is kept byte-for-
 *      byte as keystone3 does it.
 *   2. The sha256() tail uses a real struct sha256 instead of keystone3's
 *      (struct sha256 *)cast on a byte buffer (strict-aliasing UB idiom noted
 *      in keystore.c). Output bytes identical.
 *   3. The four per-SE piece functions are exported (keystone3 keeps them
 *      static) so the smoke battery and host suite can drive each SE half
 *      (se_manager.h notes this too).
 *   4. Secrets are wiped on every exit path (CLEAR_ARRAY) - shlosilo key
 *      hygiene, semantic no-op over keystone3.
 *
 * Host coverage: tests/host_se builds THIS file against behavioural driver
 * shims (se_shims.c) and pins the call state machine, the error mapping and
 * the KDF composition against a Python oracle. Real chip timing/protocol is
 * device-only - see flux/forgebox/docs/se-keystore-checklist.md.
 */

#define SHA256_COUNT                            3

/// @brief keystone3 se_manager.c:25-28. A CheckMac failure is the chip saying
///        "wrong auth key" - to the keystore that is exactly a wrong password.
static int32_t NormalizeAteccAuthError(int32_t ret)
{
    return (ret == ATCA_CHECKMAC_VERIFY_FAILED) ? ERR_KEYSTORE_AUTH : ret;
}

/// @brief Derive + store the ATECC608B half of a new key piece.
///        keystone3 se_manager.c:30-67 (1:1).
/// @param[in] accountIndex Account index, 0~2.
/// @param[out] piece 32-byte derived piece.
/// @param[in] password Password string.
/// @return err code.
int32_t SetNewKeyPieceToAtecc608b(uint8_t accountIndex, uint8_t *piece, const char *password)
{
    uint8_t authKey[32], hostRandom[32], inData[32], outData[32];
    int32_t ret = SUCCESS_CODE;
    AccountSlot_t accountSlot;

    ASSERT(accountIndex <= 2);
    do {
        HashWithSalt(authKey, (uint8_t *)password, strnlen_s(password, PASSWORD_MAX_LEN), "auth_key");
        GetAccountSlot(&accountSlot, accountIndex);
        ret = SE_EncryptWrite(accountSlot.auth, 0, authKey);
        CHECK_ERRCODE_BREAK("write auth", ret);
        ret = SE_DeriveKey(accountSlot.rollKdf, authKey);
        CHECK_ERRCODE_BREAK("derive key", ret);
        TrngGet(hostRandom, 32);
        ret = SE_EncryptWrite(accountSlot.hostKdf, 0, hostRandom);
        CHECK_ERRCODE_BREAK("write kdf", ret);

        HashWithSalt(outData, (uint8_t *)password, strnlen_s(password, PASSWORD_MAX_LEN), "password_atecc608b");
        memcpy(inData, outData, 32);
        ret = SE_Kdf(accountSlot.rollKdf, authKey, inData, 32, outData);
        CHECK_ERRCODE_BREAK("kdf", ret);
        memcpy(inData, outData, 32);
        ret = SE_Kdf(accountSlot.hostKdf, authKey, inData, 32, outData);
        CHECK_ERRCODE_BREAK("kdf", ret);
        for (uint32_t i = 0; i < SHA256_COUNT; i++) {
            struct sha256 h;
            memcpy(inData, outData, 32);
            sha256(&h, inData, 32);
            memcpy(outData, h.u.u8, 32);
        }
        memcpy(piece, outData, 32);
    } while (0);
    CLEAR_ARRAY(authKey);
    CLEAR_ARRAY(hostRandom);
    CLEAR_ARRAY(inData);
    CLEAR_ARRAY(outData);

    return ret;
}

/// @brief Derive + store the DS28S60 half of a new key piece.
///        keystone3 se_manager.c:69-90 (1:1).
/// @param[in] accountIndex Account index, 0~2.
/// @param[out] piece 32-byte derived piece (the random half; the SE page
///             holds passwordHash ^ piece).
/// @param[in] password Password string.
/// @return err code.
int32_t SetNewKeyPieceToDs28s60(uint8_t accountIndex, uint8_t *piece, const char *password)
{
    uint8_t passwordHash[32], randomKey[32], xData[32];
    int32_t ret = SUCCESS_CODE;

    ASSERT(accountIndex <= 2);
    HashWithSalt(passwordHash, (uint8_t *)password, strnlen_s(password, PASSWORD_MAX_LEN), "ds28s60 digest");
    TrngGet(randomKey, 32);
    for (uint32_t i = 0; i < 32; i++) {
        xData[i] = passwordHash[i] ^ randomKey[i];
    }
    do {
        ret = SE_HmacEncryptWrite(xData, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_KEY_PIECE);
        CHECK_ERRCODE_BREAK("write xData", ret);
        memcpy(piece, randomKey, 32);
    } while (0);
    CLEAR_ARRAY(passwordHash);
    CLEAR_ARRAY(randomKey);
    CLEAR_ARRAY(xData);

    return ret;
}

/// @brief Re-derive the ATECC608B half of the key piece from the password.
///        keystone3 se_manager.c:92-123 (1:1).
/// @param[in] accountIndex Account index, 0~2.
/// @param[out] piece 32-byte derived piece.
/// @param[in] password Password string.
/// @return err code; a wrong password surfaces as ERR_KEYSTORE_AUTH.
int32_t GetKeyPieceFromAtecc608b(uint8_t accountIndex, uint8_t *piece, const char *password)
{
    uint8_t authKey[32], inData[32], outData[32];
    int32_t ret = SUCCESS_CODE;
    AccountSlot_t accountSlot;

    ASSERT(accountIndex <= 2);
    do {
        HashWithSalt(authKey, (uint8_t *)password, strnlen_s(password, PASSWORD_MAX_LEN), "auth_key");
        HashWithSalt(outData, (uint8_t *)password, strnlen_s(password, PASSWORD_MAX_LEN), "password_atecc608b");
        memcpy(inData, outData, 32);

        GetAccountSlot(&accountSlot, accountIndex);
        ret = SE_Kdf(accountSlot.rollKdf, authKey, inData, 32, outData);
        ret = NormalizeAteccAuthError(ret);
        CHECK_ERRCODE_BREAK("kdf", ret);
        memcpy(inData, outData, 32);
        ret = SE_Kdf(accountSlot.hostKdf, authKey, inData, 32, outData);
        ret = NormalizeAteccAuthError(ret);
        CHECK_ERRCODE_BREAK("kdf", ret);
        for (uint32_t i = 0; i < SHA256_COUNT; i++) {
            struct sha256 h;
            memcpy(inData, outData, 32);
            sha256(&h, inData, 32);
            memcpy(outData, h.u.u8, 32);
        }
        memcpy(piece, outData, 32);
    } while (0);
    CLEAR_ARRAY(authKey);
    CLEAR_ARRAY(inData);
    CLEAR_ARRAY(outData);

    return ret;
}

/// @brief Re-derive the DS28S60 half of the key piece from the password.
///        keystone3 se_manager.c:125-143 (1:1).
/// @param[in] accountIndex Account index, 0~2.
/// @param[out] piece 32-byte derived piece.
/// @param[in] password Password string.
/// @return err code. NOTE (1:1 keystone3): this half cannot fail on a wrong
///         password - it yields a DIFFERENT (wrong) piece, which the keystore
///         HMAC gate then rejects as ERR_KEYSTORE_AUTH.
int32_t GetKeyPieceFromDs28s60(uint8_t accountIndex, uint8_t *piece, const char *password)
{
    uint8_t passwordHash[32], xData[32];
    int32_t ret = SUCCESS_CODE;

    ASSERT(accountIndex <= 2);
    do {
        HashWithSalt(passwordHash, (uint8_t *)password, strnlen_s(password, PASSWORD_MAX_LEN), "ds28s60 digest");
        ret = SE_HmacEncryptRead(xData, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_KEY_PIECE);
        CHECK_ERRCODE_BREAK("read xData", ret);
        for (uint32_t i = 0; i < 32; i++) {
            piece[i] = passwordHash[i] ^ xData[i];
        }
    } while (0);
    CLEAR_ARRAY(passwordHash);
    CLEAR_ARRAY(xData);

    return ret;
}

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

/// @brief Assemble both SE halves of the key piece for one account.
///        keystone3 se_manager.c:172-186 (1:1).
/// @param[in] accountIndex Account index, 0~2.
/// @param[out] pieces 64 bytes: [0..31] ATECC608B half, [32..63] DS28S60 half.
/// @param[in] password Password string.
/// @return err code.
int32_t GetKeyPieceFromSE(uint8_t accountIndex, uint8_t *pieces, const char *password)
{
    int32_t ret;
    do {
        ret = GetKeyPieceFromAtecc608b(accountIndex, pieces, password);
        CHECK_ERRCODE_BREAK("atecc piece", ret);
        ret = GetKeyPieceFromDs28s60(accountIndex, pieces + KEY_PIECE_LEN, password);
        CHECK_ERRCODE_BREAK("ds28s60 piece", ret);
    } while (0);

    return ret;
}

/// @brief Derive + store both SE halves of a new key piece for one account.
///        keystone3 se_manager.c:188-200 (1:1).
/// @param[in] accountIndex Account index, 0~2.
/// @param[out] pieces 64 bytes: [0..31] ATECC608B half, [32..63] DS28S60 half.
/// @param[in] password Password string.
/// @return err code.
int32_t SetNewKeyPieceToSE(uint8_t accountIndex, uint8_t *pieces, const char *password)
{
    int32_t ret;
    ret = SetNewKeyPieceToAtecc608b(accountIndex, pieces, password);
    CHECK_ERRCODE_RETURN_INT(ret);

    ret = SetNewKeyPieceToDs28s60(accountIndex, pieces + KEY_PIECE_LEN, password);
    CHECK_ERRCODE_RETURN_INT(ret);
    return ret;
}

/* ==== SE interface wrappers (keystone3 se_interface.c:11-70) ====
 * 1:1 call mapping onto the in-tree drivers. Per deviation 1 the keystone3
 * ASSERT-on-failure contract is replaced by error-code returns:
 *   ATECC608B: SUCCESS_CODE, ATCA_CHECKMAC_VERIFY_FAILED (raw passthrough,
 *              folded to ERR_KEYSTORE_AUTH by NormalizeAteccAuthError above -
 *              exactly keystone3's shape), else ERR_GENERAL_FAIL.
 *   DS28S60:   the driver already returns Error_Code (ERR_DS28S60_*) -
 *              passed through verbatim.
 */

/// @brief keystone3 se_interface.c:11-16 -> Atecc608bEncryptWrite.
int32_t SE_EncryptWrite(uint8_t slot, uint8_t block, const uint8_t *data)
{
    int32_t ret = Atecc608bEncryptWrite(slot, block, data);
    return (ret == ATCA_SUCCESS) ? SUCCESS_CODE : ERR_GENERAL_FAIL;
}

/// @brief keystone3 se_interface.c:18-26 -> Atecc608bKdf.
int32_t SE_Kdf(uint8_t slot, const uint8_t *authKey, const uint8_t *inData, uint32_t inLen, uint8_t *outData)
{
    int32_t ret = Atecc608bKdf(slot, authKey, inData, inLen, outData);
    if (ret == ATCA_CHECKMAC_VERIFY_FAILED) {
        return ret;
    }
    return (ret == ATCA_SUCCESS) ? SUCCESS_CODE : ERR_GENERAL_FAIL;
}

/// @brief keystone3 se_interface.c:28-33 -> Atecc608bDeriveKey.
int32_t SE_DeriveKey(uint8_t slot, const uint8_t *authKey)
{
    int32_t ret = Atecc608bDeriveKey(slot, authKey);
    return (ret == ATCA_SUCCESS) ? SUCCESS_CODE : ERR_GENERAL_FAIL;
}

/// @brief keystone3 se_interface.c:37-42 -> DS28S60_HmacEncryptRead.
int32_t SE_HmacEncryptRead(uint8_t *data, uint8_t page)
{
    return DS28S60_HmacEncryptRead(data, page);
}

/// @brief keystone3 se_interface.c:63-68 -> DS28S60_HmacEncryptWrite.
int32_t SE_HmacEncryptWrite(const uint8_t *data, uint8_t page)
{
    return DS28S60_HmacEncryptWrite(data, page);
}

/// @brief keystone3 se_interface.c:44-49 -> DS28S60_GetRng.
int32_t SE_GetDS28S60Rng(uint8_t *rngArray, uint32_t num)
{
    return DS28S60_GetRng(rngArray, num);
}

/// @brief keystone3 se_interface.c:56-61 -> Atecc608bGetRng.
int32_t SE_GetAtecc608bRng(uint8_t *rngArray, uint32_t num)
{
    int32_t ret = Atecc608bGetRng(rngArray, num);
    return (ret == ATCA_SUCCESS) ? SUCCESS_CODE : ERR_GENERAL_FAIL;
}

/// @brief keystone3 se_interface.c:51-54 -> TrngGet.
void SE_GetTRng(void *buf, uint32_t len)
{
    TrngGet(buf, len);
}
