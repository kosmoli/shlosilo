#include "define.h"
#include "keystore.h"
#include "string.h"
#include "stdio.h"
#include "user_utils.h"
#include "user_memory.h"
#include "hash_and_salt.h"
#include "drv_trng.h"
#include "sha256.h"
#include "sha512.h"
#include "hmac.h"
#include "ctaes.h"
#include "drv_otp.h"
#include "drv_mpu.h"
#include "se_manager.h"
#include "assert.h"

/*
 * keystore.c - shlosilo keystore data plane, ported 1:1 from keystone3-firmware
 * src/managers/keystore.c. The encrypted account-slot format (AES-256-CBC +
 * HMAC-SHA256, OTP XOR third factor, IV from TRNG) is byte-identical to
 * Keystone3 Pro; nothing here was re-invented (interface decision doc 3.4).
 *
 * Function map (keystone3 source -> this file):
 *   AccountExists          keystore.c:56-68     (1:1)
 *   SaveAccountSecret      keystore.c:503-604   (1:1 crypto body; new-account
 *                                               metadata tail deferred, below)
 *   LoadAccountSecretFromSE keystore.c:612-682  (1:1)
 *   LoadAccountSecret      keystore.c:690-698   (1:1 non-simulator path)
 *   CombineInnerAesKey     keystore.c:703-723   (1:1; simulator branch dropped)
 *
 * Deviations from keystone3 (documented, semantics unchanged):
 *   - SaveAccountSecret/LoadAccountSecret/CombineInnerAesKey/AccountExists are
 *     exported instead of static, so tests/host_keystore can drive the
 *     production object directly.
 *   - The COMPILE_SIMULATOR branches are dropped (host tests replace the SE
 *     at link level instead).
 *   - The `newAccount` metadata tail (SetCurrentAccountEntropyLen /
 *     get_master_fingerprint / SetCurrentAccountMfp / SaveCurrentAccountInfo,
 *     keystone3 keystore.c:564-595) is account-manager + Rust (librust_c)
 *     glue with zero effect on the encrypted slot layout; it is wired with the
 *     account-manager/forms link, not in this task.
 */

/*
 * SECURITY: KEYSTORE_PRINT_ARRAY prints plaintext key material - the pieces
 * hash, enKey/authKey, the decrypted entropy/seed buffers and the whole slot
 * blob. Enabling KEYSTORE_DEBUG=1 leaks secrets to whatever listens on the
 * debug console. Dev builds only; never on a provisioned device. (Prefer
 * printing a hash of a buffer over printing the buffer when adding new sites.)
 */
#define KEYSTORE_DEBUG          0

#if KEYSTORE_DEBUG == 1
#define KEYSTORE_PRINT_ARRAY(fmt, args...)       PrintArray(fmt, ##args)
#else
#define KEYSTORE_PRINT_ARRAY(fmt, args...)
#endif

/// @brief Check whether an account slot holds data (IV page carries entropy).
///        keystone3 keystore.c:56-68.
/// @param[in] accountIndex Account index, 0~2.
/// @param[out] exists
/// @return err code.
static int32_t AccountExistsImpl(uint8_t accountIndex, bool *exists)
{
    uint8_t iv[32];
    int32_t ret;

    ASSERT(accountIndex <= 2);
    ret = SE_HmacEncryptRead(iv, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_IV);
    if (ret == SUCCESS_CODE) {
        *exists = CheckEntropy(iv, sizeof(iv));
    }
    CLEAR_ARRAY(iv);
    return ret;
}

int32_t AccountExists(uint8_t accountIndex, bool *exists)
{
    return AccountExistsImpl(accountIndex, exists);
}

/// @brief Save account secret, including entropy/seed/reservedData.
///        keystone3 keystore.c:503-604.
/// @param[in] accountIndex Account index, 0~2.
/// @param[in] accountSecret Account secret data.
/// @param[in] password Password string.
/// @param[in] newAccount is new account.
/// @return err code.
int32_t SaveAccountSecret(uint8_t accountIndex, const AccountSecret_t *accountSecret, const char *password, bool newAccount)
{
    uint8_t pieces[KEY_PIECE_LEN * 2], hash[32];
    struct sha512 sha512Hash;   /* real struct, not a byte array: sha512()
                                 * writes through uint64_t members, so the old
                                 * (struct sha512 *) cast on a uint8_t[64] was
                                 * a strict-aliasing/alignment UB idiom. */
    uint8_t *enKey, *authKey;
    uint8_t *iv, *encryptEntropy, *encryptSeed, *slip39EmsOrTonEntropyL32, *encryptReservedData, *hmac;
    uint8_t accountEncryptData[ACCOUNT_TOTAL_LEN];
    int32_t ret;
    AES256_CBC_ctx ctx;

    ASSERT(accountIndex <= 2);
    enKey = sha512Hash.u.u8;
    authKey = sha512Hash.u.u8 + AES_KEY_LEN;
    iv = accountEncryptData;
    encryptEntropy = iv + AES_IV_LEN;
    encryptSeed = encryptEntropy + ENTROPY_MAX_LEN;
    slip39EmsOrTonEntropyL32 = encryptSeed + SEED_LEN;
    encryptReservedData = slip39EmsOrTonEntropyL32 + SLIP39_EMS_LEN;
    hmac = encryptReservedData + SE_DATA_RESERVED_LEN;
    do {
        ret = SetNewKeyPieceToSE(accountIndex, pieces, password);
        CHECK_ERRCODE_BREAK("set key to se", ret);
        HashWithSalt(hash, pieces, sizeof(pieces), "combine two pieces");
        KEYSTORE_PRINT_ARRAY("pieces hash", hash, sizeof(hash));
        sha512(&sha512Hash, hash, sizeof(hash));
        KEYSTORE_PRINT_ARRAY("sha512Hash", sha512Hash.u.u8, 64);
        TrngGet(iv, AES_IV_LEN);
        CombineInnerAesKey(enKey);
        AES256_CBC_init(&ctx, enKey, iv);
        AES256_CBC_encrypt(&ctx, ENTROPY_MAX_LEN / AES_BLOCK_SIZE, encryptEntropy, accountSecret->entropy);
        AES256_CBC_encrypt(&ctx, SEED_LEN / AES_BLOCK_SIZE, encryptSeed, accountSecret->seed);
        AES256_CBC_encrypt(&ctx, SLIP39_EMS_LEN / AES_BLOCK_SIZE, slip39EmsOrTonEntropyL32, accountSecret->slip39EmsOrTonEntropyL32);
        AES256_CBC_encrypt(&ctx, SE_DATA_RESERVED_LEN / AES_BLOCK_SIZE, encryptReservedData, accountSecret->reservedData);
        KEYSTORE_PRINT_ARRAY("iv", iv, AES_IV_LEN);
        KEYSTORE_PRINT_ARRAY("enKey", enKey, AES_KEY_LEN);
        KEYSTORE_PRINT_ARRAY("encryptEntropy", encryptEntropy, ENTROPY_MAX_LEN);
        KEYSTORE_PRINT_ARRAY("encryptSeed", encryptSeed, SEED_LEN);
        KEYSTORE_PRINT_ARRAY("slip39EmsOrTonEntropyL32", slip39EmsOrTonEntropyL32, SLIP39_EMS_LEN);
        KEYSTORE_PRINT_ARRAY("encryptReservedData", encryptReservedData, SE_DATA_RESERVED_LEN);
        hmac_sha256(authKey, AUTH_KEY_LEN, accountEncryptData, ACCOUNT_TOTAL_LEN - HMAC_LEN, hmac);
        KEYSTORE_PRINT_ARRAY("accountEncryptData", accountEncryptData, ACCOUNT_TOTAL_LEN);
        KEYSTORE_PRINT_ARRAY("authKey", authKey, AUTH_KEY_LEN);
        // param[0] = accountSecret->entropyLen;
        ret = SE_HmacEncryptWrite(iv, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_IV);
        CHECK_ERRCODE_BREAK("write iv", ret);
        ret = SE_HmacEncryptWrite(encryptEntropy, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_ENTROPY_OR_TON_ENTROPY_H32);
        CHECK_ERRCODE_BREAK("write encrypt entropy", ret);
        ret = SE_HmacEncryptWrite(encryptSeed, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_SEED_H32);
        CHECK_ERRCODE_BREAK("write encrypt seed h32", ret);
        ret = SE_HmacEncryptWrite(encryptSeed + 32, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_SEED_L32);
        CHECK_ERRCODE_BREAK("write encrypt seed l32", ret);
        ret = SE_HmacEncryptWrite(slip39EmsOrTonEntropyL32, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_SLIP39_EMS_OR_TON_ENTROPY_L32);
        CHECK_ERRCODE_BREAK("write slip39 ems or ton entropy l32", ret);
        ret = SE_HmacEncryptWrite(encryptReservedData, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_RESERVED);
        CHECK_ERRCODE_BREAK("write encrypt reserved data", ret);
        ret = SE_HmacEncryptWrite(hmac, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_HMAC);
        CHECK_ERRCODE_BREAK("write hmac", ret);
        if (newAccount) {
            /*
             * keystone3 keystore.c:564-595: new-account metadata tail
             * (SetCurrentAccountEntropyLen / get_master_fingerprint /
             * SetCurrentAccountMfp / SaveCurrentAccountInfo). Account-manager +
             * Rust (librust_c) glue - zero bytes of the encrypted slot layout
             * above depend on it; wired together with the account-manager /
             * forms link (out of this task's data-plane scope).
             */
        }
    } while (0);

    CLEAR_OBJECT(ctx);
    CLEAR_ARRAY(pieces);
    CLEAR_ARRAY(hash);
    CLEAR_OBJECT(sha512Hash);
    CLEAR_ARRAY(accountEncryptData);
    return ret;
}

/// @brief Load account secret with the SE PIN gate.
///        keystone3 keystore.c:612-682.
/// @param[in] accountIndex Account index, 0~2.
/// @param[out] accountSecret Account secret data.
/// @param[in] password Password string.
/// @return err code.
static int32_t LoadAccountSecretFromSE(uint8_t accountIndex, AccountSecret_t *accountSecret, const char *password)
{
    uint8_t pieces[KEY_PIECE_LEN * 2], hash[32], hmacCalc[32];
    struct sha512 sha512Hash;   /* real struct, see SaveAccountSecret: the old
                                 * (struct sha512 *) cast on uint8_t[64] was a
                                 * strict-aliasing/alignment UB idiom. */
    uint8_t *enKey, *authKey;
    uint8_t *iv, *encryptEntropy, *encryptSeed, *slip39EmsOrTonEntropyL32, *encryptReservedData, *hmac;
    uint8_t accountEncryptData[ACCOUNT_TOTAL_LEN], param[32];
    AccountParamHead_t *pAccountInfo = (AccountParamHead_t *)param;
    int32_t ret;
    AES256_CBC_ctx ctx;

    ASSERT(accountIndex <= 2);
    enKey = sha512Hash.u.u8;
    authKey = sha512Hash.u.u8 + AES_KEY_LEN;
    iv = accountEncryptData;
    encryptEntropy = iv + AES_IV_LEN;
    encryptSeed = encryptEntropy + ENTROPY_MAX_LEN;
    slip39EmsOrTonEntropyL32 = encryptSeed + SEED_LEN;
    encryptReservedData = slip39EmsOrTonEntropyL32 + SLIP39_EMS_LEN;
    hmac = encryptReservedData + SE_DATA_RESERVED_LEN;
    do {
        ret = GetKeyPieceFromSE(accountIndex, pieces, password);
        CHECK_ERRCODE_BREAK("get key piece", ret);
        HashWithSalt(hash, pieces, sizeof(pieces), "combine two pieces");
        KEYSTORE_PRINT_ARRAY("pieces hash", hash, sizeof(hash));
        sha512(&sha512Hash, hash, sizeof(hash));
        KEYSTORE_PRINT_ARRAY("sha512Hash", sha512Hash.u.u8, 64);

        ret = SE_HmacEncryptRead(iv, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_IV);
        CHECK_ERRCODE_BREAK("read iv", ret);
        ret = SE_HmacEncryptRead(encryptEntropy, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_ENTROPY_OR_TON_ENTROPY_H32);
        CHECK_ERRCODE_BREAK("read encrypt entropy", ret);
        ret = SE_HmacEncryptRead(encryptSeed, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_SEED_H32);
        CHECK_ERRCODE_BREAK("read encrypt seed h32", ret);
        ret = SE_HmacEncryptRead(encryptSeed + 32, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_SEED_L32);
        CHECK_ERRCODE_BREAK("read encrypt seed l32", ret);
        ret = SE_HmacEncryptRead(slip39EmsOrTonEntropyL32, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_SLIP39_EMS_OR_TON_ENTROPY_L32);
        CHECK_ERRCODE_BREAK("read slip39 ems or ton entropy l32", ret);
        ret = SE_HmacEncryptRead(encryptReservedData, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_RESERVED);
        CHECK_ERRCODE_BREAK("read encrypt reserved data", ret);
        ret = SE_HmacEncryptRead(hmac, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_HMAC);
        CHECK_ERRCODE_BREAK("read hmac", ret);
        ret = SE_HmacEncryptRead(param, accountIndex * PAGE_NUM_PER_ACCOUNT + PAGE_INDEX_PARAM);
        CHECK_ERRCODE_BREAK("read param", ret);
        hmac_sha256(authKey, AUTH_KEY_LEN, accountEncryptData, ACCOUNT_TOTAL_LEN - HMAC_LEN, hmacCalc);
        KEYSTORE_PRINT_ARRAY("accountEncryptData", accountEncryptData, ACCOUNT_TOTAL_LEN);
        KEYSTORE_PRINT_ARRAY("authKey", authKey, AUTH_KEY_LEN);
        ret = ((memcmp(hmacCalc, hmac, HMAC_LEN) == 0) ? SUCCESS_CODE : ERR_KEYSTORE_AUTH);
        CHECK_ERRCODE_BREAK("check hmac", ret);
        accountSecret->entropyLen = (pAccountInfo->entropyLen == 0) ? 32 : pAccountInfo->entropyLen; // 32 bytes as default.
        CombineInnerAesKey(enKey);
        AES256_CBC_init(&ctx, enKey, iv);
        AES256_CBC_decrypt(&ctx, ENTROPY_MAX_LEN / AES_BLOCK_SIZE, accountSecret->entropy, encryptEntropy);
        AES256_CBC_decrypt(&ctx, SEED_LEN / AES_BLOCK_SIZE, accountSecret->seed, encryptSeed);
        AES256_CBC_decrypt(&ctx, SLIP39_EMS_LEN / AES_BLOCK_SIZE, accountSecret->slip39EmsOrTonEntropyL32, slip39EmsOrTonEntropyL32);
        AES256_CBC_decrypt(&ctx, SE_DATA_RESERVED_LEN / AES_BLOCK_SIZE, accountSecret->reservedData, encryptReservedData);
        KEYSTORE_PRINT_ARRAY("iv", iv, AES_IV_LEN);
        KEYSTORE_PRINT_ARRAY("enKey", enKey, AES_KEY_LEN);
        KEYSTORE_PRINT_ARRAY("encryptEntropy", encryptEntropy, ENTROPY_MAX_LEN);
        KEYSTORE_PRINT_ARRAY("encryptSeed", encryptSeed, SEED_LEN);
        KEYSTORE_PRINT_ARRAY("slip39EmsOrTonEntropyL32", slip39EmsOrTonEntropyL32, SLIP39_EMS_LEN);
        KEYSTORE_PRINT_ARRAY("encryptReservedData", encryptReservedData, SE_DATA_RESERVED_LEN);
    } while (0);

    CLEAR_OBJECT(ctx);
    CLEAR_ARRAY(pieces);
    CLEAR_ARRAY(hash);
    CLEAR_OBJECT(sha512Hash);
    CLEAR_ARRAY(accountEncryptData);
    CLEAR_ARRAY(hmacCalc);
    /* param carries account metadata (entropyLen + the account-info tail the
     * account manager owns) - wipe it like the key material. */
    CLEAR_ARRAY(param);
    return ret;
}

/// @brief Load account secret, including entropy/seed/reservedData.
///        keystone3 keystore.c:690-698.
/// @param[in] accountIndex Account index, 0~2.
/// @param[out] accountSecret Account secret data.
/// @param[in] password Password string.
/// @return err code.
int32_t LoadAccountSecret(uint8_t accountIndex, AccountSecret_t *accountSecret, const char *password)
{
    ASSERT(accountIndex <= 2);
    return LoadAccountSecretFromSE(accountIndex, accountSecret, password);
}

/// @brief Combine with the internal AES KEY of MCU.
///        keystone3 keystore.c:703-723 (OTP XOR third factor).
/// @param[inout] aesKey
/// @return
void CombineInnerAesKey(uint8_t *aesKey)
{
    uint8_t aesPiece[AES_KEY_LEN];

    MpuSetOtpProtection(false);
    OTP_PowerOn();
    memcpy_s(aesPiece, sizeof(aesPiece), (uint8_t *)OTP_ADDR_AES_KEY, AES_KEY_LEN);
    if (CheckEntropy(aesPiece, AES_KEY_LEN) == false) {
        printf("need generate inner aes piece\r\n");
        TrngGet(aesPiece, AES_KEY_LEN);
        /* The OTP burn must be loud. A silently failed write would leave THIS
         * call XORing a freshly generated, never-persisted piece into the
         * enKey while every later call re-generates a DIFFERENT piece - load
         * would then decrypt with a wrong enKey, and because authKey is not
         * XORed with the OTP piece the HMAC still verifies: LoadAccountSecret
         * would silently return a garbled seed. Same loud pattern as
         * hash_and_salt.c:58. */
        ASSERT(SUCCESS_CODE == WriteOtpData(OTP_ADDR_AES_KEY, aesPiece, AES_KEY_LEN));
    }
    MpuSetOtpProtection(true);
    for (uint32_t i = 0; i < AES_KEY_LEN; i++) {
        aesKey[i] ^= aesPiece[i];
    }
    /* Key hygiene (shlosilo rule; semantic no-op over keystone3, which leaves
     * the plaintext piece on the stack): wipe the inner AES piece. */
    CLEAR_ARRAY(aesPiece);
}
