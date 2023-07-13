#ifndef IOTEX_DES_H
#define IOTEX_DES_H

#include "build_info.h"
#include "platform_util.h"

#include <stddef.h>
#include <stdint.h>

#define IOTEX_DES_ENCRYPT     1
#define IOTEX_DES_DECRYPT     0

/** The data input has an invalid length. */
#define IOTEX_ERR_DES_INVALID_INPUT_LENGTH              -0x0032

#define IOTEX_DES_KEY_SIZE    8

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(IOTEX_DES_ALT)
// Regular implementation
//

/**
 * \brief          DES context structure
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
typedef struct iotex_des_context
{
    uint32_t sk[32];            /*!<  DES subkeys       */
}
iotex_des_context;

/**
 * \brief          Triple-DES context structure
 */
typedef struct iotex_des3_context
{
    uint32_t sk[96];            /*!<  3DES subkeys      */
}
iotex_des3_context;

#else  /* IOTEX_DES_ALT */
#include "des_alt.h"
#endif /* IOTEX_DES_ALT */

/**
 * \brief          Initialize DES context
 *
 * \param ctx      DES context to be initialized
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void iotex_des_init( iotex_des_context *ctx );

/**
 * \brief          Clear DES context
 *
 * \param ctx      DES context to be cleared
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void iotex_des_free( iotex_des_context *ctx );

/**
 * \brief          Initialize Triple-DES context
 *
 * \param ctx      DES3 context to be initialized
 */
void iotex_des3_init( iotex_des3_context *ctx );

/**
 * \brief          Clear Triple-DES context
 *
 * \param ctx      DES3 context to be cleared
 */
void iotex_des3_free( iotex_des3_context *ctx );

/**
 * \brief          Set key parity on the given key to odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void iotex_des_key_set_parity( unsigned char key[IOTEX_DES_KEY_SIZE] );

/**
 * \brief          Check that key parity on the given key is odd.
 *
 *                 DES keys are 56 bits long, but each byte is padded with
 *                 a parity bit to allow verification.
 *
 * \param key      8-byte secret key
 *
 * \return         0 is parity was ok, 1 if parity was not correct.
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des_key_check_key_parity( const unsigned char key[IOTEX_DES_KEY_SIZE] );

/**
 * \brief          Check that key is not a weak or semi-weak DES key
 *
 * \param key      8-byte secret key
 *
 * \return         0 if no weak key was found, 1 if a weak key was identified.
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des_key_check_weak( const unsigned char key[IOTEX_DES_KEY_SIZE] );

/**
 * \brief          DES key schedule (56-bit, encryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 *
 * \return         0
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des_setkey_enc( iotex_des_context *ctx, const unsigned char key[IOTEX_DES_KEY_SIZE] );

/**
 * \brief          DES key schedule (56-bit, decryption)
 *
 * \param ctx      DES context to be initialized
 * \param key      8-byte secret key
 *
 * \return         0
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des_setkey_dec( iotex_des_context *ctx, const unsigned char key[IOTEX_DES_KEY_SIZE] );

/**
 * \brief          Triple-DES key schedule (112-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 *
 * \return         0
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des3_set2key_enc( iotex_des3_context *ctx,
                      const unsigned char key[IOTEX_DES_KEY_SIZE * 2] );

/**
 * \brief          Triple-DES key schedule (112-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      16-byte secret key
 *
 * \return         0
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des3_set2key_dec( iotex_des3_context *ctx,
                      const unsigned char key[IOTEX_DES_KEY_SIZE * 2] );

/**
 * \brief          Triple-DES key schedule (168-bit, encryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 *
 * \return         0
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des3_set3key_enc( iotex_des3_context *ctx,
                      const unsigned char key[IOTEX_DES_KEY_SIZE * 3] );

/**
 * \brief          Triple-DES key schedule (168-bit, decryption)
 *
 * \param ctx      3DES context to be initialized
 * \param key      24-byte secret key
 *
 * \return         0
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des3_set3key_dec( iotex_des3_context *ctx,
                      const unsigned char key[IOTEX_DES_KEY_SIZE * 3] );

/**
 * \brief          DES-ECB block encryption/decryption
 *
 * \param ctx      DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des_crypt_ecb( iotex_des_context *ctx,
                    const unsigned char input[8],
                    unsigned char output[8] );

#if defined(IOTEX_CIPHER_MODE_CBC)
/**
 * \brief          DES-CBC buffer encryption/decryption
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      DES context
 * \param mode     IOTEX_DES_ENCRYPT or IOTEX_DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des_crypt_cbc( iotex_des_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output );
#endif /* IOTEX_CIPHER_MODE_CBC */

/**
 * \brief          3DES-ECB block encryption/decryption
 *
 * \param ctx      3DES context
 * \param input    64-bit input block
 * \param output   64-bit output block
 *
 * \return         0 if successful
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des3_crypt_ecb( iotex_des3_context *ctx,
                     const unsigned char input[8],
                     unsigned char output[8] );

#if defined(IOTEX_CIPHER_MODE_CBC)
/**
 * \brief          3DES-CBC buffer encryption/decryption
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      3DES context
 * \param mode     IOTEX_DES_ENCRYPT or IOTEX_DES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or IOTEX_ERR_DES_INVALID_INPUT_LENGTH
 */
IOTEX_CHECK_RETURN_TYPICAL
int iotex_des3_crypt_cbc( iotex_des3_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[8],
                     const unsigned char *input,
                     unsigned char *output );
#endif /* IOTEX_CIPHER_MODE_CBC */

/**
 * \brief          Internal function for key expansion.
 *                 (Only exposed to allow overriding it,
 *                 see IOTEX_DES_SETKEY_ALT)
 *
 * \param SK       Round keys
 * \param key      Base key
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
void iotex_des_setkey( uint32_t SK[32],
                         const unsigned char key[IOTEX_DES_KEY_SIZE] );

#if defined(IOTEX_SELF_TEST)

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
IOTEX_CHECK_RETURN_CRITICAL
int iotex_des_self_test( int verbose );

#endif /* IOTEX_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* des.h */
