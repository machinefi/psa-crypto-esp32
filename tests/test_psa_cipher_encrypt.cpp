#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaCipherEncrypt : public ::testing::Test
{
  protected:
	void SetUp() override
	{
	}
	void TearDown() override
	{
		reset_global_data();
		crypto_slot_management_reset_global_data();
	}

	const uint8_t aes_cbc_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
									 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	const uint8_t aes_ctr_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	const uint8_t iv_buf_cbc[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
									0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	const uint8_t iv_buf_ctr[16] = {0x22, 0x22, 0x1a, 0x70, 0x22, 0x22, 0x1a, 0x70,
									0x22, 0x22, 0x1a, 0x70, 0x22, 0x22, 0x1a, 0x70};
	uint8_t msg[64] = {0xd8, 0x65, 0xc9, 0xcd, 0xea, 0x33, 0x56, 0xc5, 0x48, 0x8e, 0x7b, 0xa1, 0x5e,
					   0x84, 0xf4, 0xeb, 0xa3, 0xb8, 0x25, 0x9c, 0x05, 0x3f, 0x24, 0xce, 0x29, 0x67,
					   0x22, 0x1c, 0x00, 0x38, 0x84, 0xd7, 0x9d, 0x4c, 0xa4, 0x87, 0x7f, 0xfa, 0x4b,
					   0xc6, 0x87, 0xc6, 0x67, 0xe5, 0x49, 0x5b, 0xcf, 0xec, 0x12, 0xf4, 0x87, 0x17,
					   0x32, 0xaa, 0xe4, 0x5a, 0x11, 0x06, 0x76, 0x11, 0x3d, 0xf9, 0xe7, 0xda};
	uint8_t ctr_output[80] = {// iv
							  0x22, 0x22, 0x1a, 0x70, 0x22, 0x22, 0x1a, 0x70, 0x22, 0x22, 0x1a,
							  0x70, 0x22, 0x22, 0x1a, 0x70,
							  // cipher text
							  0xb6, 0x72, 0xf2, 0xaf, 0x6a, 0xcc, 0x20, 0xae, 0xee, 0x1a, 0xd8,
							  0x14, 0x12, 0x8c, 0x31, 0x8b, 0x95, 0x5b, 0xbe, 0x80, 0x5b, 0x38,
							  0x92, 0x49, 0x89, 0x76, 0x00, 0xf5, 0x20, 0x74, 0x54, 0x32, 0x7d,
							  0x6d, 0x0f, 0xb4, 0xac, 0x0a, 0x94, 0xf3, 0x7c, 0xa0, 0x9e, 0x45,
							  0x05, 0x33, 0x98, 0xfe, 0xa8, 0x9c, 0x20, 0x0a, 0xd3, 0x58, 0x12,
							  0x6d, 0x9e, 0x89, 0xa4, 0x05, 0x26, 0x5c, 0x96, 0xe7};
};

TEST_F(PsaCipherEncrypt, BadState)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	uint8_t cipher_buf[80]; // Random IV + Ciphertext for single-part
	psa_status_t status = psa_cipher_encrypt(1, PSA_ALG_CTR, msg, sizeof(msg), cipher_buf,
											 sizeof(cipher_buf), &output_length);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaCipherEncrypt, InvalidKeyHandle)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	uint8_t cipher_buf[80]; // Random IV + Ciphertext for single-part
	psa_crypto_init();
	psa_status_t status = psa_cipher_encrypt(1, PSA_ALG_CTR, msg, sizeof(msg), cipher_buf,
											 sizeof(cipher_buf), &output_length);
	EXPECT_EQ(status, PSA_ERROR_INVALID_HANDLE);
}

TEST_F(PsaCipherEncrypt, InvalidAlgorithm)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	uint8_t cipher_buf[80]; // Random IV + Ciphertext for single-part
	psa_crypto_init();
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_CTR);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);
	psa_status_t status =
		psa_import_key(&key_attributes, aes_ctr_key, sizeof(aes_ctr_key), &key_handle);
	EXPECT_EQ(status, PSA_SUCCESS);
	status = psa_cipher_encrypt(key_handle, PSA_ALG_XTS, msg, sizeof(msg), cipher_buf,
								sizeof(cipher_buf), &output_length);
	EXPECT_EQ(status, PSA_ERROR_NOT_PERMITTED);
}

TEST_F(PsaCipherEncrypt, InvalidOutputSize)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	uint8_t cipher_buf[80]; // Random IV + Ciphertext for single-part
	psa_crypto_init();
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_CTR);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);
	psa_status_t status =
		psa_import_key(&key_attributes, aes_ctr_key, sizeof(aes_ctr_key), &key_handle);
	EXPECT_EQ(status, PSA_SUCCESS);
	status = psa_cipher_encrypt(key_handle, PSA_ALG_CTR, msg, sizeof(msg), cipher_buf, 79,
								&output_length);
	EXPECT_EQ(status, PSA_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(PsaCipherEncrypt, KeyUsageFlagNotSet)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	uint8_t cipher_buf[80]; // Random IV + Ciphertext for single-part
	psa_crypto_init();
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&key_attributes, 0);
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_CTR);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);
	psa_status_t status =
		psa_import_key(&key_attributes, aes_ctr_key, sizeof(aes_ctr_key), &key_handle);
	EXPECT_EQ(status, PSA_SUCCESS);
	status = psa_cipher_encrypt(key_handle, PSA_ALG_CTR, msg, sizeof(msg), cipher_buf,
								sizeof(cipher_buf), &output_length);
	EXPECT_EQ(status, PSA_ERROR_NOT_PERMITTED);
}

TEST_F(PsaCipherEncrypt, Success)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	uint8_t cipher_buf[80] = {0}; // Random IV + Ciphertext for single-part
	psa_crypto_init();
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_CTR);
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&key_attributes, 128);
	psa_status_t status =
		psa_import_key(&key_attributes, aes_ctr_key, sizeof(aes_ctr_key), &key_handle);
	EXPECT_EQ(status, PSA_SUCCESS);
	status = psa_cipher_encrypt(key_handle, PSA_ALG_CTR, msg, sizeof(msg), cipher_buf,
								sizeof(cipher_buf), &output_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(output_length, 80);
	uint8_t plain_buf[80] = {0};
	size_t plain_length = 0;
	status = psa_cipher_decrypt(key_handle, PSA_ALG_CTR, cipher_buf, sizeof(cipher_buf), plain_buf,
								sizeof(plain_buf), &plain_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(plain_length, 64);
	EXPECT_EQ(memcmp(plain_buf, msg, 64), 0);
}