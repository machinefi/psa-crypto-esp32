#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaCipherGenerateIv : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		psa_crypto_init();
		// Import aes_ctr_key
		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
		psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
		psa_set_key_bits(&attributes, 128);
		psa_status_t status =
			psa_import_key(&attributes, aes_ctr_key, sizeof(aes_ctr_key), &key_handle);
		EXPECT_EQ(status, PSA_SUCCESS);
		// Setup cipher operation
		status = psa_cipher_encrypt_setup(&operation, key_handle, PSA_ALG_CTR);
		EXPECT_EQ(status, PSA_SUCCESS);
	}
	void TearDown() override
	{
		reset_global_data();
		crypto_slot_management_reset_global_data();
	}

	const uint8_t aes_ctr_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	psa_key_handle_t key_handle = 0;
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
};

TEST_F(PsaCipherGenerateIv, NullIvArgument)
{
	size_t output_length = 0;
	uint8_t iv[16] = {0};
	size_t iv_length = 0;
	psa_status_t status = psa_cipher_generate_iv(&operation, NULL, sizeof(iv), &iv_length);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaCipherGenerateIv, BufferTooSmall)
{
	size_t output_length = 0;
	uint8_t iv[16] = {0};
	size_t iv_length = 0;
	psa_status_t status = psa_cipher_generate_iv(&operation, iv, 15, &iv_length);
	EXPECT_EQ(status, PSA_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(PsaCipherGenerateIv, Success)
{
	size_t output_length = 0;
	uint8_t iv[16] = {0};
	size_t iv_length = 0;
	psa_status_t status = psa_cipher_generate_iv(&operation, iv, sizeof(iv), &iv_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(iv_length, 16);
}