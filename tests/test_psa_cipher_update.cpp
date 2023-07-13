#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaCipherUpdate : public ::testing::Test
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
		// Set the iv for the operation
		uint8_t iv[16] = {0};
		status = psa_cipher_set_iv(&operation, iv, sizeof(iv));
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

TEST_F(PsaCipherUpdate, NullInputArgument)
{
	uint8_t input[16] = {0};
	uint8_t output[16] = {0};
	size_t output_length = 0;
	psa_status_t status =
		psa_cipher_update(&operation, NULL, sizeof(input), output, 16, &output_length);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaCipherUpdate, NullOutputArgument)
{
	uint8_t input[16] = {0};
	size_t output_length = 0;
	psa_status_t status =
		psa_cipher_update(&operation, input, sizeof(input), NULL, 16, &output_length);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaCipherUpdate, NullOutputLengthArgument)
{
	uint8_t input[16] = {0};
	uint8_t output[16] = {0};
	psa_status_t status = psa_cipher_update(&operation, input, sizeof(input), output, 16, NULL);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaCipherUpdate, InvalidOutputSize)
{
	uint8_t input[16] = {0};
	uint8_t output[15] = {0};
	size_t output_length = 0;
	psa_status_t status =
		psa_cipher_update(&operation, input, sizeof(input), output, 15, &output_length);
	EXPECT_EQ(status, PSA_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(PsaCipherUpdate, Ok_SizeOfOutput_EqualToInput)
{
	uint8_t input[16] = {0};
	uint8_t output[16] = {0};
	size_t output_length = 0;
	psa_status_t status =
		psa_cipher_update(&operation, input, sizeof(input), output, sizeof(output), &output_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(output_length, sizeof(input));
}

TEST_F(PsaCipherUpdate, Ok_SizeOfOutput_GreaterThanInput)
{
	uint8_t input[64] = {0};
	uint8_t output[80] = {0};
	size_t output_length = 0;
	psa_status_t status =
		psa_cipher_update(&operation, input, sizeof(input), output, sizeof(output), &output_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(output_length, sizeof(input));
}

TEST_F(PsaCipherUpdate, MultipleUpdates)
{
	uint8_t input[32] = {0};
	uint8_t output[32] = {0};
	uint8_t block_size = 16;
	size_t output_length = 0;
	psa_status_t status =
		psa_cipher_update(&operation, input, block_size, output, sizeof(output), &output_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(output_length, block_size);
	status = psa_cipher_update(&operation, input + block_size, block_size, output,
							   sizeof(output) - block_size, &output_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(output_length, block_size);
}