#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaCipherDecryptSetup : public ::testing::Test
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

	const uint8_t aes_ctr_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
};

TEST_F(PsaCipherDecryptSetup, BadState)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	psa_status_t status = psa_cipher_decrypt_setup(&operation, 0, PSA_ALG_CTR);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaCipherDecryptSetup, InvalidKeyHandle)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	psa_crypto_init();
	psa_status_t status = psa_cipher_decrypt_setup(&operation, 1, PSA_ALG_CTR);
	EXPECT_EQ(status, PSA_ERROR_INVALID_HANDLE);
}

TEST_F(PsaCipherDecryptSetup, InvalidAlgorithm)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	psa_crypto_init();
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, 128);
	psa_status_t status =
		psa_import_key(&attributes, aes_ctr_key, sizeof(aes_ctr_key), &key_handle);
	ASSERT_EQ(status, PSA_SUCCESS);
	status = psa_cipher_decrypt_setup(&operation, key_handle, PSA_ALG_XTS);
	EXPECT_EQ(status, PSA_ERROR_NOT_PERMITTED);
}

TEST_F(PsaCipherDecryptSetup, InvalidKeyUsage)
{
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
	size_t output_length = 0;
	psa_crypto_init();
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, 128);
	psa_status_t status =
		psa_import_key(&attributes, aes_ctr_key, sizeof(aes_ctr_key), &key_handle);
	ASSERT_EQ(status, PSA_SUCCESS);
	status = psa_cipher_decrypt_setup(&operation, key_handle, PSA_ALG_CTR);
	EXPECT_EQ(status, PSA_ERROR_NOT_PERMITTED);
}