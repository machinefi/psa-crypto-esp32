#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaDestroyKey : public ::testing::Test
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

	void ImportAesKey(psa_key_id_t* source_key, psa_key_attributes_t* attr, bool allowCopy = true)
	{
		uint8_t aes_ctr_key[16] = {0};
		psa_crypto_init();
		psa_set_key_usage_flags(attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_algorithm(attr, PSA_ALG_CTR);
		psa_set_key_type(attr, PSA_KEY_TYPE_AES);
		psa_set_key_bits(attr, 128);
		psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_status_t status = psa_import_key(attr, aes_ctr_key, sizeof(aes_ctr_key), source_key);
		ASSERT_EQ(status, PSA_SUCCESS);
	}
};

TEST_F(PsaDestroyKey, BadState)
{
	psa_status_t status = psa_destroy_key(1);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaDestroyKey, InvalidHandle)
{
	psa_crypto_init();
	psa_status_t status = psa_destroy_key(1);
	EXPECT_EQ(status, PSA_ERROR_INVALID_HANDLE);
}

TEST_F(PsaDestroyKey, NullHandle)
{
	psa_crypto_init();
	psa_status_t status = psa_destroy_key(PSA_KEY_ID_NULL);
	EXPECT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaDestroyKey, DestroysKeyMaterial)
{
	psa_key_id_t handle;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportAesKey(&handle, &attr);
	psa_status_t status = psa_destroy_key(handle);
	EXPECT_EQ(status, PSA_SUCCESS);

	// Exporting the key should fail
	uint8_t key_data[16];
	size_t key_data_length = 0;
	status = psa_export_key(handle, key_data, sizeof(key_data), &key_data_length);
	EXPECT_EQ(status, PSA_ERROR_INVALID_HANDLE);
}
