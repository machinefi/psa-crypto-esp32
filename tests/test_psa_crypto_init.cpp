#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaCryptoInitTest : public ::testing::Test
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
};

TEST_F(PsaCryptoInitTest, SetsInitializedFlag)
{
	psa_status_t status = psa_crypto_init();
	EXPECT_EQ(PSA_SUCCESS, status);
	EXPECT_TRUE(global_data_is_initialized());
}

TEST_F(PsaCryptoInitTest, DoubleInitialization)
{
	psa_status_t status = psa_crypto_init();
	EXPECT_EQ(PSA_SUCCESS, status);
	status = psa_crypto_init();
	ASSERT_EQ(PSA_SUCCESS, status);
}

TEST_F(PsaCryptoInitTest, DoubleInitializationDoesNotResetKeyslots)
{
	psa_status_t status = psa_crypto_init();
	EXPECT_EQ(PSA_SUCCESS, status);

	uint8_t aes_ctr_key[16] = {0};
	psa_key_handle_t key_handle = 0;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, 128);
	status = psa_import_key(&attributes, aes_ctr_key, sizeof(aes_ctr_key), &key_handle);
	ASSERT_EQ(status, PSA_SUCCESS);

	status = psa_crypto_init();
	ASSERT_EQ(PSA_SUCCESS, status);

	// The key should still be present
	uint8_t buf[32] = {0};
	size_t exported_lenght = 0;
	status = psa_export_key(key_handle, buf, sizeof(buf), &exported_lenght);
	ASSERT_EQ(status, PSA_SUCCESS);
}

// TODO Test entropy initialization