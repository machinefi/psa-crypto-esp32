#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaGenerateKey : public ::testing::Test
{
  protected:
	void SetUp() override
	{
	}
	void TearDown() override
	{
		// reset_global_data();
		// crypto_slot_management_reset_global_data();
	}
};

TEST_F(PsaGenerateKey, BadState)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

	psa_status_t status = psa_generate_key(&attr, &key);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaGenerateKey, ZeroLengthKey)
{
	psa_key_attributes_t attr;
	psa_key_id_t key;
	psa_crypto_init();
	psa_set_key_bits(&attr, 0);
	psa_status_t status = psa_generate_key(&attr, &key);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaGenerateKey, AsymmetricPublicKey)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	psa_crypto_init();
	psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
	psa_status_t status = psa_generate_key(&attr, &key);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaGenerateKey, VendorDefinedKeyType)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	psa_crypto_init();
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_VENDOR_FLAG);
	psa_status_t status = psa_generate_key(&attr, &key);
	EXPECT_EQ(status, PSA_ERROR_NOT_SUPPORTED);
}

TEST_F(PsaGenerateKey, NoneKeyType)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	psa_crypto_init();
	psa_set_key_type(&attr, PSA_KEY_TYPE_NONE);
	psa_status_t status = psa_generate_key(&attr, &key);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaGenerateKey, PersistentKey)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	psa_crypto_init();
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
	psa_status_t status = psa_generate_key(&attr, &key);
	EXPECT_EQ(status, PSA_ERROR_NOT_SUPPORTED);
}

TEST_F(PsaGenerateKey, VolatileKey)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key = 0;
	psa_crypto_init();
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_status_t status = psa_generate_key(&attr, &key);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_NE(key, 0);
	psa_destroy_key(key);
}

// TODO Test validation of key size for each algorithm
// TODO Test validation of algorithm