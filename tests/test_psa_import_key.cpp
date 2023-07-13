#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaImportKey : public ::testing::Test
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
	void FillAllSlots()
	{
		for(int i = 0; i < IOTEX_PSA_KEY_SLOT_COUNT; i++)
		{
			// Import aes_ctr_key
			psa_key_id_t key_handle;
			psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
			psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
			psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
			psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
			psa_set_key_bits(&attributes, 128);
			psa_status_t status =
				psa_import_key(&attributes, aes_ctr_key, sizeof(aes_ctr_key), &key_handle);
			EXPECT_EQ(status, PSA_SUCCESS);
		}
	}

	const uint8_t aes_ctr_key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
};

TEST_F(PsaImportKey, BadState)
{
	psa_key_attributes_t attr;
	psa_key_id_t key;
	psa_status_t status = psa_import_key(&attr, NULL, 0, &key);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaImportKey, ZeroLengthKey)
{
	psa_key_attributes_t attr;
	psa_key_id_t key;
	uint8_t data[32];
	psa_crypto_init();
	psa_set_key_bits(&attr, 0);
	psa_status_t status = psa_import_key(&attr, data, sizeof(data), &key);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaImportKey, ZeroDataLength)
{
	psa_key_attributes_t attr;
	psa_key_id_t key;
	uint8_t data[32];
	psa_crypto_init();
	psa_set_key_bits(&attr, 128);
	psa_status_t status = psa_import_key(&attr, data, 0, &key);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaImportKey, NullData)
{
	psa_key_attributes_t attr;
	psa_key_id_t key;
	psa_crypto_init();
	psa_set_key_bits(&attr, 128);
	psa_status_t status = psa_import_key(&attr, NULL, 32, &key);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaImportKey, NoFreeSlots)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	uint8_t data[32];
	psa_crypto_init();
	FillAllSlots();
	psa_set_key_bits(&attr, 128);
	psa_status_t status = psa_import_key(&attr, data, sizeof(data), &key);
	EXPECT_EQ(status, PSA_ERROR_INSUFFICIENT_MEMORY);
}

TEST_F(PsaImportKey, AsymmetricPublicKey)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	uint8_t data[32];
	psa_crypto_init();
	psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
	psa_status_t status = psa_import_key(&attr, data, sizeof(data), &key);
	EXPECT_EQ(status, PSA_ERROR_NOT_SUPPORTED);
}

TEST_F(PsaImportKey, VendorDefinedKeyType)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	uint8_t data[32];
	psa_crypto_init();
	psa_set_key_type(&attr, PSA_KEY_TYPE_VENDOR_FLAG);
	psa_status_t status = psa_import_key(&attr, data, sizeof(data), &key);
	EXPECT_EQ(status, PSA_ERROR_NOT_SUPPORTED);
}

TEST_F(PsaImportKey, NoneKeyType)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	uint8_t data[32];
	psa_crypto_init();
	psa_set_key_type(&attr, PSA_KEY_TYPE_NONE);
	psa_status_t status = psa_import_key(&attr, data, sizeof(data), &key);
	EXPECT_EQ(status, PSA_ERROR_NOT_SUPPORTED);
}

TEST_F(PsaImportKey, PersistentKey)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	uint8_t data[32];
	psa_crypto_init();
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_PERSISTENT);
	psa_status_t status = psa_import_key(&attr, data, sizeof(data), &key);
	EXPECT_EQ(status, PSA_ERROR_NOT_SUPPORTED);
}

TEST_F(PsaImportKey, VolatileKey)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	uint8_t data[16];
	psa_crypto_init();
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_status_t status = psa_import_key(&attr, data, sizeof(data), &key);
	EXPECT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaImportKey, VolatileKeyInvalidBufferSize)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key;
	uint8_t data[32];
	psa_crypto_init();
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 128);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_status_t status = psa_import_key(&attr, data, sizeof(data), &key);
	// Should return an error because the size of the data buffer is not equal to 128 bits (key
	// bits)
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

// TODO test key location, algorithm, size for algorithm
// TODO Validate usage policies in source and target are compatible