#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaCopyKey : public ::testing::Test
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
		psa_crypto_init();
		*attr = PSA_KEY_ATTRIBUTES_INIT;
		psa_set_key_usage_flags(attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_algorithm(attr, PSA_ALG_CTR);
		psa_set_key_type(attr, PSA_KEY_TYPE_AES);
		psa_set_key_bits(attr, 128);
		psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_VOLATILE);
		if(allowCopy)
		{
			psa_set_key_usage_flags(attr, PSA_KEY_USAGE_COPY);
		}
		psa_status_t status = psa_import_key(attr, aes_ctr_key, sizeof(aes_ctr_key), source_key);
		EXPECT_EQ(status, PSA_SUCCESS);
	}

	void FillAllSlots()
	{
		for(int i = 0; i < IOTEX_PSA_KEY_SLOT_COUNT - 1; i++)
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

TEST_F(PsaCopyKey, BadState)
{
	psa_key_id_t source_key;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaCopyKey, InvalidSourceKey)
{
	psa_key_id_t source_key = 0;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_crypto_init();
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_ERROR_INVALID_HANDLE);
}

TEST_F(PsaCopyKey, NoFreeSlots)
{
	psa_key_id_t source_key;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportAesKey(&source_key, &attr);
	FillAllSlots();
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_ERROR_INSUFFICIENT_MEMORY);
}

TEST_F(PsaCopyKey, SourceKeyDoesNotAllowCopy)
{
	psa_key_id_t source_key;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportAesKey(&source_key, &attr, false);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_COPY);
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_ERROR_NOT_PERMITTED);
}

TEST_F(PsaCopyKey, DifferentKeySizes)
{
	psa_key_id_t source_key;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportAesKey(&source_key, &attr);
	psa_set_key_bits(&attr, 256);
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaCopyKey, SameKeySize)
{
	psa_key_id_t source_key;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportAesKey(&source_key, &attr);
	psa_set_key_bits(&attr, 128);
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaCopyKey, NoOptionalKeySize)
{
	psa_key_id_t source_key;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportAesKey(&source_key, &attr);
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaCopyKey, NoOptionalKeyType)
{
	psa_key_id_t source_key;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportAesKey(&source_key, &attr);
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaCopyKey, SameKeyType)
{
	psa_key_id_t source_key;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportAesKey(&source_key, &attr);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaCopyKey, DifferentKeyType)
{
	psa_key_id_t source_key;
	psa_key_id_t target_key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportAesKey(&source_key, &attr);
	psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_status_t status = psa_copy_key(source_key, &attr, &target_key);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

// TODO Test key location, algorithm, size are combined from source and input attributes and
// verified
// TODO Test key type. If none, it must be set to the source key type
// TODO Test validation of compatibility of usage policies in source and target key