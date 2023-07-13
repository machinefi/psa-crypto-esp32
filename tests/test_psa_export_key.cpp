#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaExportKey : public ::testing::Test
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

	uint8_t private_key[32] = {0xa2, 0x6f, 0x81, 0x89, 0x4a, 0x38, 0x69, 0x9d, 0x5a, 0xb2, 0x2c,
							   0x66, 0x71, 0x01, 0xcb, 0x74, 0x53, 0x36, 0x16, 0x03, 0x6c, 0xed,
							   0x6e, 0x46, 0x3b, 0xaa, 0x36, 0x3f, 0x36, 0xff, 0x3d, 0x64};
	uint8_t public_key[65] = {0x04, 0x10, 0x96, 0x6a, 0xe7, 0x6f, 0xbb, 0xb0, 0xca, 0x4c, 0x38,
							  0x08, 0xb4, 0x53, 0xaf, 0x40, 0xa6, 0x97, 0xf3, 0x6e, 0x7d, 0x9d,
							  0x2b, 0x5c, 0x00, 0x32, 0xf9, 0xb0, 0x9e, 0x39, 0xd9, 0x63, 0xa6,
							  0x0c, 0x6a, 0x43, 0x57, 0xaa, 0x76, 0xb2, 0x5f, 0xa7, 0x02, 0xb3,
							  0x8d, 0x17, 0x36, 0x4d, 0xdd, 0x6e, 0x54, 0xa2, 0xd8, 0x3f, 0x9d,
							  0x4f, 0x15, 0xbc, 0x58, 0x87, 0xe1, 0xe3, 0xfa, 0xe2, 0x70};

	void ImportEccKey(psa_key_id_t* source_key, psa_key_attributes_t* attr, bool allowExport = true)
	{
		psa_crypto_init();
		psa_set_key_algorithm(attr, PSA_ALG_ECDSA_ANY);
		psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(attr, 256);
		psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_VOLATILE);
		if(allowExport)
		{
			psa_set_key_usage_flags(attr, PSA_KEY_USAGE_EXPORT);
		}
		psa_status_t status = psa_import_key(attr, private_key, sizeof(private_key), source_key);
		ASSERT_EQ(status, PSA_SUCCESS);
	}
};

TEST_F(PsaExportKey, BadState)
{
	psa_key_id_t key = 1;
	uint8_t buf[32] = {0};
	size_t exported_lenght = 0;
	psa_status_t status = psa_export_key(key, buf, sizeof(buf), &exported_lenght);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaExportKey, BadHandle)
{
	psa_key_id_t key = 1;
	uint8_t buf[32] = {0};
	size_t exported_lenght = 0;
	psa_crypto_init();
	psa_status_t status = psa_export_key(key, buf, sizeof(buf), &exported_lenght);
	EXPECT_EQ(status, PSA_ERROR_INVALID_HANDLE);
}

TEST_F(PsaExportKey, ExportFlagNotSet)
{
	psa_key_id_t key = 1;
	uint8_t buf[32] = {0};
	size_t exported_lenght = 0;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportEccKey(&key, &attr, false);
	psa_status_t status = psa_export_key(key, buf, sizeof(buf), &exported_lenght);
	EXPECT_EQ(status, PSA_ERROR_NOT_PERMITTED);
}

TEST_F(PsaExportKey, BufferSizeTooSmall)
{
	psa_key_id_t key = 1;
	uint8_t buf[32] = {0};
	size_t exported_lenght = 0;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportEccKey(&key, &attr);
	psa_status_t status = psa_export_key(key, buf, 31, &exported_lenght);
	EXPECT_EQ(status, PSA_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(PsaExportKey, EccKey)
{
	psa_key_id_t key = 1;
	uint8_t buf[32] = {0};
	size_t exported_lenght = 0;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	ImportEccKey(&key, &attr);
	psa_status_t status = psa_export_key(key, buf, sizeof(buf), &exported_lenght);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(exported_lenght, 32);
	EXPECT_EQ(memcmp(buf, private_key, exported_lenght), 0);
}