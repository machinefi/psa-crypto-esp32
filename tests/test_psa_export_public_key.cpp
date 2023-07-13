#include "PSACrypto.h"
#include "test_helpers.h"
#include <algorithm>
#include <gtest/gtest.h>
#include <string>

class PsaExportPublicKey : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// Convert private_key_str and public_key_str to upper case
		std::transform(private_key_str.begin(), private_key_str.end(), private_key_str.begin(),
					   ::toupper);
		std::transform(public_key_str.begin(), public_key_str.end(), public_key_str.begin(),
					   ::toupper);

		// Convert private_key_str and public_key_str to byte arrays
		hex_string_to_byte_array(private_key_str, private_key, sizeof(private_key));
		hex_string_to_byte_array(public_key_str, public_key, sizeof(public_key));
	}

	void TearDown() override
	{
		reset_global_data();
		crypto_slot_management_reset_global_data();
	}

	std::string private_key_str =
		"7B9E3432DEE7B1CEB719496D30B86A76CC34B6815919328099468DD9A99DC01C";
	std::string public_key_str =
		"04d3e3555d86d404fa937c1dff8ce3f1777dc11a0e7ff972cab0ef8f7efc62267949d639fceebfcb1c3495f50c"
		"5694d716b7d6443e2a50baf46ac5fee6b6652206";
	uint8_t private_key[32] = {};
	uint8_t public_key[65] = {};

	void ImportEccKey(psa_key_id_t* source_key, psa_key_attributes_t* attr, bool allowExport = true)
	{
		psa_crypto_init();
		psa_set_key_algorithm(attr, PSA_ALG_ECDSA_ANY);
		psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
		psa_set_key_bits(attr, 256);
		psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_VOLATILE);
		if(allowExport)
		{
			psa_set_key_usage_flags(attr, PSA_KEY_USAGE_EXPORT);
		}
		psa_status_t status = psa_import_key(attr, private_key, sizeof(private_key), source_key);
		ASSERT_EQ(status, PSA_SUCCESS);
	}

	void hex_string_to_byte_array(std::string& in, uint8_t* out, size_t size)
	{
		std::string hex = in;
		hex.erase(std::remove(hex.begin(), hex.end(), ' '), hex.end());
		for(size_t i = 0; i < size; ++i)
		{
			std::string byteString = hex.substr(i * 2, 2);
			out[i] = (uint8_t)strtol(byteString.c_str(), NULL, 16);
		}
	}
};

TEST_F(PsaExportPublicKey, BadState)
{
	psa_key_id_t source_key = 0;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t buffer[65] = {0};
	size_t buffer_size = 0;
	psa_status_t status = psa_export_public_key(source_key, buffer, sizeof(buffer), &buffer_size);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaExportPublicKey, BadHandle)
{
	psa_key_id_t source_key = 0;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t buffer[65] = {0};
	size_t buffer_size = 0;
	psa_status_t status = psa_export_public_key(source_key, buffer, sizeof(buffer), &buffer_size);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaExportPublicKey, ExportFlagNotSet)
{
	psa_key_id_t source_key = 0;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t buffer[65] = {0};
	size_t buffer_size = 0;
	ImportEccKey(&source_key, &attr, false);
	psa_status_t status = psa_export_public_key(source_key, buffer, sizeof(buffer), &buffer_size);
	// Exporting a public key does not require usage flags. So this should succeed.
	EXPECT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaExportPublicKey, BufferSizeTooSmall)
{
	psa_key_id_t source_key = 0;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t buffer[65] = {0};
	size_t buffer_size = 0;
	ImportEccKey(&source_key, &attr);
	auto expected_size =
		PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256);
	psa_status_t status =
		psa_export_public_key(source_key, buffer, expected_size - 1, &buffer_size);
	EXPECT_EQ(status, PSA_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(PsaExportPublicKey, EccKey)
{
	psa_key_id_t source_key = 0;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t buffer[65] = {0};
	size_t buffer_size = 0;
	ImportEccKey(&source_key, &attr);
	psa_status_t status = psa_export_public_key(source_key, buffer, sizeof(buffer), &buffer_size);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(buffer_size, sizeof(public_key));
	EXPECT_EQ(memcmp(buffer, public_key, sizeof(public_key)), 0);
}