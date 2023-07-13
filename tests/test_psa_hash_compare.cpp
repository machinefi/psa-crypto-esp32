#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaHashCompare : public ::testing::Test
{
  protected:
	void SetUp() override
	{
	}
	void TearDown() override
	{
		reset_global_data();
	}

	// Hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
	const uint8_t hash[32] = {0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea,
							  0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b,
							  0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08};
	const uint8_t wrongHash[32] = {0x00, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea,
								   0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b,
								   0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08};
	const uint8_t msg[4] = {'t', 'e', 's', 't'};
};

TEST_F(PsaHashCompare, BadState)
{
	psa_hash_operation_t operation;
	psa_status_t status = psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash));
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashCompare, InvalidHashAlgorithm)
{
	psa_hash_operation_t operation;
	psa_crypto_init();
	psa_status_t status = psa_hash_compare(PSA_ALG_MD5, msg, sizeof(msg), hash, sizeof(hash));
	EXPECT_EQ(status, PSA_ERROR_NOT_SUPPORTED);
}

TEST_F(PsaHashCompare, NotAHashAlgorithm)
{
	psa_hash_operation_t operation;
	psa_crypto_init();
	psa_status_t status =
		psa_hash_compare(PSA_ALG_CBC_NO_PADDING, msg, sizeof(msg), hash, sizeof(hash));
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaHashCompare, InputHashHasWrongSize)
{
	psa_hash_operation_t operation;
	psa_crypto_init();
	psa_status_t status =
		psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash) - 1);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaHashCompare, CorrectHash)
{
	psa_hash_operation_t operation;
	psa_crypto_init();
	psa_status_t status = psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash));
	EXPECT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaHashCompare, InCorrectHash)
{
	psa_hash_operation_t operation;
	psa_crypto_init();
	psa_status_t status =
		psa_hash_compare(PSA_ALG_SHA_256, msg, sizeof(msg), wrongHash, sizeof(wrongHash));
	EXPECT_EQ(status, PSA_ERROR_INVALID_SIGNATURE);
}