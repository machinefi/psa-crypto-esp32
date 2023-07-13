#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaHashSetup : public ::testing::Test
{
  protected:
	void SetUp() override
	{
	}
	void TearDown() override
	{
		reset_global_data();
	}
};

TEST_F(PsaHashSetup, BadState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashSetup, InvalidHashAlgorithm)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_status_t status = psa_hash_setup(&operation, PSA_ALG_MD5);
	EXPECT_EQ(status, PSA_ERROR_NOT_SUPPORTED);
}

TEST_F(PsaHashSetup, NotAHashAlgorithm)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_status_t status = psa_hash_setup(&operation, PSA_ALG_CBC_NO_PADDING);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}