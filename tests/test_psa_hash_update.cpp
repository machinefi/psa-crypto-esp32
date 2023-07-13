#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaHashUpdate : public ::testing::Test
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

TEST_F(PsaHashUpdate, BadState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_status_t status = psa_hash_update(&operation, NULL, 0);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashUpdate, BadOperationState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_status_t status = psa_hash_update(&operation, NULL, 0);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashUpdate, ZeroInputLength)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	ASSERT_EQ(status, PSA_SUCCESS);
	status = psa_hash_update(&operation, NULL, 0);
	EXPECT_EQ(status, PSA_SUCCESS);
}

TEST_F(PsaHashUpdate, NullInputButLengthNotZero)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	ASSERT_EQ(status, PSA_SUCCESS);
	status = psa_hash_update(&operation, NULL, 1);
	EXPECT_EQ(status, PSA_ERROR_INVALID_ARGUMENT);
}

TEST_F(PsaHashUpdate, Ok)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	ASSERT_EQ(status, PSA_SUCCESS);
	status = psa_hash_update(&operation, (const uint8_t*)"abc", 3);
	EXPECT_EQ(status, PSA_SUCCESS);
}
