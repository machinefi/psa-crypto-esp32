#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaHashClone : public ::testing::Test
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

TEST_F(PsaHashClone, BadState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_hash_operation_t clone = PSA_HASH_OPERATION_INIT;
	psa_status_t status = psa_hash_clone(&operation, &clone);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashClone, BadSourceOperationState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_hash_operation_t clone = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_status_t status = psa_hash_clone(&operation, &clone);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashClone, BadTargetOperationState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_hash_operation_t clone = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_hash_setup(&operation, PSA_ALG_SHA_256);
	psa_hash_setup(&clone, PSA_ALG_SHA_256);
	psa_status_t status = psa_hash_clone(&operation, &clone);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashClone, ClonesOperation)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_hash_operation_t clone = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_hash_setup(&operation, PSA_ALG_SHA_256);
	psa_status_t status = psa_hash_clone(&operation, &clone);
	EXPECT_EQ(status, PSA_SUCCESS);
	psa_hash_update(&operation, (const uint8_t*)"test", 4);
	EXPECT_EQ(status, PSA_SUCCESS);
	psa_hash_update(&clone, (const uint8_t*)"test", 4);
	EXPECT_EQ(status, PSA_SUCCESS);
	uint8_t hash[32];
	size_t hash_length = 0;
	status = psa_hash_finish(&operation, hash, sizeof(hash), &hash_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(hash_length, 32);
	uint8_t clone_hash[32];
	size_t clone_hash_length = 0;
	status = psa_hash_finish(&clone, clone_hash, sizeof(clone_hash), &clone_hash_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(clone_hash_length, 32);
	EXPECT_EQ(memcmp(hash, clone_hash, 32), 0);
}