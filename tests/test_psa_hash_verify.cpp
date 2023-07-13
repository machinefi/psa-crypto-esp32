#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaHashVerify : public ::testing::Test
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

TEST_F(PsaHashVerify, BadState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	uint8_t hash[32] = {0};
	psa_status_t status = psa_hash_verify(&operation, hash, 32);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashVerify, BadOperationState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	uint8_t hash[32] = {0};
	psa_crypto_init();
	psa_status_t status = psa_hash_verify(&operation, hash, 32);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashVerify, BadHashLength)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	uint8_t hash[32] = {0};
	psa_crypto_init();
	psa_hash_setup(&operation, PSA_ALG_SHA_256);
	psa_status_t status = psa_hash_verify(&operation, hash, 31);
	EXPECT_EQ(status, PSA_ERROR_INVALID_SIGNATURE);
}

TEST_F(PsaHashVerify, VarificationFailed)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	uint8_t hash[32] = {0};
	psa_crypto_init();
	psa_hash_setup(&operation, PSA_ALG_SHA_256);
	psa_status_t status = psa_hash_update(&operation, (const uint8_t*)"test", 4);
	EXPECT_EQ(status, PSA_SUCCESS);
	status = psa_hash_verify(&operation, hash, 32);
	EXPECT_EQ(status, PSA_ERROR_INVALID_SIGNATURE);
}

TEST_F(PsaHashVerify, VarificationSuccessful)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_hash_setup(&operation, PSA_ALG_SHA_256);
	uint8_t hash[] = {0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea,
					  0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b,
					  0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08};
	psa_status_t status = psa_hash_update(&operation, (const uint8_t*)"test", 4);
	EXPECT_EQ(status, PSA_SUCCESS);
	status = psa_hash_verify(&operation, hash, 32);
	EXPECT_EQ(status, PSA_SUCCESS);
}