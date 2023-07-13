#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaHashFinish : public ::testing::Test
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

TEST_F(PsaHashFinish, BadState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	uint8_t buf[32];
	size_t hash_length = 0;
	psa_status_t status = psa_hash_finish(&operation, buf, 32, &hash_length);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashFinish, BadOperationState)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	uint8_t buf[32];
	size_t hash_length = 0;
	psa_crypto_init();
	psa_status_t status = psa_hash_finish(&operation, buf, 32, &hash_length);
	EXPECT_EQ(status, PSA_ERROR_BAD_STATE);
}

TEST_F(PsaHashFinish, InvalidBufferSize)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	uint8_t buf[32];
	size_t hash_length = 0;
	psa_crypto_init();
	psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	ASSERT_EQ(status, PSA_SUCCESS);
	status = psa_hash_finish(&operation, buf, 31, &hash_length);
	EXPECT_EQ(status, PSA_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(PsaHashFinish, ComputesHashInOneStep)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	ASSERT_EQ(status, PSA_SUCCESS);
	uint8_t hash[32] = {0};
	size_t hash_length = 0;
	uint8_t expected_hash[] = {0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea,
							   0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b,
							   0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08};
	status = psa_hash_update(&operation, (const uint8_t*)"test", 4);
	EXPECT_EQ(status, PSA_SUCCESS);
	status = psa_hash_finish(&operation, hash, sizeof(hash), &hash_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(hash_length, 32);
	EXPECT_EQ(memcmp(hash, expected_hash, hash_length), 0);
}

TEST_F(PsaHashFinish, ComputesHashInTwoSteps)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_status_t status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
	ASSERT_EQ(status, PSA_SUCCESS);
	uint8_t hash[32] = {0};
	size_t hash_length = 0;
	uint8_t expected_hash[] = {0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea,
							   0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b,
							   0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08};
	status = psa_hash_update(&operation, (const uint8_t*)"te", 2);
	EXPECT_EQ(status, PSA_SUCCESS);
	status = psa_hash_update(&operation, (const uint8_t*)"st", 2);
	EXPECT_EQ(status, PSA_SUCCESS);
	status = psa_hash_finish(&operation, hash, sizeof(hash), &hash_length);
	EXPECT_EQ(status, PSA_SUCCESS);
	EXPECT_EQ(hash_length, 32);
	EXPECT_EQ(memcmp(hash, expected_hash, hash_length), 0);
}
