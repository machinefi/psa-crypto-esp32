#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaHashAbort : public ::testing::Test
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

TEST_F(PsaHashAbort, Success)
{
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_crypto_init();
	psa_hash_setup(&operation, PSA_ALG_SHA_256);
	psa_status_t status = psa_hash_abort(&operation);
	EXPECT_EQ(status, PSA_SUCCESS);
}