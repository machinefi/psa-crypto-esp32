#include "PSACrypto.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

class PsaGenerateRandomTest : public ::testing::Test
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

TEST_F(PsaGenerateRandomTest, GenerateRandom)
{
	uint8_t output[16];
	size_t output_size = sizeof(output);
	psa_crypto_init();
	psa_status_t status = psa_generate_random(output, output_size);
	EXPECT_EQ(PSA_SUCCESS, status);
}

TEST_F(PsaGenerateRandomTest, BadState)
{
	uint8_t output[16];
	size_t output_size = sizeof(output);
	// NOTE: the call to psa_crypto_init() was ommited
	psa_status_t status = psa_generate_random(output, output_size);
	EXPECT_EQ(PSA_ERROR_BAD_STATE, status);
}