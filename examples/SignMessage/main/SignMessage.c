#include "esp_random.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_sntp.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "PSACrypto.h"

static const char *TAG = "";

void app_main(void)
{
	ESP_LOGI(TAG, "W3bstream SDK example: Sign message");
	ESP_LOGI(TAG, "This example shows how to use the W3bstream PSA Crypto API to sign a message "
				   "using the Secp256r1 Elliptic Curve.");
	ESP_LOGI(TAG, "--------------------------------------------------------------------\n");

	// Initialize the library.
	psa_crypto_init();

	// Generate a random seed.
	default_SetSeed(esp_random());	

	// Define a variable status that will be used to store the result of the PSA API calls.
	psa_status_t status = PSA_SUCCESS;

	// Define a variable that will be used to store the key identifier.
	psa_key_id_t keyId = 0;

	// Generate an ECDS SECP256R1 key pair.
	ESP_LOGI(TAG, "Generating a key pair");
	psa_key_attributes_t keyAttributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&keyAttributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH |
												PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&keyAttributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&keyAttributes, 256);
	status = psa_generate_key(&keyAttributes, &keyId);
	if(status != PSA_SUCCESS)
	{
		ESP_LOGI(TAG, "Error: psa_generate_key failed. Status code: %d", status);
		return;
	}

	// Print the key bytes as a hex string.
	uint8_t key[32] = {0};
	size_t keyLength = 0;
	status = psa_export_key(keyId, key, sizeof(key), &keyLength);
	if(status != PSA_SUCCESS)
	{
		ESP_LOGI(TAG, "Error: psa_export_key failed. Status code: %d", status);
		return;
	}
	ESP_LOGI(TAG, "Key: ");
	ESP_LOG_BUFFER_HEX(TAG, key, keyLength);

	// Sign a message.
	uint8_t message[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
	ESP_LOGI(TAG, "Signing message:");
	ESP_LOG_BUFFER_HEX(TAG, message, sizeof(message));

	uint8_t signature[64] = {0};
	size_t signatureLength = 0;
	status = psa_sign_message(keyId, PSA_ALG_ECDSA(PSA_ALG_SHA_256), message, sizeof(message),
							  signature, sizeof(signature), &signatureLength);
	if(status != PSA_SUCCESS)
	{
		ESP_LOGI(TAG, "Error: psa_sign_message failed. Status code: %d", status);
		return;
	}

	// Print the signature.
	ESP_LOGI(TAG, "Signature: ");
	ESP_LOG_BUFFER_HEX(TAG, signature, signatureLength);

	// Verify the signature.
	ESP_LOGI(TAG, "Verifying signature");
	status = psa_verify_message(keyId, PSA_ALG_ECDSA(PSA_ALG_SHA_256), message, sizeof(message),
								signature, signatureLength);
	if(status != PSA_SUCCESS)
	{
		ESP_LOGI(TAG, "Error: psa_verify_message failed. Status code: %d", status);
		return;
	}

	ESP_LOGI(TAG, "Signature verified successfully");

    while(1) {

    	vTaskDelay(5000 / portTICK_PERIOD_MS);

    }	
}

