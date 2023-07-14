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
	ESP_LOGI(TAG, "W3bstream SDK example: Hash");
	ESP_LOGI(TAG, "This example shows how to use the W3bstream PSA Crypto API compute and "
				   "validate a hash using a one shot operation.");
	ESP_LOGI(TAG, "--------------------------------------------------------------------\n");

	// Initialize the library.
	psa_crypto_init();

	// Generate a random seed.
	default_SetSeed(esp_random());

	// Define a variable status that will be used to store the result of the PSA API calls.
	psa_status_t status = PSA_SUCCESS;

	// The data to hash.
	uint8_t message[4] = {0x01, 0x02, 0x03, 0x04};

	// A buffer where the computed hash will be stored.
	uint8_t hash[32] = {0};

	// A variable where the length of the computed hash will be stored.
	size_t hashLenght = 0;

	// Compute the hash using SHA256.
	status = psa_hash_compute(PSA_ALG_SHA_256, message, sizeof(message), hash, sizeof(hash),
							  &hashLenght);

	// Print the message and the computed hash.
	ESP_LOGI(TAG, "Message: ");
	ESP_LOG_BUFFER_HEX(TAG, message, sizeof(message));

	ESP_LOGI(TAG, "Hash (%d bytes):", hashLenght);
	ESP_LOG_BUFFER_HEX(TAG, hash, sizeof(hash));

	// Verify the hash
	status = psa_hash_compare(PSA_ALG_SHA_256, message, sizeof(message), hash, hashLenght);
	if(status != PSA_SUCCESS)
	{
		ESP_LOGI(TAG, "Error: psa_hash_compare failed. Status code:  %d", status);

		return;
	}
	else
	{
		ESP_LOGI(TAG, "Hash verified successfully.");
	}

	while(1) {

    	vTaskDelay(5000 / portTICK_PERIOD_MS);

    }
}

