#include <stdio.h>

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

extern void default_SetSeed(unsigned int seed);
void app_main(void)
{
	ESP_LOGI(TAG, "W3bstream SDK example: Random number generation");
	ESP_LOGI(TAG, 
		"This example shows how to use the W3bstream PSA Crypto API to generate random values.");
	ESP_LOGI(TAG, "Note: This example is only for demonstration purposes. Production applications "
				   "should seed the random generator with enough entropy.");
	ESP_LOGI(TAG, "--------------------------------------------------------------------");

	// Initialize the library.
	psa_crypto_init();

	// Set the random generator seed.
	// Note: This is only for demonstration purposes and not a true random seed.
	// The random seed should be set to a true random value in a production application.
	default_SetSeed(esp_random());

	// Generate 10 random bytes.
	ESP_LOGI(TAG, "Generating 10 random bytes");
	uint8_t random[10] = {0};
	psa_status_t status = psa_generate_random(random, sizeof(random));
	if(status != PSA_SUCCESS)
	{
		printf(TAG, "Error: psa_generate_random failed.");
		printf(TAG, "Status code: %d", status);
		
		return;
	}

	// Print the random bytes.
	ESP_LOGI(TAG, "Random bytes:");

	for(int i = 0; i < sizeof(random); i++)
	{
		ESP_LOGI(TAG, "%.2x ", random[i]);
	}

    while(1) {

    	vTaskDelay(5000 / portTICK_PERIOD_MS);

    }	
}

