#ifndef __IOTEX_HAL_NVS_ESP32___
#define __IOTEX_HAL_NVS_ESP32___

#include "hal/nvs/nvs_common.h"

#define IOTEX_HAL_NVS_NAMESPACE_MAX_LENGTH  15

extern nvs_drv esp32_nvs;

int esp32_hal_nvs_init(void);

#endif