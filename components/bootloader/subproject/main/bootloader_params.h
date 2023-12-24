#pragma once

#include <stdint.h>

#ifndef FACTORY_INDEX
#define FACTORY_INDEX (-1)
#endif
#ifndef TEST_APP_INDEX
#define TEST_APP_INDEX (-2)
#endif

typedef struct {
  int8_t   partition_index;
  uint8_t  _[CONFIG_BOOTLOADER_CUSTOM_RESERVE_RTC_SIZE - 1];
} bootloader_params_t;

 enum { BOOTLOADER_PARAMS_IS_CONFIGURED = 1/!!(sizeof(bootloader_params_t) == CONFIG_BOOTLOADER_CUSTOM_RESERVE_RTC_SIZE) };