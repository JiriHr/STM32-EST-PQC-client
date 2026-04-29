#ifndef RANDOMBYTES_STM32_H
#define RANDOMBYTES_STM32_H

#include "stm32wbxx_hal.h"

int randombytes_stm32_init(RNG_HandleTypeDef *hrng_handle,
                           CRYP_HandleTypeDef *hcryp_handle);

#endif /* RANDOMBYTES_STM32_H */
