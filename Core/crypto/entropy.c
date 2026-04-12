#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "stm32wbxx_hal.h"
#include "mbedtls/platform.h"
#include "psa/crypto.h"

extern RNG_HandleTypeDef hrng;

int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags,
                                 size_t *estimate_bits,
                                 unsigned char *output,
                                 size_t output_size)
{
    uint32_t random_word;
    size_t generated = 0;

    if (flags != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    while (generated < output_size) {
        if (HAL_RNG_GenerateRandomNumber(&hrng, &random_word) != HAL_OK) {
            *estimate_bits = 0;
            return PSA_ERROR_INSUFFICIENT_ENTROPY;
        }

        size_t to_copy = (output_size - generated > sizeof(random_word))
                       ? sizeof(random_word)
                       : (output_size - generated);

        memcpy(output + generated, &random_word, to_copy);
        generated += to_copy;
    }

    *estimate_bits = 8 * output_size;
    return 0;
}
