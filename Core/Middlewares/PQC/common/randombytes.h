#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

int randombytes(uint8_t *out, size_t outlen);
void randombytes_init(const uint8_t *entropy_input,
                      const uint8_t *personalization_string,
                      int security_strength);

#endif /* RANDOMBYTES_H */
