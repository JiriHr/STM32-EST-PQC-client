#ifndef CSR_GEN_H
#define CSR_GEN_H

#include <stdint.h>
#include <stddef.h>

int csr_build_certification_request_info(
    const char *common_name,
    const uint8_t *pubkey,
    size_t pubkey_len,
    uint8_t *out,
    size_t out_size,
    size_t *out_len
);

int csr_assemble(
    const uint8_t *cri,
    size_t cri_len,
    const uint8_t *signature,
    size_t signature_len,
    uint8_t *out,
    size_t out_size,
    size_t *out_len
);

int csr_generate(
    const char *common_name,
    const uint8_t *pubkey,
    size_t pubkey_len,
    const uint8_t *signature,
    size_t signature_len,
    uint8_t *out,
    size_t out_size,
    size_t *out_len
);

#endif
