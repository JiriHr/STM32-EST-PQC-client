#ifndef PQC_MLDSA44_H
#define PQC_MLDSA44_H

#include <stddef.h>
#include <stdint.h>

#define PQC_MLDSA44_PUBLICKEYBYTES 1312U
#define PQC_MLDSA44_SECRETKEYBYTES 2560U
#define PQC_MLDSA44_SIGNATUREBYTES 2420U

int pqc_mldsa44_keypair(uint8_t *pk, uint8_t *sk);
int pqc_mldsa44_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk);
int pqc_mldsa44_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk);

#endif /* PQC_MLDSA44_H */
