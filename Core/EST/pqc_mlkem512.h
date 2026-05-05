#ifndef PQC_MLKEM512_H
#define PQC_MLKEM512_H

#include <stddef.h>
#include <stdint.h>

#define PQC_MLKEM512_PUBLICKEYBYTES 800U
#define PQC_MLKEM512_SECRETKEYBYTES 1632U
#define PQC_MLKEM512_CIPHERTEXTBYTES 768U
#define PQC_MLKEM512_SHAREDSECRETBYTES 32U

int pqc_mlkem512_keypair(uint8_t *pk, uint8_t *sk);
int pqc_mlkem512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqc_mlkem512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif /* PQC_MLKEM512_H */
