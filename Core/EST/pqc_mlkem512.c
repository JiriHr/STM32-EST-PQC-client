#include "pqc_mlkem512.h"

#include "../Middlewares/PQC/ml-kem-512/m4fstack/ml-kem-512-api.h"

int pqc_mlkem512_keypair(uint8_t *pk, uint8_t *sk)
{
    return crypto_kem_keypair(pk, sk);
}

int pqc_mlkem512_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    return crypto_kem_enc(ct, ss, pk);
}

int pqc_mlkem512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    return crypto_kem_dec(ss, ct, sk);
}
