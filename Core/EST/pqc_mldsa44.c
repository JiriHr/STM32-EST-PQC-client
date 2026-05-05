#include "pqc_mldsa44.h"

#include "../Middlewares/PQC/ml-dsa-44/m4fstack/ml-dsa-44-api.h"

int pqc_mldsa44_keypair(uint8_t *pk, uint8_t *sk)
{
    return crypto_sign_keypair(pk, sk);
}

int pqc_mldsa44_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *sk)
{
    return crypto_sign_signature(sig, sig_len, msg, msg_len, sk);
}

int pqc_mldsa44_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len, const uint8_t *pk)
{
    return crypto_sign_verify(sig, sig_len, msg, msg_len, pk);
}
