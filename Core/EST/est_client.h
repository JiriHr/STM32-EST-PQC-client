#ifndef EST_CLIENT_H
#define EST_CLIENT_H

#include <stddef.h>
#include <stdint.h>

int est_client_get_cacerts(const char *host,
                           uint16_t port,
                           const char *path,
                           const char *ca_pem,
                           uint8_t *out_body,
                           size_t out_body_size,
                           size_t *out_body_len);

int est_client_simpleenroll(const char *host,
                            uint16_t port,
                            const char *path,
                            const char *ca_pem,
                            const char *client_cert_pem,
                            const char *client_key_pem,
                            const uint8_t *csr_der,
                            size_t csr_der_len,
                            uint8_t *out_body,
                            size_t out_body_size,
                            size_t *out_body_len);

#endif /* EST_CLIENT_H */
