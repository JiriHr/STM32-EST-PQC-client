#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

int tls_client_test_https_get(const char *host,
                              uint16_t port,
                              const char *path,
                              const char *ca_pem);

#endif
