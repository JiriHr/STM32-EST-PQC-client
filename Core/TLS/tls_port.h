#ifndef TLS_PORT_H
#define TLS_PORT_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    int connected;
} tls_socket_t;

int tls_port_connect(tls_socket_t *sock, const char *host, uint16_t port);
int tls_port_send(void *ctx, const unsigned char *buf, size_t len);
int tls_port_recv(void *ctx, unsigned char *buf, size_t len);
void tls_port_close(tls_socket_t *sock);

#endif
