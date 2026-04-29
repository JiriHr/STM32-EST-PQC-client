#include "../TLS/tls_port.h"

#include "vcp_uart.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include <stdio.h>
#include <string.h>

#define TLS_FRAME_MAX 2048

static uint8_t frame_buf[TLS_FRAME_MAX];
static size_t frame_len = 0;
static size_t frame_off = 0;

static int uart_write_all(const uint8_t *buf, size_t len)
{
    if (HAL_UART_Transmit(&huart1, (uint8_t *)buf, len, 5000) == HAL_OK) {
        return (int)len;
    }
    return -1;
}

static int uart_read_exact(uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    uint32_t start = HAL_GetTick();
    size_t got = 0;

    while (got < len) {
        if (HAL_UART_Receive(&huart1, &buf[got], 1, 10) == HAL_OK) {
            got++;
            start = HAL_GetTick();
        } else {
            if ((HAL_GetTick() - start) >= timeout_ms) {
                return -1;
            }
        }
    }

    return 0;
}

int tls_port_connect(tls_socket_t *sock, const char *host, uint16_t port)
{
    char cmd[128];
    char resp[16] = {0};
    size_t idx = 0;
    uint8_t ch;

    if (sock == NULL || host == NULL) {
        return -1;
    }

    printf("tls_port_connect(): host=%s port=%u\r\n", host, (unsigned) port);

    snprintf(cmd, sizeof(cmd), "CONNECT %s %u\n", host, (unsigned) port);

    printf("Sending CONNECT command over UART\r\n");

    if (uart_write_all((const uint8_t *) cmd, strlen(cmd)) < 0) {
        sock->connected = 0;
        return -1;
    }

    uint32_t start = HAL_GetTick();
    while ((HAL_GetTick() - start) < 2000 && idx < sizeof(resp) - 1) {
        if (HAL_UART_Receive(&huart1, &ch, 1, 10) == HAL_OK) {
            resp[idx++] = (char) ch;
            if (ch == '\n') {
                break;
            }
        }
    }

    resp[idx] = '\0';

    printf("Proxy reply raw: %s\r\n", resp);

    if (strncmp(resp, "OK", 2) == 0) {
        sock->connected = 1;
        frame_len = 0;
        frame_off = 0;
        return 0;
    }

    sock->connected = 0;
    return -1;
}

int tls_port_send(void *ctx, const unsigned char *buf, size_t len)
{
    tls_socket_t *sock = (tls_socket_t *) ctx;

    if (sock == NULL || !sock->connected) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    int ret = uart_write_all(buf, len);
    if (ret < 0) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    return ret;
}

int tls_port_recv(void *ctx, unsigned char *buf, size_t len)
{
    tls_socket_t *sock = (tls_socket_t *) ctx;

    if (sock == NULL || !sock->connected) {
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    /* If no buffered payload remains, read one framed chunk:
       [2-byte big-endian length][payload] */
    if (frame_off >= frame_len) {
        uint8_t hdr[2];
        uint16_t payload_len;

        if (uart_read_exact(hdr, 2, 5000) != 0) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }

        payload_len = ((uint16_t) hdr[0] << 8) | hdr[1];

        if (payload_len == 0) {
            printf("tls_port_recv: EOF frame\r\n");
            sock->connected = 0;
            return 0;
        }

        if (payload_len > TLS_FRAME_MAX) {
            printf("tls_port_recv: bad frame length %u\r\n", (unsigned) payload_len);
            return MBEDTLS_ERR_NET_RECV_FAILED;
        }

        if (uart_read_exact(frame_buf, payload_len, 5000) != 0) {
            return MBEDTLS_ERR_NET_RECV_FAILED;
        }

        frame_len = payload_len;
        frame_off = 0;

        printf("tls_port_recv: framed payload %u bytes\r\n", (unsigned) frame_len);
    }

    size_t avail = frame_len - frame_off;
    size_t take = (len < avail) ? len : avail;

    memcpy(buf, &frame_buf[frame_off], take);
    frame_off += take;

    return (int) take;
}

void tls_port_close(tls_socket_t *sock)
{
    if (sock != NULL) {
        sock->connected = 0;
    }
    frame_len = 0;
    frame_off = 0;
}
