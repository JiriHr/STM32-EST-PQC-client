#include "../TLS/tls_port.h"

#include "vcp_uart.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include <stdio.h>
#include <string.h>

#define TLS_FRAME_MAX 2048
#define UART_FRAME_LOG  0x01U
#define UART_FRAME_DATA 0x02U
#define UART_TX_CHUNK_MAX 1024U

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

static int uart_write_frame(uint8_t type, const unsigned char *buf, size_t len)
{
    uint8_t hdr[3];

    if (buf == NULL && len > 0U) {
        return -1;
    }

    hdr[0] = type;
    hdr[1] = (uint8_t) ((len >> 8) & 0xFFU);
    hdr[2] = (uint8_t) (len & 0xFFU);

    if (uart_write_all(hdr, sizeof(hdr)) < 0) {
        return -1;
    }

    if (len > 0U && uart_write_all(buf, len) < 0) {
        return -1;
    }

    return 0;
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

static void uart_drain_rx(uint32_t duration_ms)
{
    uint32_t start = HAL_GetTick();
    uint8_t ch;

    while ((HAL_GetTick() - start) < duration_ms) {
        if (HAL_UART_Receive(&huart1, &ch, 1, 1) == HAL_OK) {
            start = HAL_GetTick();
        }
    }
}

static int uart_read_line(char *resp, size_t resp_size, uint32_t timeout_ms)
{
    uint32_t start = HAL_GetTick();
    size_t idx = 0;
    uint8_t ch;

    if (resp == NULL || resp_size == 0U) {
        return -1;
    }

    while ((HAL_GetTick() - start) < timeout_ms && idx < resp_size - 1U) {
        if (HAL_UART_Receive(&huart1, &ch, 1, 10) == HAL_OK) {
            if (ch == '\0') {
                continue;
            }
            resp[idx++] = (char) ch;
            if (ch == '\n') {
                break;
            }
        }
    }

    resp[idx] = '\0';
    return (idx > 0U) ? 0 : -1;
}

int tls_port_fetch_server_cert(const char *host, uint16_t port, char *out_pem, size_t out_size, size_t *out_len)
{
    char cmd[128];
    char resp[32] = {0};
    unsigned pem_len = 0;
    uint8_t hdr[2];

    if (out_len != NULL) {
        *out_len = 0;
    }

    if (host == NULL || out_pem == NULL || out_size == 0U || out_len == NULL) {
        return -1;
    }

    printf("tls_port_fetch_server_cert(): host=%s port=%u\r\n", host, (unsigned) port);

    uart_drain_rx(25);

    snprintf(cmd, sizeof(cmd), "CERT %s %u\n", host, (unsigned) port);

    printf("Sending CERT command over UART\r\n");

    if (uart_write_all((const uint8_t *) cmd, strlen(cmd)) < 0) {
        return -1;
    }

    if (uart_read_line(resp, sizeof(resp), 15000) != 0) {
        printf("Proxy cert reply timed out\r\n");
        return -1;
    }

    if (strncmp(resp, "OK", 2) != 0) {
        return -1;
    }

    if (sscanf(resp, "OK %u", &pem_len) != 1) {
        if (uart_read_exact(hdr, sizeof(hdr), 15000) != 0) {
            printf("Proxy cert length frame timed out\r\n");
            return -1;
        }
        pem_len = ((unsigned) hdr[0] << 8) | (unsigned) hdr[1];
    }

    if (pem_len == 0U) {
        return -1;
    }

    if ((size_t) pem_len >= out_size) {
        printf("Server certificate buffer too small: need %u, have %u\r\n",
               pem_len + 1U,
               (unsigned) out_size);
        return -1;
    }

    if (uart_read_exact((uint8_t *) out_pem, (size_t) pem_len, 15000) != 0) {
        return -1;
    }

    out_pem[pem_len] = '\0';
    *out_len = (size_t) pem_len;
    printf("Proxy cert reply OK, payload %u bytes\r\n", pem_len);
    return 0;
}

int tls_port_connect(tls_socket_t *sock, const char *host, uint16_t port)
{
    char cmd[128];
    char resp[16] = {0};

    if (sock == NULL || host == NULL) {
        return -1;
    }

    printf("tls_port_connect(): host=%s port=%u\r\n", host, (unsigned) port);

    uart_drain_rx(25);

    snprintf(cmd, sizeof(cmd), "CONNECT %s %u\n", host, (unsigned) port);

    printf("Sending CONNECT command over UART\r\n");

    if (uart_write_all((const uint8_t *) cmd, strlen(cmd)) < 0) {
        sock->connected = 0;
        return -1;
    }

    (void) uart_read_line(resp, sizeof(resp), 2000);

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
    size_t written = 0;

    if (sock == NULL || !sock->connected) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    while (written < len) {
        size_t chunk = len - written;
        if (chunk > UART_TX_CHUNK_MAX) {
            chunk = UART_TX_CHUNK_MAX;
        }

        if (uart_write_frame(UART_FRAME_DATA, buf + written, chunk) != 0) {
            return MBEDTLS_ERR_NET_SEND_FAILED;
        }

        written += chunk;
    }

    return (int) len;
}

int tls_port_log_write(const unsigned char *buf, size_t len)
{
    size_t written = 0;

    while (written < len) {
        size_t chunk = len - written;
        if (chunk > UART_TX_CHUNK_MAX) {
            chunk = UART_TX_CHUNK_MAX;
        }

        if (uart_write_frame(UART_FRAME_LOG, buf + written, chunk) != 0) {
            return -1;
        }

        written += chunk;
    }

    return (int) len;
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
