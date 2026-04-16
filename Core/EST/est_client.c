#include "est_client.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "psa/crypto.h"

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/pk.h"

#include "tls_port.h"

#define EST_RX_CHUNK_SIZE          1024
#define EST_HTTP_RESPONSE_MAX      8192
#define EST_HTTP_HEADER_MAX        1024

static uint8_t g_http_response_buf[EST_HTTP_RESPONSE_MAX];

static void print_mbedtls_error(const char *label, int ret)
{
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    printf("%s failed: ret=%d (-0x%04X) (%s)\r\n",
           label, ret, (unsigned int) -ret, buf);

    if (ret == -137) {
        printf("%s note: this is PSA_ERROR_BAD_STATE\r\n", label);
    }
}

static void tls_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    (void) ctx;
    (void) level;
    printf("[mbedtls] %s:%d: %s", file, line, str);
}

static int find_header_body_split(const uint8_t *buf, size_t len)
{
    size_t i;

    if (buf == NULL || len < 4) {
        return -1;
    }

    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return (int) (i + 4);
        }
    }

    return -1;
}

static int parse_http_status_code(const uint8_t *buf, size_t len)
{
    char line[64];
    size_t i = 0;

    if (buf == NULL || len == 0) {
        return -1;
    }

    while (i < len && i < sizeof(line) - 1 &&
           buf[i] != '\r' && buf[i] != '\n') {
        line[i] = (char) buf[i];
        i++;
    }
    line[i] = '\0';

    if (strncmp(line, "HTTP/", 5) != 0) {
        return -1;
    }

    {
        const char *p = strchr(line, ' ');
        if (p == NULL) {
            return -1;
        }
        return atoi(p + 1);
    }
}

static void print_http_headers(const uint8_t *buf, size_t header_len)
{
    char headers[EST_HTTP_HEADER_MAX];
    size_t copy_len = header_len;

    if (copy_len >= sizeof(headers)) {
        copy_len = sizeof(headers) - 1;
    }

    memcpy(headers, buf, copy_len);
    headers[copy_len] = '\0';

    printf("HTTP headers:\r\n%s", headers);
}

static void print_http_body_preview(const uint8_t *buf, size_t len)
{
    size_t preview_len;
    size_t i;
    int printable = 1;

    if (buf == NULL || len == 0) {
        printf("HTTP body is empty\r\n");
        return;
    }

    preview_len = len;
    if (preview_len > 256) {
        preview_len = 256;
    }

    for (i = 0; i < preview_len; i++) {
        if (!(isprint((unsigned char) buf[i]) ||
              buf[i] == '\r' || buf[i] == '\n' || buf[i] == '\t')) {
            printable = 0;
            break;
        }
    }

    printf("HTTP body length: %u bytes\r\n", (unsigned) len);

    if (printable) {
        printf("HTTP body preview:\r\n");
        for (i = 0; i < preview_len; i++) {
            putchar((char) buf[i]);
        }
        if (preview_len < len) {
            printf("\r\n... (truncated)\r\n");
        } else if (preview_len == 0 || buf[preview_len - 1] != '\n') {
            printf("\r\n");
        }
    } else {
        printf("HTTP body preview (hex, first %u bytes):\r\n", (unsigned) preview_len);
        for (i = 0; i < preview_len; i++) {
            printf("%02X ", buf[i]);
            if (((i + 1) % 16) == 0) {
                printf("\r\n");
            }
        }
        if ((preview_len % 16) != 0) {
            printf("\r\n");
        }
        if (preview_len < len) {
            printf("... (truncated)\r\n");
        }
    }
}

static int ssl_write_all(mbedtls_ssl_context *ssl,
                         const uint8_t *buf,
                         size_t len)
{
    int ret;
    size_t written = 0;

    while (written < len) {
        ret = mbedtls_ssl_write(ssl, buf + written, len - written);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret < 0) {
            return ret;
        }

        written += (size_t) ret;
    }

    return 0;
}

static int est_https_request(const char *host,
                             uint16_t port,
                             const char *path,
                             const char *ca_pem,
                             const char *client_cert_pem,
                             const char *client_key_pem,
                             const char *method,
                             const char *content_type,
                             const char *content_transfer_encoding,
                             const uint8_t *body,
                             size_t body_len,
                             uint8_t *out_body,
                             size_t out_body_size,
                             size_t *out_body_len)
{
    int ret;
    uint8_t rx_chunk[EST_RX_CHUNK_SIZE];
    char req_headers[896];
    size_t resp_len = 0;
    int header_body_off;
    int status_code;

    tls_socket_t sock = {0};

    mbedtls_x509_crt cacert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&client_cert);
    mbedtls_pk_init(&client_key);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    if (out_body_len != NULL) {
        *out_body_len = 0;
    }

    if (host == NULL || path == NULL || method == NULL ||
        out_body == NULL || out_body_len == NULL) {
        printf("est_https_request: invalid argument\r\n");
        ret = -1;
        goto cleanup;
    }

    printf("EST request start\r\n");
    printf("  host=%s\r\n", host);
    printf("  port=%u\r\n", (unsigned) port);
    printf("  method=%s\r\n", method);
    printf("  path=%s\r\n", path);
    printf("  body_len=%u\r\n", (unsigned) body_len);

    ret = psa_crypto_init();
    if (ret != PSA_SUCCESS) {
        printf("psa_crypto_init failed: %d\r\n", ret);
        ret = -1;
        goto cleanup;
    }

    if (ca_pem == NULL || ca_pem[0] == '\0') {
        printf("CA certificate is required\r\n");
        ret = -1;
        goto cleanup;
    }

    printf("Parsing CA certificate...\r\n");
    ret = mbedtls_x509_crt_parse(&cacert,
                                 (const unsigned char *) ca_pem,
                                 strlen(ca_pem) + 1);
    if (ret != 0) {
        print_mbedtls_error("mbedtls_x509_crt_parse(ca)", ret);
        goto cleanup;
    }

    if (client_cert_pem != NULL && client_cert_pem[0] != '\0') {
        printf("Parsing client certificate...\r\n");
        ret = mbedtls_x509_crt_parse(&client_cert,
                                     (const unsigned char *) client_cert_pem,
                                     strlen(client_cert_pem) + 1);
        if (ret != 0) {
            print_mbedtls_error("mbedtls_x509_crt_parse(client_cert)", ret);
            goto cleanup;
        }
    }

    if (client_key_pem != NULL && client_key_pem[0] != '\0') {
        printf("Parsing client private key...\r\n");
        ret = mbedtls_pk_parse_key(&client_key,
                                   (const unsigned char *) client_key_pem,
                                   strlen(client_key_pem) + 1,
                                   NULL,
                                   0);
        if (ret != 0) {
            print_mbedtls_error("mbedtls_pk_parse_key", ret);
            goto cleanup;
        }
    }

    if ((client_cert_pem != NULL && client_cert_pem[0] != '\0') ^
        (client_key_pem != NULL && client_key_pem[0] != '\0')) {
        printf("Client cert and key must either both be present or both be absent\r\n");
        ret = -1;
        goto cleanup;
    }

    printf("Connecting via transport...\r\n");
    ret = tls_port_connect(&sock, host, port);
    if (ret != 0) {
        printf("tls_port_connect failed\r\n");
        ret = -1;
        goto cleanup;
    }

    printf("Configuring TLS...\r\n");
    ret = mbedtls_ssl_config_defaults(&conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
        goto cleanup;
    }

    mbedtls_debug_set_threshold(0);
    /* Uncomment only if you really need SSL traces */
    /* mbedtls_ssl_conf_dbg(&conf, tls_debug, NULL); */

    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    printf("TLS server certificate verification: REQUIRED\r\n");

    if (client_cert_pem != NULL && client_cert_pem[0] != '\0') {
        ret = mbedtls_ssl_conf_own_cert(&conf, &client_cert, &client_key);
        if (ret != 0) {
            print_mbedtls_error("mbedtls_ssl_conf_own_cert", ret);
            goto cleanup;
        }
        printf("TLS client certificate configured\r\n");
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        print_mbedtls_error("mbedtls_ssl_setup", ret);
        goto cleanup;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, host);
    if (ret != 0) {
        print_mbedtls_error("mbedtls_ssl_set_hostname", ret);
        goto cleanup;
    }

    mbedtls_ssl_set_bio(&ssl, &sock, tls_port_send, tls_port_recv, NULL);

    printf("Starting TLS handshake with %s:%u\r\n", host, (unsigned) port);

    while (1) {
        ret = mbedtls_ssl_handshake(&ssl);

        if (ret == 0) {
            printf("TLS handshake OK\r\n");
            break;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        print_mbedtls_error("mbedtls_ssl_handshake", ret);
        goto cleanup;
    }

    {
        uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
        if (flags != 0) {
            char vrfy_buf[256];
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
            printf("Certificate verification failed:\r\n%s", vrfy_buf);
            ret = -1;
            goto cleanup;
        }
    }

    printf("Certificate verification OK\r\n");

    if (body != NULL && body_len > 0) {
        if (content_transfer_encoding != NULL && content_transfer_encoding[0] != '\0') {
            ret = snprintf(req_headers, sizeof(req_headers),
                           "%s %s HTTP/1.1\r\n"
                           "Host: %s:%u\r\n"
                           "Connection: close\r\n"
                           "Content-Type: %s\r\n"
                           "Content-Transfer-Encoding: %s\r\n"
                           "Content-Length: %u\r\n"
                           "\r\n",
                           method,
                           path,
                           host,
                           (unsigned) port,
                           (content_type != NULL) ? content_type : "application/octet-stream",
                           content_transfer_encoding,
                           (unsigned) body_len);
        } else {
            ret = snprintf(req_headers, sizeof(req_headers),
                           "%s %s HTTP/1.1\r\n"
                           "Host: %s:%u\r\n"
                           "Connection: close\r\n"
                           "Content-Type: %s\r\n"
                           "Content-Length: %u\r\n"
                           "\r\n",
                           method,
                           path,
                           host,
                           (unsigned) port,
                           (content_type != NULL) ? content_type : "application/octet-stream",
                           (unsigned) body_len);
        }
    } else {
        ret = snprintf(req_headers, sizeof(req_headers),
                       "%s %s HTTP/1.1\r\n"
                       "Host: %s:%u\r\n"
                       "Connection: close\r\n"
                       "\r\n",
                       method,
                       path,
                       host,
                       (unsigned) port);
    }

    if (ret < 0 || (size_t) ret >= sizeof(req_headers)) {
        printf("HTTP request headers too large\r\n");
        ret = -1;
        goto cleanup;
    }

    printf("Sending HTTP request headers...\r\n");
    ret = ssl_write_all(&ssl, (const uint8_t *) req_headers, strlen(req_headers));
    if (ret != 0) {
        print_mbedtls_error("ssl_write_all(headers)", ret);
        goto cleanup;
    }

    if (body != NULL && body_len > 0) {
        printf("Sending HTTP request body (%u bytes)...\r\n", (unsigned) body_len);
        ret = ssl_write_all(&ssl, body, body_len);
        if (ret != 0) {
            print_mbedtls_error("ssl_write_all(body)", ret);
            goto cleanup;
        }
    }

    printf("HTTP request sent\r\n");

    while (1) {
        ret = mbedtls_ssl_read(&ssl, rx_chunk, sizeof(rx_chunk));

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            printf("Peer closed the TLS connection cleanly\r\n");
            break;
        }

        if (ret == 0) {
            printf("Connection closed by peer\r\n");
            break;
        }

        if (ret < 0) {
            print_mbedtls_error("mbedtls_ssl_read", ret);
            goto cleanup;
        }

        if (resp_len + (size_t) ret > sizeof(g_http_response_buf)) {
            printf("HTTP response too large for buffer (%u bytes used, %d incoming)\r\n",
                   (unsigned) resp_len, ret);
            ret = -1;
            goto cleanup;
        }

        memcpy(&g_http_response_buf[resp_len], rx_chunk, (size_t) ret);
        resp_len += (size_t) ret;
    }

    if (resp_len == 0) {
        printf("Empty HTTP response\r\n");
        ret = -1;
        goto cleanup;
    }

    header_body_off = find_header_body_split(g_http_response_buf, resp_len);
    if (header_body_off < 0) {
        printf("Failed to find end of HTTP headers\r\n");
        ret = -1;
        goto cleanup;
    }

    status_code = parse_http_status_code(g_http_response_buf, resp_len);
    printf("HTTP status code: %d\r\n", status_code);

    print_http_headers(g_http_response_buf, (size_t) header_body_off);

    {
        size_t body_bytes = resp_len - (size_t) header_body_off;

        if (status_code < 200 || status_code >= 300) {
            printf("HTTP request failed with status %d\r\n", status_code);
            print_http_body_preview(&g_http_response_buf[header_body_off], body_bytes);
            ret = -1;
            goto cleanup;
        }

        if (body_bytes > out_body_size) {
            printf("Output body buffer too small: need %u, have %u\r\n",
                   (unsigned) body_bytes, (unsigned) out_body_size);
            ret = -1;
            goto cleanup;
        }

        memcpy(out_body, &g_http_response_buf[header_body_off], body_bytes);
        *out_body_len = body_bytes;

        printf("HTTP body length: %u bytes\r\n", (unsigned) body_bytes);
    }

    ret = 0;

cleanup:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_pk_free(&client_key);
    mbedtls_x509_crt_free(&client_cert);
    mbedtls_x509_crt_free(&cacert);
    tls_port_close(&sock);

    return ret;
}

int est_client_get_cacerts(const char *host,
                           uint16_t port,
                           const char *path,
                           const char *ca_pem,
                           uint8_t *out_body,
                           size_t out_body_size,
                           size_t *out_body_len)
{
    return est_https_request(host,
                             port,
                             path,
                             ca_pem,
                             NULL,
                             NULL,
                             "GET",
                             NULL,
                             NULL,
                             NULL,
                             0,
                             out_body,
                             out_body_size,
                             out_body_len);
}

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
                            size_t *out_body_len)
{
    if (csr_der == NULL || csr_der_len == 0) {
        printf("est_client_simpleenroll: CSR is missing\r\n");
        return -1;
    }

    return est_https_request(host,
                             port,
                             path,
                             ca_pem,
                             client_cert_pem,
                             client_key_pem,
                             "POST",
                             "application/pkcs10",
                             "base64",
                             csr_der,
                             csr_der_len,
                             out_body,
                             out_body_size,
                             out_body_len);
}
