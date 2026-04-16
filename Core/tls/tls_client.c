#include <stdio.h>
#include <string.h>

#include "psa/crypto.h"

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include "tls_port.h"
#include "tls_client.h"

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

int tls_client_test_https_get(const char *host,
                              uint16_t port,
                              const char *path,
                              const char *ca_pem)
{
    int ret;
    unsigned char rxbuf[1024];
    char txbuf[512];

    tls_socket_t sock = {0};

    mbedtls_x509_crt cacert;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_x509_crt_init(&cacert);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    printf("tls_client_test_https_get() entry\r\n");
    printf("host=%s port=%u path=%s\r\n",
           host ? host : "(null)",
           (unsigned) port,
           path ? path : "(null)");

    if (ca_pem == NULL) {
        printf("ca_pem = NULL\r\n");
    } else {
        size_t ca_len = strlen(ca_pem);
        printf("ca_pem strlen = %u\r\n", (unsigned) ca_len);
        printf("ca_pem first 32 chars: %.32s\r\n", ca_pem);
    }

    printf("Initializing PSA crypto...\r\n");

    ret = psa_crypto_init();
    if (ret != PSA_SUCCESS) {
        printf("psa_crypto_init failed: %d\r\n", ret);
        ret = -1;
        goto cleanup;
    }

    if (ca_pem != NULL && ca_pem[0] != '\0') {
        printf("Parsing CA certificate...\r\n");

        ret = mbedtls_x509_crt_parse(&cacert,
                                     (const unsigned char *) ca_pem,
                                     strlen(ca_pem) + 1);
        if (ret != 0) {
            print_mbedtls_error("mbedtls_x509_crt_parse", ret);
            goto cleanup;
        }

        printf("CA certificate parsed OK\r\n");
    } else {
        printf("No CA certificate provided\r\n");
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
    // mbedtls_ssl_conf_dbg(&conf, tls_debug, NULL);

    if (ca_pem != NULL && ca_pem[0] != '\0') {
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        printf("TLS server certificate verification: REQUIRED\r\n");
    } else {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        printf("TLS server certificate verification: DISABLED (no CA loaded)\r\n");
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

    printf("About to start handshake\r\n");
    printf("Starting TLS handshake with %s:%u\r\n", host, (unsigned) port);

    uint32_t hs_start = HAL_GetTick();

    while (1) {
        ret = mbedtls_ssl_handshake(&ssl);
        printf("mbedtls_ssl_handshake ret = %d\r\n", ret);

        if (ret == 0) {
            printf("TLS handshake OK\r\n");
            break;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {

            if ((HAL_GetTick() - hs_start) > 10000) {
                printf("TLS handshake timeout\r\n");
                ret = -1;
                goto cleanup;
            }

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

        printf("Certificate verification OK\r\n");
    }

    snprintf(txbuf, sizeof(txbuf),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             path, host);

    {
        size_t to_write = strlen(txbuf);
        size_t written_total = 0;

        printf("Sending HTTP request...\r\n");

        while (written_total < to_write) {
            ret = mbedtls_ssl_write(&ssl,
                                    (const unsigned char *) txbuf + written_total,
                                    to_write - written_total);

            if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }

            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                printf("\r\nPeer closed the TLS connection cleanly\r\n");
                break;
            }

            if (ret < 0) {
                print_mbedtls_error("mbedtls_ssl_read", ret);
                goto cleanup;
            }

            written_total += (size_t) ret;
        }
    }

    printf("HTTP request sent\r\n");

    while (1) {
        ret = mbedtls_ssl_read(&ssl, rxbuf, sizeof(rxbuf) - 1);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            printf("\r\nPeer closed the TLS connection cleanly\r\n");
            break;
        }

        if (ret == 0) {
            printf("\r\nConnection closed by peer\r\n");
            break;
        }

        if (ret < 0) {
            print_mbedtls_error("mbedtls_ssl_read", ret);
            goto cleanup;
        }

        rxbuf[ret] = '\0';
        printf("%s", rxbuf);
    }

    ret = 0;

cleanup:
    printf("Cleaning up...\r\n");

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);
    tls_port_close(&sock);

    return ret;
}
