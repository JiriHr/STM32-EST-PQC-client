/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "aes.h"
#include "rng.h"
#include "gpio.h"
#include "vcp_uart.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "ca_cert.h"
#include "est_client.h"
#include "csr_data.h"
#include "bootstrap_credentials.h"
#include "csr_gen.h"
#include "cms_pqc.h"
#include "tls_port.h"

#include "mbedtls/base64.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

#include "../Middlewares/PQC/ml-dsa-44/m4fstack/ml-dsa-44-api.h"
#include "../Middlewares/PQC/common/randombytes_stm32.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define EST_TARGET_ADHOC_RA                 1
#define EST_TARGET_LAMASSU_PQC_MLDSA44      2

#ifndef EST_TARGET_PROFILE
#define EST_TARGET_PROFILE                  EST_TARGET_ADHOC_RA
#endif

#define EST_HOST                            "localhost"
#define EST_PORT                            8443
#define EST_BASE_PATH                       "/api/dmsmanager/.well-known/est/"
#define EST_DEVICE_COMMON_NAME              "device-01"

#if EST_TARGET_PROFILE == EST_TARGET_ADHOC_RA
#define EST_PROFILE_NAME                    "ad-hoc-ra"
#define EST_APS_ID                          "est-ra"
#define EST_USE_TLS_CLIENT_CERT             1
#define EST_USE_DYNAMIC_SERVER_CA           0
#define EST_SERVER_CA_PEM                   test_ca_pem
#elif EST_TARGET_PROFILE == EST_TARGET_LAMASSU_PQC_MLDSA44
#define EST_PROFILE_NAME                    "lamassu-pqc-mldsa44"
#define EST_APS_ID                          "mldsa44-est-dms"
#define EST_USE_TLS_CLIENT_CERT             0
#define EST_USE_DYNAMIC_SERVER_CA           1
#define EST_SERVER_CA_PEM                   g_dynamic_server_ca_pem
#else
#error "Unsupported EST_TARGET_PROFILE"
#endif

#define EST_CACERTS_PATH                    EST_BASE_PATH EST_APS_ID "/cacerts"
#define EST_SIMPLEENROLL_PATH               EST_BASE_PATH EST_APS_ID "/simpleenroll"

#if EST_USE_TLS_CLIENT_CERT
#define EST_TLS_CLIENT_CERT_PEM             bootstrap_cert_pem
#define EST_TLS_CLIENT_KEY_PEM              bootstrap_key_pem
#else
#define EST_TLS_CLIENT_CERT_PEM             NULL
#define EST_TLS_CLIENT_KEY_PEM              NULL
#endif

#define CACERTS_BUF_SIZE        8192
#define ENROLL_BUF_SIZE         8192
#define DER_DECODE_BUF_SIZE     8192
#define CERT_PEM_B64_BUF_SIZE   8192
#define CERT_INFO_BUF_SIZE      2048
#define DYNAMIC_SERVER_CA_BUF_SIZE 2048
#define CSR_CRI_BUF_SIZE        2048
#define CSR_DER_BUF_SIZE        4096
#define CSR_B64_BUF_SIZE        6144
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

COM_InitTypeDef BspCOMInit;

/* USER CODE BEGIN PV */
static uint8_t g_cacerts_buf[CACERTS_BUF_SIZE];
static uint8_t g_enroll_buf[ENROLL_BUF_SIZE];
static uint8_t g_der_buf[DER_DECODE_BUF_SIZE];
static unsigned char g_cert_pem_b64_buf[CERT_PEM_B64_BUF_SIZE];
static uint8_t g_csr_cri[CSR_CRI_BUF_SIZE];
static uint8_t g_csr_der[CSR_DER_BUF_SIZE];
static uint8_t g_csr_b64[CSR_B64_BUF_SIZE];
static uint8_t g_mldsa_pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t g_mldsa_sk[CRYPTO_SECRETKEYBYTES];
static uint8_t g_mldsa_sig[CRYPTO_BYTES];
#if EST_USE_DYNAMIC_SERVER_CA
static char g_dynamic_server_ca_pem[DYNAMIC_SERVER_CA_BUF_SIZE];
#endif
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
void PeriphCommonClock_Config(void);

/* USER CODE BEGIN PFP */
static void dump_hex_preview(const char *label, const uint8_t *buf, size_t len, size_t max_len);
static int compact_base64_body(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size, size_t *out_len);
static int asn1_get_object_total_len(const uint8_t *buf, size_t buf_len, size_t *out_total_len);
static int asn1_get_tlv(const uint8_t *buf, size_t buf_len, uint8_t *out_tag, size_t *out_hdr_len, size_t *out_content_len);
static int is_mldsa44_certificate_like(const uint8_t *buf, size_t buf_len);
static int find_first_der_certificate(const uint8_t *buf, size_t buf_len, size_t *out_off, size_t *out_len);
static void print_mbedtls_error(const char *label, int ret);
static int print_raw_certificate_pem(const uint8_t *cert_der, size_t cert_der_len);
static int print_certificate_from_est_body(const uint8_t *body_b64, size_t body_b64_len);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

static void dump_hex_preview(const char *label, const uint8_t *buf, size_t len, size_t max_len)
{
    size_t i;
    size_t shown;

    if (label == NULL) {
        label = "buffer";
    }

    if (buf == NULL) {
        printf("%s: (null)\r\n", label);
        return;
    }

    shown = (len < max_len) ? len : max_len;

    printf("%s (%u bytes, showing %u):\r\n",
           label,
           (unsigned) len,
           (unsigned) shown);

    for (i = 0; i < shown; i++) {
        printf("%02X ", buf[i]);

        if (((i + 1) % 16) == 0) {
            printf("\r\n");
        }
    }

    if ((shown % 16) != 0) {
        printf("\r\n");
    }
}

static void print_mbedtls_error(const char *label, int ret)
{
    char errbuf[128];

    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    printf("%s failed: ret=%d (-0x%04X) (%s)\r\n",
           label,
           ret,
           (unsigned int) -ret,
           errbuf);
}

static int compact_base64_body(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size, size_t *out_len)
{
    size_t i;
    size_t j = 0;

    if (in == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    for (i = 0; i < in_len; i++) {
        uint8_t c = in[i];

        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
            continue;
        }

        if (j >= out_size) {
            return -1;
        }

        out[j++] = c;
    }

    *out_len = j;
    return 0;
}

static int asn1_get_object_total_len(const uint8_t *buf, size_t buf_len, size_t *out_total_len)
{
    size_t len_bytes;
    size_t content_len = 0;
    size_t i;

    if (buf == NULL || out_total_len == NULL || buf_len < 2) {
        return -1;
    }

    if (buf[0] != 0x30) {
        return -1;
    }

    if ((buf[1] & 0x80U) == 0U) {
        content_len = buf[1];
        if (2U + content_len > buf_len) {
            return -1;
        }
        *out_total_len = 2U + content_len;
        return 0;
    }

    len_bytes = (size_t) (buf[1] & 0x7FU);
    if (len_bytes == 0U || len_bytes > sizeof(size_t) || 2U + len_bytes > buf_len) {
        return -1;
    }

    for (i = 0; i < len_bytes; i++) {
        content_len = (content_len << 8) | buf[2U + i];
    }

    if (2U + len_bytes + content_len > buf_len) {
        return -1;
    }

    *out_total_len = 2U + len_bytes + content_len;
    return 0;
}

static int asn1_get_tlv(const uint8_t *buf, size_t buf_len, uint8_t *out_tag, size_t *out_hdr_len, size_t *out_content_len)
{
    size_t len_bytes;
    size_t content_len = 0;
    size_t i;

    if (buf == NULL || out_tag == NULL || out_hdr_len == NULL || out_content_len == NULL || buf_len < 2U) {
        return -1;
    }

    *out_tag = buf[0];

    if ((buf[1] & 0x80U) == 0U) {
        *out_hdr_len = 2U;
        *out_content_len = buf[1];
        return (2U + *out_content_len <= buf_len) ? 0 : -1;
    }

    len_bytes = (size_t) (buf[1] & 0x7FU);
    if (len_bytes == 0U || len_bytes > sizeof(size_t) || 2U + len_bytes > buf_len) {
        return -1;
    }

    for (i = 0; i < len_bytes; i++) {
        content_len = (content_len << 8) | buf[2U + i];
    }

    *out_hdr_len = 2U + len_bytes;
    *out_content_len = content_len;
    return (*out_hdr_len + content_len <= buf_len) ? 0 : -1;
}

static int der_contains_mldsa44_oid(const uint8_t *buf, size_t buf_len)
{
    static const uint8_t oid_tlv[] = {
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
    };
    size_t i;

    if (buf == NULL || buf_len < sizeof(oid_tlv)) {
        return 0;
    }

    for (i = 0; i + sizeof(oid_tlv) <= buf_len; i++) {
        if (memcmp(buf + i, oid_tlv, sizeof(oid_tlv)) == 0) {
            return 1;
        }
    }

    return 0;
}

static int is_mldsa44_certificate_like(const uint8_t *buf, size_t buf_len)
{
    uint8_t tag;
    size_t hdr_len;
    size_t content_len;
    size_t total_len;
    size_t pos;
    size_t end;
    size_t child_len;
    size_t tbs_off;
    size_t alg_off;
    size_t sig_off;

    if (buf == NULL || asn1_get_object_total_len(buf, buf_len, &total_len) != 0 || total_len != buf_len) {
        return 0;
    }

    if (asn1_get_tlv(buf, buf_len, &tag, &hdr_len, &content_len) != 0 || tag != 0x30U) {
        return 0;
    }

    pos = hdr_len;
    end = hdr_len + content_len;

    tbs_off = pos;
    if (asn1_get_object_total_len(buf + pos, end - pos, &child_len) != 0) {
        return 0;
    }
    pos += child_len;

    alg_off = pos;
    if (asn1_get_object_total_len(buf + pos, end - pos, &child_len) != 0) {
        return 0;
    }
    pos += child_len;

    sig_off = pos;
    if (asn1_get_tlv(buf + pos, end - pos, &tag, &hdr_len, &content_len) != 0) {
        return 0;
    }
    child_len = hdr_len + content_len;
    if (pos + child_len != end || tag != 0x03U) {
        return 0;
    }

    return der_contains_mldsa44_oid(buf + tbs_off, alg_off - tbs_off) &&
           der_contains_mldsa44_oid(buf + alg_off, sig_off - alg_off);
}

static int find_first_der_certificate(const uint8_t *buf, size_t buf_len, size_t *out_off, size_t *out_len)
{
    size_t off;

    if (buf == NULL || out_off == NULL || out_len == NULL) {
        return -1;
    }

    for (off = 0; off + 4 < buf_len; off++) {
        size_t obj_len;
        int ret;
        mbedtls_x509_crt crt;

        if (buf[off] != 0x30) {
            continue;
        }

        ret = asn1_get_object_total_len(buf + off, buf_len - off, &obj_len);
        if (ret != 0) {
            continue;
        }

        if (is_mldsa44_certificate_like(buf + off, obj_len)) {
            *out_off = off;
            *out_len = obj_len;
            return 0;
        }

        mbedtls_x509_crt_init(&crt);
        ret = mbedtls_x509_crt_parse_der(&crt, buf + off, obj_len);
        if (ret == 0) {
            *out_off = off;
            *out_len = obj_len;
            mbedtls_x509_crt_free(&crt);
            return 0;
        }
        mbedtls_x509_crt_free(&crt);
    }

    return -1;
}

static int print_raw_certificate_pem(const uint8_t *cert_der, size_t cert_der_len)
{
    int ret;
    size_t pem_b64_len = 0;
    size_t i;

    ret = mbedtls_base64_encode(g_cert_pem_b64_buf,
                                sizeof(g_cert_pem_b64_buf),
                                &pem_b64_len,
                                cert_der,
                                cert_der_len);
    if (ret != 0) {
        print_mbedtls_error("mbedtls_base64_encode(cert DER)", ret);
        return -1;
    }

    printf("\r\n=== EXTRACTED CERTIFICATE PEM ===\r\n");
    printf("-----BEGIN CERTIFICATE-----\r\n");

    for (i = 0; i < pem_b64_len; i++) {
        putchar((char) g_cert_pem_b64_buf[i]);
        if (((i + 1U) % 64U) == 0U) {
            printf("\r\n");
        }
    }

    if ((pem_b64_len % 64U) != 0U) {
        printf("\r\n");
    }

    printf("-----END CERTIFICATE-----\r\n");
    return 0;
}

static int print_certificate_from_est_body(const uint8_t *body_b64, size_t body_b64_len)
{
    int ret;
    size_t compact_len = 0;
    size_t der_len = 0;
    size_t cert_off = 0;
    size_t cert_len = 0;
    char info_buf[CERT_INFO_BUF_SIZE];
    mbedtls_x509_crt crt;

    if (body_b64 == NULL || body_b64_len == 0) {
        printf("No EST body to decode\r\n");
        return -1;
    }

    ret = compact_base64_body(body_b64,
                              body_b64_len,
                              g_der_buf,
                              sizeof(g_der_buf),
                              &compact_len);
    if (ret != 0) {
        printf("Failed to compact base64 EST body\r\n");
        return -1;
    }

    ret = mbedtls_base64_decode(g_der_buf,
                                sizeof(g_der_buf),
                                &der_len,
                                g_der_buf,
                                compact_len);
    if (ret != 0) {
        print_mbedtls_error("mbedtls_base64_decode(EST body)", ret);
        return -1;
    }

    printf("Decoded EST PKCS#7/CMS length: %u bytes\r\n", (unsigned) der_len);
    dump_hex_preview("decoded CMS body", g_der_buf, der_len, 96);

    ret = find_first_der_certificate(g_der_buf, der_len, &cert_off, &cert_len);
    if (ret != 0) {
        printf("Failed to locate an embedded DER certificate inside CMS response\r\n");
        return -1;
    }

    printf("Found DER certificate at offset %u, length %u bytes\r\n",
           (unsigned) cert_off,
           (unsigned) cert_len);

    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse_der(&crt, g_der_buf + cert_off, cert_len);
    if (ret != 0) {
        if (is_mldsa44_certificate_like(g_der_buf + cert_off, cert_len)) {
            printf("\r\n=== EXTRACTED CERTIFICATE INFO ===\r\n");
            printf("certificate type  : X.509 with ML-DSA-44 algorithm identifiers\r\n");
            printf("certificate length: %u bytes\r\n", (unsigned) cert_len);
            printf("note              : mbedTLS does not parse ML-DSA X.509 OIDs in this build\r\n");
            ret = print_raw_certificate_pem(g_der_buf + cert_off, cert_len);
            mbedtls_x509_crt_free(&crt);
            return ret;
        }

        print_mbedtls_error("mbedtls_x509_crt_parse_der(extracted cert)", ret);
        mbedtls_x509_crt_free(&crt);
        return -1;
    }

    memset(info_buf, 0, sizeof(info_buf));
    mbedtls_x509_crt_info(info_buf, sizeof(info_buf) - 1, "", &crt);

    printf("\r\n=== EXTRACTED CERTIFICATE INFO ===\r\n");
    printf("%s", info_buf);

    ret = print_raw_certificate_pem(crt.raw.p, crt.raw.len);

    mbedtls_x509_crt_free(&crt);
    return ret;
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  size_t cacerts_len = 0;
  size_t enroll_len = 0;
  int ret;

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* Configure the peripherals common clocks */
  PeriphCommonClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  psa_crypto_init();
  MX_GPIO_Init();
  MX_RNG_Init();
  MX_AES1_Init();
  VCP_UART_Init();

  /* USER CODE BEGIN 2 */

  /* USER CODE END 2 */

  /* Initialize COM1 port (115200, 8 bits (7-bit data + 1 stop bit), no parity */
  BspCOMInit.BaudRate   = 115200;
  BspCOMInit.WordLength = COM_WORDLENGTH_8B;
  BspCOMInit.StopBits   = COM_STOPBITS_1;
  BspCOMInit.Parity     = COM_PARITY_NONE;
  BspCOMInit.HwFlowCtl  = COM_HWCONTROL_NONE;

  if (BSP_COM_Init(COM1, &BspCOMInit) != BSP_ERROR_NONE)
  {
    Error_Handler();
  }

  if (randombytes_stm32_init(&hrng, &hcryp1) != 0) {
      printf("randombytes_stm32_init failed\r\n");
      while (1);
  }

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */

  printf("Starting EST test...\r\n");
  printf("EST profile: %s\r\n", EST_PROFILE_NAME);
  printf("EST APS/DMS ID: %s\r\n", EST_APS_ID);
  printf("TLS client certificate: %s\r\n", EST_USE_TLS_CLIENT_CERT ? "enabled" : "disabled");

#if EST_USE_DYNAMIC_SERVER_CA
  size_t server_ca_len = 0;

  printf("Acquiring TLS server certificate via UART proxy...\r\n");

  ret = tls_port_fetch_server_cert(
      EST_HOST,
      EST_PORT,
      g_dynamic_server_ca_pem,
      sizeof(g_dynamic_server_ca_pem),
      &server_ca_len);

  if (ret != 0) {
      printf("TLS server certificate acquisition failed: %d\r\n", ret);
      while (1);
  }

  printf("TLS server certificate acquired (%u bytes)\r\n", (unsigned) server_ca_len);
#endif

   /* ===================================================== */
   /* STEP 1: GET CACERTS */
   /* ===================================================== */

   printf("\r\n=== STEP 1: GET cacerts ===\r\n");

   ret = est_client_get_cacerts(
       EST_HOST,
       EST_PORT,
       EST_CACERTS_PATH,
       EST_SERVER_CA_PEM,
       g_cacerts_buf,
       sizeof(g_cacerts_buf),
       &cacerts_len);

   if (ret != 0) {
       printf("est_client_get_cacerts failed: %d\r\n", ret);
   } else {
       printf("est_client_get_cacerts OK, body length = %u bytes\r\n",
              (unsigned)cacerts_len);
       dump_hex_preview("cacerts body", g_cacerts_buf, cacerts_len, 128);
   }

   /* ===================================================== */
   /* STEP 2: GENERATE CSR (CUSTOM, NO MBEDTLS) */
   /* ===================================================== */

   printf("\r\n=== STEP 2: GENERATE CSR ===\r\n");

   size_t csr_cri_len = 0;
   size_t csr_der_len = 0;
   size_t csr_b64_len = 0;
   size_t signature_len = 0;

   ret = crypto_sign_keypair(g_mldsa_pk, g_mldsa_sk);
   if (ret != 0) {
       printf("ML-DSA keypair failed: %d\r\n", ret);
       while (1);
   }

   ret = csr_build_certification_request_info(
       EST_DEVICE_COMMON_NAME,
       g_mldsa_pk, sizeof(g_mldsa_pk),
       g_csr_cri, sizeof(g_csr_cri),
       &csr_cri_len);

   if (ret != 0) {
       printf("CSR CRI generation failed\r\n");
       while (1);
   }

   ret = crypto_sign_signature(
       g_mldsa_sig, &signature_len,
       g_csr_cri, csr_cri_len,
       g_mldsa_sk);

   if (ret != 0) {
       printf("ML-DSA signing failed: %d\r\n", ret);
       while (1);
   }

   printf("ML-DSA signature ready (%u bytes)\r\n", (unsigned)signature_len);

   ret = crypto_sign_verify(
       g_mldsa_sig, signature_len,
       g_csr_cri, csr_cri_len,
       g_mldsa_pk);

   if (ret != 0) {
       printf("ML-DSA local verification failed: %d\r\n", ret);
       while (1);
   }

   printf("ML-DSA local verification OK\r\n");

   ret = csr_assemble(
       g_csr_cri, csr_cri_len,
       g_mldsa_sig, signature_len,
       g_csr_der, sizeof(g_csr_der),
       &csr_der_len);

   if (ret != 0) {
       printf("CSR assembly failed\r\n");
       while (1);
   }

   printf("CSR DER ready (%u bytes)\r\n", (unsigned)csr_der_len);
   dump_hex_preview("CSR DER", g_csr_der, csr_der_len, 128);

   /* Base64 encode CSR */
   ret = mbedtls_base64_encode(
       g_csr_b64,
       sizeof(g_csr_b64),
       &csr_b64_len,
       g_csr_der,
       csr_der_len);

   if (ret != 0) {
       printf("Base64 encoding failed: %d\r\n", ret);
       while (1);
   }

   printf("CSR base64 ready (%u bytes)\r\n", (unsigned)csr_b64_len);

   /* ===================================================== */
   /* STEP 3: SIMPLE ENROLL */
   /* ===================================================== */

   printf("\r\n=== STEP 3: POST simpleenroll ===\r\n");

   ret = est_client_simpleenroll(
       EST_HOST,
       EST_PORT,
       EST_SIMPLEENROLL_PATH,
       EST_SERVER_CA_PEM,
       EST_TLS_CLIENT_CERT_PEM,
       EST_TLS_CLIENT_KEY_PEM,
       g_csr_b64,
       csr_b64_len,
       g_enroll_buf,
       sizeof(g_enroll_buf),
       &enroll_len);

   if (ret != 0) {
       printf("est_client_simpleenroll failed: %d\r\n", ret);
   } else {
       printf("est_client_simpleenroll OK, PKCS#7 length = %u bytes\r\n",
              (unsigned)enroll_len);
       dump_hex_preview("simpleenroll body", g_enroll_buf, enroll_len, 128);

       ret = print_certificate_from_est_body(g_enroll_buf, enroll_len);
       if (ret != 0) {
           printf("Failed to extract certificate from EST response: %d\r\n", ret);
       }
   }

   /* ===================================================== */
   /* STEP 4: CMS PQC SELF-TESTS */
   /* ===================================================== */

   printf("\r\n=== STEP 4: CMS PQC self-tests ===\r\n");

   ret = cms_pqc_self_test();
   if (ret != 0) {
       printf("CMS PQC self-tests failed: %d\r\n", ret);
   }

   printf("\r\nEST test finished\r\n");
  while (1)
  {
    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI48 | RCC_OSCILLATORTYPE_HSI
                                   | RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.HSI48State = RCC_HSI48_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.MSICalibrationValue = RCC_MSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_6;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_MSI;
  RCC_OscInitStruct.PLL.PLLM = RCC_PLLM_DIV1;
  RCC_OscInitStruct.PLL.PLLN = 32;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV2;

  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Configure the SYSCLKSource, HCLK, PCLK1 and PCLK2 clocks dividers
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK4 | RCC_CLOCKTYPE_HCLK2
                              | RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
                              | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.AHBCLK2Divider = RCC_SYSCLK_DIV2;
  RCC_ClkInitStruct.AHBCLK4Divider = RCC_SYSCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_3) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief Peripherals Common Clock Configuration
  * @retval None
  */
void PeriphCommonClock_Config(void)
{
  RCC_PeriphCLKInitTypeDef PeriphClkInitStruct = {0};

  /** Initializes the peripherals clock
  */
  PeriphClkInitStruct.PeriphClockSelection = RCC_PERIPHCLK_SMPS;
  PeriphClkInitStruct.SmpsClockSelection = RCC_SMPSCLKSOURCE_HSI;
  PeriphClkInitStruct.SmpsDivSelection = RCC_SMPSCLKDIV_RANGE0;

  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN Smps */

  /* USER CODE END Smps */
}

/* USER CODE BEGIN 4 */
int _write(int file, char *ptr, int len)
{
    (void) file;

    if (len <= 0) {
        return len;
    }

    if (tls_port_log_write((const unsigned char *) ptr, (size_t) len) < 0) {
        for (int i = 0; i < len; i++) {
            ITM_SendChar(*ptr++);
        }
    }

    return len;
}
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  printf("Wrong parameters value: file %s on line %lu\r\n", file, (unsigned long) line);
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
