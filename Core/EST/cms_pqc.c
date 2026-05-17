#include "cms_pqc.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "est_measure.h"
#include "pqc_mldsa44.h"
#include "pqc_mlkem512.h"
#include "../Middlewares/PQC/common/fips202.h"
#include "psa/crypto.h"

#define CMS_PQC_BUF_SIZE 4096U
#define CMS_PQC_PLAINTEXT_LEN 32U
#define CMS_PQC_KDF_LABEL "cms-pqc-ml-kem-512-demo-v1"
#define CMS_PQC_KDF_LABEL_LEN (sizeof(CMS_PQC_KDF_LABEL) - 1U)
#define CMS_PQC_AES_KEY_LEN 16U
#define CMS_PQC_AES_GCM_NONCE_LEN 12U
#define CMS_PQC_AES_GCM_TAG_LEN 16U
#define CMS_PQC_ENCRYPTED_LEN (CMS_PQC_PLAINTEXT_LEN + CMS_PQC_AES_GCM_TAG_LEN)

/* OID content bytes, without ASN.1 tag/length. */
static const uint8_t OID_CMS_DATA[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
};
static const uint8_t OID_CMS_SIGNED_DATA[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
};
static const uint8_t OID_CMS_ENVELOPED_DATA[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03
};
static const uint8_t OID_ORI_KEM[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x0D, 0x03
};
static const uint8_t OID_MLKEM512[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01
};
static const uint8_t OID_MLDSA44[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
};
static const uint8_t OID_HKDF_SHA256[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x1C
};
static const uint8_t OID_AES128_WRAP[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05
};
static const uint8_t OID_AES128_GCM[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06
};

static uint8_t g_cms_buf[CMS_PQC_BUF_SIZE];
static uint8_t g_mldsa_pk[PQC_MLDSA44_PUBLICKEYBYTES];
static uint8_t g_mldsa_sk[PQC_MLDSA44_SECRETKEYBYTES];
static uint8_t g_mldsa_sig[PQC_MLDSA44_SIGNATUREBYTES];
static uint8_t g_kem_pk[PQC_MLKEM512_PUBLICKEYBYTES];
static uint8_t g_kem_sk[PQC_MLKEM512_SECRETKEYBYTES];
static uint8_t g_kem_ct[PQC_MLKEM512_CIPHERTEXTBYTES];
static uint8_t g_ss_originator[PQC_MLKEM512_SHAREDSECRETBYTES];
static uint8_t g_ss_recipient[PQC_MLKEM512_SHAREDSECRETBYTES];
static uint8_t g_plaintext[CMS_PQC_PLAINTEXT_LEN];
static uint8_t g_encrypted[CMS_PQC_ENCRYPTED_LEN];
static uint8_t g_decrypted[CMS_PQC_PLAINTEXT_LEN];
static uint8_t g_aes_key[CMS_PQC_AES_KEY_LEN];
static uint8_t g_aes_nonce[CMS_PQC_AES_GCM_NONCE_LEN];
static uint8_t g_kdf_output[CMS_PQC_AES_KEY_LEN + CMS_PQC_AES_GCM_NONCE_LEN];
static uint8_t g_kdf_input[CMS_PQC_KDF_LABEL_LEN +
                           PQC_MLKEM512_SHAREDSECRETBYTES +
                           PQC_MLKEM512_CIPHERTEXTBYTES];

typedef struct {
    uint8_t *buf;
    size_t size;
    size_t len;
} der_writer_t;

static int der_put(der_writer_t *w, const uint8_t *buf, size_t len)
{
    if (w == NULL || (buf == NULL && len != 0U) || w->len + len > w->size) {
        return -1;
    }

    if (len != 0U) {
        memcpy(w->buf + w->len, buf, len);
    }
    w->len += len;
    return 0;
}

static int der_put_len(der_writer_t *w, size_t len)
{
    uint8_t tmp[5];
    size_t n = 0;
    size_t i;

    if (len < 128U) {
        tmp[0] = (uint8_t) len;
        return der_put(w, tmp, 1U);
    }

    for (i = len; i != 0U; i >>= 8) {
        n++;
    }

    tmp[0] = (uint8_t) (0x80U | n);
    for (i = 0; i < n; i++) {
        tmp[1U + i] = (uint8_t) (len >> (8U * (n - 1U - i)));
    }

    return der_put(w, tmp, 1U + n);
}

static int der_put_tlv_header(der_writer_t *w, uint8_t tag, size_t len)
{
    if (der_put(w, &tag, 1U) != 0) {
        return -1;
    }
    return der_put_len(w, len);
}

static size_t der_len_len(size_t len)
{
    size_t n = 0;

    if (len < 128U) {
        return 1U;
    }

    while (len != 0U) {
        n++;
        len >>= 8;
    }

    return 1U + n;
}

static size_t der_tlv_len(size_t content_len)
{
    return 1U + der_len_len(content_len) + content_len;
}

static size_t der_alg_id_len(size_t oid_len)
{
    return der_tlv_len(der_tlv_len(oid_len));
}

static int der_put_oid(der_writer_t *w, const uint8_t *oid, size_t oid_len)
{
    if (der_put_tlv_header(w, 0x06U, oid_len) != 0) {
        return -1;
    }
    return der_put(w, oid, oid_len);
}

static int der_put_integer_u8(der_writer_t *w, uint8_t value)
{
    if (der_put_tlv_header(w, 0x02U, 1U) != 0) {
        return -1;
    }
    return der_put(w, &value, 1U);
}

static int der_put_octet_string(der_writer_t *w, const uint8_t *buf, size_t len)
{
    if (der_put_tlv_header(w, 0x04U, len) != 0) {
        return -1;
    }
    return der_put(w, buf, len);
}

static int der_put_algorithm_identifier(der_writer_t *w, const uint8_t *oid, size_t oid_len)
{
    size_t oid_tlv_len = der_tlv_len(oid_len);

    if (der_put_tlv_header(w, 0x30U, oid_tlv_len) != 0) {
        return -1;
    }
    return der_put_oid(w, oid, oid_len);
}

static int der_put_algorithm_identifier_params(der_writer_t *w,
                                               const uint8_t *oid,
                                               size_t oid_len,
                                               const uint8_t *params,
                                               size_t params_len)
{
    size_t oid_tlv_len = der_tlv_len(oid_len);

    if (der_put_tlv_header(w, 0x30U, oid_tlv_len + params_len) != 0 ||
        der_put_oid(w, oid, oid_len) != 0) {
        return -1;
    }

    return der_put(w, params, params_len);
}

static int der_read_tlv(const uint8_t *buf,
                        size_t buf_len,
                        size_t off,
                        uint8_t *tag,
                        size_t *hdr_len,
                        size_t *content_len)
{
    size_t len_len;
    size_t len = 0;
    size_t i;

    if (buf == NULL || tag == NULL || hdr_len == NULL || content_len == NULL || off + 2U > buf_len) {
        return -1;
    }

    *tag = buf[off];
    if ((buf[off + 1U] & 0x80U) == 0U) {
        *hdr_len = 2U;
        *content_len = buf[off + 1U];
        return (off + *hdr_len + *content_len <= buf_len) ? 0 : -1;
    }

    len_len = (size_t) (buf[off + 1U] & 0x7FU);
    if (len_len == 0U || len_len > sizeof(size_t) || off + 2U + len_len > buf_len) {
        return -1;
    }

    for (i = 0; i < len_len; i++) {
        len = (len << 8) | buf[off + 2U + i];
    }

    *hdr_len = 2U + len_len;
    *content_len = len;
    return (off + *hdr_len + len <= buf_len) ? 0 : -1;
}

static int cms_find_tlv_after_oid(const uint8_t *cms,
                                  size_t cms_len,
                                  const uint8_t *oid,
                                  size_t oid_len,
                                  uint8_t wanted_tag,
                                  const uint8_t **out_content,
                                  size_t *out_len)
{
    size_t i;

    if (cms == NULL || oid == NULL || out_content == NULL || out_len == NULL) {
        return -1;
    }

    for (i = 0; i + 2U + oid_len < cms_len; i++) {
        uint8_t tag;
        size_t hdr_len;
        size_t content_len;
        size_t off;

        if (cms[i] != 0x06U || cms[i + 1U] != oid_len || memcmp(cms + i + 2U, oid, oid_len) != 0) {
            continue;
        }

        off = i + 2U + oid_len;
        while (off < cms_len) {
            if (der_read_tlv(cms, cms_len, off, &tag, &hdr_len, &content_len) != 0) {
                return -1;
            }

            if (tag == wanted_tag) {
                *out_content = cms + off + hdr_len;
                *out_len = content_len;
                return 0;
            }
            off += hdr_len + content_len;
        }
    }

    return -1;
}

static int cms_find_octet_string_by_len(const uint8_t *cms,
                                        size_t cms_len,
                                        size_t wanted_len,
                                        const uint8_t **out_content)
{
    size_t off = 0;

    if (cms == NULL || out_content == NULL) {
        return -1;
    }

    while (off < cms_len) {
        uint8_t tag;
        size_t hdr_len;
        size_t content_len;

        if (der_read_tlv(cms, cms_len, off, &tag, &hdr_len, &content_len) != 0) {
            off++;
            continue;
        }

        if (tag == 0x04U && content_len == wanted_len) {
            *out_content = cms + off + hdr_len;
            return 0;
        }

        off++;
    }

    return -1;
}

static int cms_pqc_build_signed_data(const uint8_t *content,
                                     size_t content_len,
                                     const uint8_t *signature,
                                     size_t signature_len,
                                     uint8_t *out,
                                     size_t out_size,
                                     size_t *out_len)
{
    der_writer_t w = { out, out_size, 0U };
    size_t alg_mldsa_len = der_alg_id_len(sizeof(OID_MLDSA44));
    size_t digest_algorithms_len = der_tlv_len(alg_mldsa_len);
    size_t econtent_octet_len = der_tlv_len(content_len);
    size_t econtent_explicit_len = der_tlv_len(econtent_octet_len);
    size_t encap_content_info_content_len = der_tlv_len(sizeof(OID_CMS_DATA)) + econtent_explicit_len;
    size_t encap_content_info_len = der_tlv_len(encap_content_info_content_len);
    size_t signer_info_content_len = der_tlv_len(1U) + der_tlv_len(0U) + alg_mldsa_len +
                                     alg_mldsa_len + der_tlv_len(signature_len);
    size_t signer_info_len = der_tlv_len(signer_info_content_len);
    size_t signer_infos_len = der_tlv_len(signer_info_len);
    size_t signed_data_content_len = der_tlv_len(1U) + digest_algorithms_len +
                                     encap_content_info_len + signer_infos_len;
    size_t signed_data_len = der_tlv_len(signed_data_content_len);
    size_t content_info_content_len = der_tlv_len(sizeof(OID_CMS_SIGNED_DATA)) + der_tlv_len(signed_data_len);

    if (content == NULL || signature == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    if (der_put_tlv_header(&w, 0x30U, content_info_content_len) != 0 ||
        der_put_oid(&w, OID_CMS_SIGNED_DATA, sizeof(OID_CMS_SIGNED_DATA)) != 0 ||
        der_put_tlv_header(&w, 0xA0U, signed_data_len) != 0 ||
        der_put_tlv_header(&w, 0x30U, signed_data_content_len) != 0 ||
        der_put_integer_u8(&w, 1U) != 0 ||
        der_put_tlv_header(&w, 0x31U, alg_mldsa_len) != 0 ||
        der_put_algorithm_identifier(&w, OID_MLDSA44, sizeof(OID_MLDSA44)) != 0 ||
        der_put_tlv_header(&w, 0x30U, encap_content_info_content_len) != 0 ||
        der_put_oid(&w, OID_CMS_DATA, sizeof(OID_CMS_DATA)) != 0 ||
        der_put_tlv_header(&w, 0xA0U, econtent_octet_len) != 0 ||
        der_put_octet_string(&w, content, content_len) != 0 ||
        der_put_tlv_header(&w, 0x31U, signer_info_len) != 0 ||
        der_put_tlv_header(&w, 0x30U, signer_info_content_len) != 0 ||
        der_put_integer_u8(&w, 1U) != 0 ||
        der_put_tlv_header(&w, 0x80U, 0U) != 0 ||
        der_put_algorithm_identifier(&w, OID_MLDSA44, sizeof(OID_MLDSA44)) != 0 ||
        der_put_algorithm_identifier(&w, OID_MLDSA44, sizeof(OID_MLDSA44)) != 0 ||
        der_put_octet_string(&w, signature, signature_len) != 0) {
        return -1;
    }

    *out_len = w.len;
    return 0;
}

static int cms_pqc_signed_data_self_test(void)
{
    const uint8_t *parsed_sig = NULL;
    size_t sig_len = 0;
    size_t cms_len = 0;
    size_t i;
    uint32_t measure_start;
    uint32_t measure_total = est_measure_start();
    int ret;

    for (i = 0; i < sizeof(g_plaintext); i++) {
        g_plaintext[i] = (uint8_t) ('a' + (i % 26U));
    }

    measure_start = est_measure_start();
    ret = pqc_mldsa44_keypair(g_mldsa_pk, g_mldsa_sk);
    if (ret != 0) {
        printf("ML-DSA-44 CMS keypair failed: %d\r\n", ret);
        return -1;
    }
    est_measure_cycles("cms_signed_mldsa_keypair", est_measure_elapsed(measure_start));

    measure_start = est_measure_start();
    ret = pqc_mldsa44_sign(g_mldsa_sig,
                           &sig_len,
                           g_plaintext,
                           sizeof(g_plaintext),
                           g_mldsa_sk);
    if (ret != 0) {
        printf("ML-DSA-44 CMS signing failed: %d\r\n", ret);
        return -1;
    }
    est_measure_cycles("cms_signed_mldsa_sign", est_measure_elapsed(measure_start));
    est_measure_size("cms_signed_mldsa_signature", sig_len);

    measure_start = est_measure_start();
    ret = cms_pqc_build_signed_data(g_plaintext,
                                    sizeof(g_plaintext),
                                    g_mldsa_sig,
                                    sig_len,
                                    g_cms_buf,
                                    sizeof(g_cms_buf),
                                    &cms_len);
    if (ret != 0) {
        printf("CMS SignedData assembly failed\r\n");
        return -1;
    }
    est_measure_cycles("cms_signed_assemble", est_measure_elapsed(measure_start));
    est_measure_size("cms_signed_der", cms_len);

    measure_start = est_measure_start();
    ret = cms_find_octet_string_by_len(g_cms_buf, cms_len, sig_len, &parsed_sig);
    if (ret != 0) {
        printf("CMS SignedData signature parse failed\r\n");
        return -1;
    }
    est_measure_cycles("cms_signed_parse_signature", est_measure_elapsed(measure_start));

    measure_start = est_measure_start();
    ret = pqc_mldsa44_verify(parsed_sig,
                             sig_len,
                             g_plaintext,
                             sizeof(g_plaintext),
                             g_mldsa_pk);
    if (ret != 0) {
        printf("CMS SignedData ML-DSA verification failed: %d\r\n", ret);
        return -1;
    }
    est_measure_cycles("cms_signed_mldsa_verify", est_measure_elapsed(measure_start));
    est_measure_cycles("cms_signed_total", est_measure_elapsed(measure_total));

    printf("CMS SignedData ML-DSA-44 self-test OK (cms_der=%u sig=%u)\r\n",
           (unsigned) cms_len,
           (unsigned) sig_len);

    return 0;
}

static void cms_pqc_derive_aes_material(const uint8_t *ss, const uint8_t *ct)
{
    size_t pos = 0;

    memcpy(g_kdf_input + pos, CMS_PQC_KDF_LABEL, CMS_PQC_KDF_LABEL_LEN);
    pos += CMS_PQC_KDF_LABEL_LEN;
    memcpy(g_kdf_input + pos, ss, PQC_MLKEM512_SHAREDSECRETBYTES);
    pos += PQC_MLKEM512_SHAREDSECRETBYTES;
    memcpy(g_kdf_input + pos, ct, PQC_MLKEM512_CIPHERTEXTBYTES);
    pos += PQC_MLKEM512_CIPHERTEXTBYTES;

    shake256(g_kdf_output, sizeof(g_kdf_output), g_kdf_input, pos);
    memcpy(g_aes_key, g_kdf_output, sizeof(g_aes_key));
    memcpy(g_aes_nonce, g_kdf_output + sizeof(g_aes_key), sizeof(g_aes_nonce));
}

static int cms_pqc_aes_gcm_encrypt(const uint8_t *plaintext,
                                   size_t plaintext_len,
                                   uint8_t *ciphertext,
                                   size_t ciphertext_size,
                                   size_t *ciphertext_len)
{
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;

    if (plaintext == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return -1;
    }

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128U);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    status = psa_import_key(&attrs, g_aes_key, sizeof(g_aes_key), &key_id);
    psa_reset_key_attributes(&attrs);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    status = psa_aead_encrypt(key_id,
                              PSA_ALG_GCM,
                              g_aes_nonce,
                              sizeof(g_aes_nonce),
                              NULL,
                              0U,
                              plaintext,
                              plaintext_len,
                              ciphertext,
                              ciphertext_size,
                              ciphertext_len);

    (void) psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

static int cms_pqc_aes_gcm_decrypt(const uint8_t *ciphertext,
                                   size_t ciphertext_len,
                                   uint8_t *plaintext,
                                   size_t plaintext_size,
                                   size_t *plaintext_len)
{
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;

    if (ciphertext == NULL || plaintext == NULL || plaintext_len == NULL) {
        return -1;
    }

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128U);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    status = psa_import_key(&attrs, g_aes_key, sizeof(g_aes_key), &key_id);
    psa_reset_key_attributes(&attrs);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    status = psa_aead_decrypt(key_id,
                              PSA_ALG_GCM,
                              g_aes_nonce,
                              sizeof(g_aes_nonce),
                              NULL,
                              0U,
                              ciphertext,
                              ciphertext_len,
                              plaintext,
                              plaintext_size,
                              plaintext_len);

    (void) psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

static int cms_pqc_write_aes_gcm_params(uint8_t *out, size_t out_size, size_t *out_len)
{
    der_writer_t w = { out, out_size, 0U };
    size_t nonce_len = der_tlv_len(sizeof(g_aes_nonce));
    size_t tag_len = der_tlv_len(1U);

    if (out == NULL || out_len == NULL) {
        return -1;
    }

    if (der_put_tlv_header(&w, 0x30U, nonce_len + tag_len) != 0 ||
        der_put_octet_string(&w, g_aes_nonce, sizeof(g_aes_nonce)) != 0 ||
        der_put_integer_u8(&w, CMS_PQC_AES_GCM_TAG_LEN) != 0) {
        return -1;
    }

    *out_len = w.len;
    return 0;
}

static int cms_pqc_build_enveloped_data(const uint8_t *kem_ct,
                                        const uint8_t *encrypted_content,
                                        size_t encrypted_content_len,
                                        const uint8_t *content_alg_params,
                                        size_t content_alg_params_len,
                                        uint8_t *out,
                                        size_t out_size,
                                        size_t *out_len)
{
    der_writer_t w = { out, out_size, 0U };
    size_t alg_mlkem_len = der_alg_id_len(sizeof(OID_MLKEM512));
    size_t alg_hkdf_len = der_alg_id_len(sizeof(OID_HKDF_SHA256));
    size_t alg_wrap_len = der_alg_id_len(sizeof(OID_AES128_WRAP));
    size_t alg_content_len = der_tlv_len(der_tlv_len(sizeof(OID_AES128_GCM)) + content_alg_params_len);
    size_t rid_len = der_tlv_len(0U);
    size_t kemct_len = der_tlv_len(PQC_MLKEM512_CIPHERTEXTBYTES);
    size_t encrypted_key_len = der_tlv_len(0U);
    size_t kemri_content_len;
    size_t kemri_len;
    size_t ori_content_len;
    size_t ori_len;
    size_t recipient_infos_len;
    size_t encrypted_content_info_content_len;
    size_t encrypted_content_info_len;
    size_t enveloped_data_content_len;
    size_t enveloped_data_len;
    size_t content_info_content_len;

    if (kem_ct == NULL ||
        encrypted_content == NULL ||
        content_alg_params == NULL ||
        out == NULL ||
        out_len == NULL) {
        return -1;
    }

    kemri_content_len = der_tlv_len(1U) + rid_len + alg_mlkem_len + kemct_len +
                        alg_hkdf_len + der_tlv_len(1U) + alg_wrap_len + encrypted_key_len;
    kemri_len = der_tlv_len(kemri_content_len);
    ori_content_len = der_tlv_len(sizeof(OID_ORI_KEM)) + kemri_len;
    ori_len = der_tlv_len(ori_content_len);
    recipient_infos_len = der_tlv_len(ori_len);
    encrypted_content_info_content_len = der_tlv_len(sizeof(OID_CMS_DATA)) + alg_content_len +
                                         der_tlv_len(encrypted_content_len);
    encrypted_content_info_len = der_tlv_len(encrypted_content_info_content_len);
    enveloped_data_content_len = der_tlv_len(1U) + recipient_infos_len + encrypted_content_info_len;
    enveloped_data_len = der_tlv_len(enveloped_data_content_len);
    content_info_content_len = der_tlv_len(sizeof(OID_CMS_ENVELOPED_DATA)) + der_tlv_len(enveloped_data_len);

    if (der_put_tlv_header(&w, 0x30U, content_info_content_len) != 0 ||
        der_put_oid(&w, OID_CMS_ENVELOPED_DATA, sizeof(OID_CMS_ENVELOPED_DATA)) != 0 ||
        der_put_tlv_header(&w, 0xA0U, enveloped_data_len) != 0 ||
        der_put_tlv_header(&w, 0x30U, enveloped_data_content_len) != 0 ||
        der_put_integer_u8(&w, 2U) != 0 ||
        der_put_tlv_header(&w, 0x31U, ori_len) != 0 ||
        der_put_tlv_header(&w, 0xA4U, ori_content_len) != 0 ||
        der_put_oid(&w, OID_ORI_KEM, sizeof(OID_ORI_KEM)) != 0 ||
        der_put_tlv_header(&w, 0x30U, kemri_content_len) != 0 ||
        der_put_integer_u8(&w, 0U) != 0 ||
        der_put_tlv_header(&w, 0x80U, 0U) != 0 ||
        der_put_algorithm_identifier(&w, OID_MLKEM512, sizeof(OID_MLKEM512)) != 0 ||
        der_put_octet_string(&w, kem_ct, PQC_MLKEM512_CIPHERTEXTBYTES) != 0 ||
        der_put_algorithm_identifier(&w, OID_HKDF_SHA256, sizeof(OID_HKDF_SHA256)) != 0 ||
        der_put_integer_u8(&w, 16U) != 0 ||
        der_put_algorithm_identifier(&w, OID_AES128_WRAP, sizeof(OID_AES128_WRAP)) != 0 ||
        der_put_octet_string(&w, NULL, 0U) != 0 ||
        der_put_tlv_header(&w, 0x30U, encrypted_content_info_content_len) != 0 ||
        der_put_oid(&w, OID_CMS_DATA, sizeof(OID_CMS_DATA)) != 0 ||
        der_put_algorithm_identifier_params(&w,
                                            OID_AES128_GCM,
                                            sizeof(OID_AES128_GCM),
                                            content_alg_params,
                                            content_alg_params_len) != 0 ||
        der_put_tlv_header(&w, 0x80U, encrypted_content_len) != 0 ||
        der_put(&w, encrypted_content, encrypted_content_len) != 0) {
        return -1;
    }

    *out_len = w.len;
    return 0;
}

static int cms_pqc_enveloped_data_self_test(void)
{
    const uint8_t *parsed_ct = NULL;
    const uint8_t *parsed_encrypted = NULL;
    size_t parsed_ct_len = 0;
    size_t parsed_encrypted_len = 0;
    size_t cms_len = 0;
    size_t encrypted_len = 0;
    size_t decrypted_len = 0;
    uint8_t aes_gcm_params[32];
    size_t aes_gcm_params_len = 0;
    size_t i;
    uint32_t measure_start;
    uint32_t measure_total = est_measure_start();
    int ret;

    for (i = 0; i < sizeof(g_plaintext); i++) {
        g_plaintext[i] = (uint8_t) ('A' + (i % 26U));
    }

    measure_start = est_measure_start();
    ret = pqc_mlkem512_keypair(g_kem_pk, g_kem_sk);
    if (ret != 0) {
        printf("ML-KEM-512 keypair failed: %d\r\n", ret);
        return -1;
    }
    est_measure_cycles("cms_enveloped_mlkem_keypair", est_measure_elapsed(measure_start));
    est_measure_size("mlkem_public_key", PQC_MLKEM512_PUBLICKEYBYTES);
    est_measure_size("mlkem_secret_key", PQC_MLKEM512_SECRETKEYBYTES);

    measure_start = est_measure_start();
    ret = pqc_mlkem512_enc(g_kem_ct, g_ss_originator, g_kem_pk);
    if (ret != 0) {
        printf("ML-KEM-512 encapsulation failed: %d\r\n", ret);
        return -1;
    }
    est_measure_cycles("cms_enveloped_mlkem_encapsulate", est_measure_elapsed(measure_start));
    est_measure_size("mlkem_ciphertext", PQC_MLKEM512_CIPHERTEXTBYTES);
    est_measure_size("mlkem_shared_secret", PQC_MLKEM512_SHAREDSECRETBYTES);

    measure_start = est_measure_start();
    cms_pqc_derive_aes_material(g_ss_originator, g_kem_ct);
    est_measure_cycles("cms_enveloped_kdf_originator", est_measure_elapsed(measure_start));

    measure_start = est_measure_start();
    ret = cms_pqc_aes_gcm_encrypt(g_plaintext,
                                  sizeof(g_plaintext),
                                  g_encrypted,
                                  sizeof(g_encrypted),
                                  &encrypted_len);
    if (ret != 0) {
        printf("CMS AES-128-GCM encryption failed\r\n");
        return -1;
    }
    est_measure_cycles("cms_enveloped_aes_gcm_encrypt", est_measure_elapsed(measure_start));
    est_measure_size("cms_enveloped_encrypted_content", encrypted_len);

    measure_start = est_measure_start();
    ret = cms_pqc_write_aes_gcm_params(aes_gcm_params, sizeof(aes_gcm_params), &aes_gcm_params_len);
    if (ret != 0) {
        printf("CMS AES-128-GCM parameter encoding failed\r\n");
        return -1;
    }
    est_measure_cycles("cms_enveloped_aes_gcm_params", est_measure_elapsed(measure_start));

    measure_start = est_measure_start();
    ret = cms_pqc_build_enveloped_data(g_kem_ct,
                                       g_encrypted,
                                       encrypted_len,
                                       aes_gcm_params,
                                       aes_gcm_params_len,
                                       g_cms_buf,
                                       sizeof(g_cms_buf),
                                       &cms_len);
    if (ret != 0) {
        printf("CMS EnvelopedData assembly failed\r\n");
        return -1;
    }
    est_measure_cycles("cms_enveloped_assemble", est_measure_elapsed(measure_start));
    est_measure_size("cms_enveloped_der", cms_len);

    measure_start = est_measure_start();
    ret = cms_find_tlv_after_oid(g_cms_buf,
                                 cms_len,
                                 OID_MLKEM512,
                                 sizeof(OID_MLKEM512),
                                 0x04U,
                                 &parsed_ct,
                                 &parsed_ct_len);
    if (ret != 0 || parsed_ct_len != PQC_MLKEM512_CIPHERTEXTBYTES) {
        printf("CMS ML-KEM ciphertext parse failed\r\n");
        return -1;
    }
    est_measure_cycles("cms_enveloped_parse_ciphertext", est_measure_elapsed(measure_start));

    measure_start = est_measure_start();
    ret = cms_find_tlv_after_oid(g_cms_buf,
                                 cms_len,
                                 OID_AES128_GCM,
                                 sizeof(OID_AES128_GCM),
                                 0x80U,
                                 &parsed_encrypted,
                                 &parsed_encrypted_len);
    if (ret != 0 || parsed_encrypted_len != encrypted_len) {
        printf("CMS encrypted content parse failed\r\n");
        return -1;
    }
    est_measure_cycles("cms_enveloped_parse_encrypted_content", est_measure_elapsed(measure_start));

    measure_start = est_measure_start();
    ret = pqc_mlkem512_dec(g_ss_recipient, parsed_ct, g_kem_sk);
    if (ret != 0) {
        printf("ML-KEM-512 decapsulation failed: %d\r\n", ret);
        return -1;
    }
    est_measure_cycles("cms_enveloped_mlkem_decapsulate", est_measure_elapsed(measure_start));

    if (memcmp(g_ss_originator, g_ss_recipient, sizeof(g_ss_originator)) != 0) {
        printf("ML-KEM-512 shared secret mismatch\r\n");
        return -1;
    }

    measure_start = est_measure_start();
    cms_pqc_derive_aes_material(g_ss_recipient, parsed_ct);
    est_measure_cycles("cms_enveloped_kdf_recipient", est_measure_elapsed(measure_start));

    measure_start = est_measure_start();
    ret = cms_pqc_aes_gcm_decrypt(parsed_encrypted,
                                  parsed_encrypted_len,
                                  g_decrypted,
                                  sizeof(g_decrypted),
                                  &decrypted_len);
    if (ret != 0) {
        printf("CMS AES-128-GCM decryption failed\r\n");
        return -1;
    }
    est_measure_cycles("cms_enveloped_aes_gcm_decrypt", est_measure_elapsed(measure_start));

    if (decrypted_len != sizeof(g_plaintext) ||
        memcmp(g_plaintext, g_decrypted, sizeof(g_plaintext)) != 0) {
        printf("CMS decrypted content mismatch\r\n");
        return -1;
    }

    printf("ML-KEM-512 keypair OK (pk=%u sk=%u)\r\n",
           (unsigned) PQC_MLKEM512_PUBLICKEYBYTES,
           (unsigned) PQC_MLKEM512_SECRETKEYBYTES);
    printf("ML-KEM-512 encapsulation/decapsulation OK (ct=%u ss=%u)\r\n",
           (unsigned) PQC_MLKEM512_CIPHERTEXTBYTES,
           (unsigned) PQC_MLKEM512_SHAREDSECRETBYTES);
    printf("CMS EnvelopedData ML-KEM-512 + AES-128-GCM self-test OK (cms_der=%u payload=%u encrypted=%u)\r\n",
           (unsigned) cms_len,
           (unsigned) sizeof(g_plaintext),
           (unsigned) encrypted_len);
    est_measure_cycles("cms_enveloped_total", est_measure_elapsed(measure_total));

    return 0;
}

int cms_pqc_self_test(void)
{
    int ret;

    ret = cms_pqc_signed_data_self_test();
    if (ret != 0) {
        return ret;
    }

    return cms_pqc_enveloped_data_self_test();
}
