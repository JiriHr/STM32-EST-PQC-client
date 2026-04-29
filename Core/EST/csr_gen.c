#include "csr_gen.h"

#include <string.h>
#include <stdio.h>

/*
 * Minimal PKCS#10 CSR DER encoder.
 *
 * This does NOT use Mbed TLS CSR generation.
 * It builds:
 *
 * CertificationRequest ::= SEQUENCE {
 *     certificationRequestInfo CertificationRequestInfo,
 *     signatureAlgorithm       AlgorithmIdentifier,
 *     signature                BIT STRING
 * }
 *
 * The public key and signature are supplied externally.
 * For ML-DSA, build the CertificationRequestInfo first, sign those
 * exact DER bytes, then assemble the final CSR.
 */

/* RFC 9881 id-ml-dsa-44:
 * 2.16.840.1.101.3.4.3.17
 *
 * ML-DSA AlgorithmIdentifier parameters are absent.
 */
static const uint8_t OID_MLDSA_44[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
};

/* OID: commonName = 2.5.4.3 */
static const uint8_t OID_COMMON_NAME[] = {
    0x55, 0x04, 0x03
};

static uint8_t *der_write_raw(uint8_t *p, const uint8_t *buf, size_t len)
{
    p -= len;
    memcpy(p, buf, len);
    return p;
}

static uint8_t *der_write_tag(uint8_t *p, uint8_t tag)
{
    *--p = tag;
    return p;
}

static uint8_t *der_write_len(uint8_t *p, size_t len)
{
    if (len < 128U) {
        *--p = (uint8_t) len;
        return p;
    }

    if (len <= 0xFFU) {
        *--p = (uint8_t) len;
        *--p = 0x81;
        return p;
    }

    if (len <= 0xFFFFU) {
        *--p = (uint8_t) (len & 0xFFU);
        *--p = (uint8_t) ((len >> 8) & 0xFFU);
        *--p = 0x82;
        return p;
    }

    if (len <= 0xFFFFFFU) {
        *--p = (uint8_t) (len & 0xFFU);
        *--p = (uint8_t) ((len >> 8) & 0xFFU);
        *--p = (uint8_t) ((len >> 16) & 0xFFU);
        *--p = 0x83;
        return p;
    }

    *--p = (uint8_t) (len & 0xFFU);
    *--p = (uint8_t) ((len >> 8) & 0xFFU);
    *--p = (uint8_t) ((len >> 16) & 0xFFU);
    *--p = (uint8_t) ((len >> 24) & 0xFFU);
    *--p = 0x84;
    return p;
}

static uint8_t *der_wrap(uint8_t *p, uint8_t tag, size_t content_len)
{
    p = der_write_len(p, content_len);
    p = der_write_tag(p, tag);
    return p;
}

static uint8_t *der_write_integer_zero(uint8_t *p)
{
    *--p = 0x00;
    p = der_write_len(p, 1);
    p = der_write_tag(p, 0x02);
    return p;
}

static uint8_t *der_write_oid(uint8_t *p, const uint8_t *oid, size_t oid_len)
{
    p = der_write_raw(p, oid, oid_len);
    p = der_write_len(p, oid_len);
    p = der_write_tag(p, 0x06);
    return p;
}

static uint8_t *der_write_utf8_string(uint8_t *p, const char *s)
{
    size_t len = strlen(s);

    p = der_write_raw(p, (const uint8_t *) s, len);
    p = der_write_len(p, len);
    p = der_write_tag(p, 0x0C);

    return p;
}

static uint8_t *der_write_bit_string(uint8_t *p, const uint8_t *buf, size_t len)
{
    /*
     * DER BIT STRING:
     *
     *   03 <length> 00 <payload>
     *
     * The first content byte is the number of unused bits.
     * For byte-aligned key/signature payloads this must be 0.
     *
     * Important: because we write backwards, write payload first,
     * then prepend the unused-bits byte.
     */
    p = der_write_raw(p, buf, len);
    *--p = 0x00;
    p = der_write_len(p, len + 1U);
    p = der_write_tag(p, 0x03);

    return p;
}

static uint8_t *der_write_algorithm_identifier(uint8_t *p)
{
    uint8_t *start = p;

    p = der_write_oid(p, OID_MLDSA_44, sizeof(OID_MLDSA_44));

    p = der_wrap(p, 0x30, (size_t) (start - p));
    return p;
}

static uint8_t *der_write_subject(uint8_t *p, const char *common_name)
{
    /*
     * Name ::= SEQUENCE OF RelativeDistinguishedName
     *
     * For CN=device-01:
     *
     * SEQUENCE {
     *   SET {
     *     SEQUENCE {
     *       OID commonName
     *       UTF8String common_name
     *     }
     *   }
     * }
     */

    uint8_t *name_start;
    uint8_t *set_start;
    uint8_t *attr_start;

    name_start = p;

    set_start = p;

    attr_start = p;

    /* AttributeTypeAndValue value */
    p = der_write_utf8_string(p, common_name);

    /* AttributeTypeAndValue type = commonName */
    p = der_write_oid(p, OID_COMMON_NAME, sizeof(OID_COMMON_NAME));

    /* AttributeTypeAndValue SEQUENCE */
    p = der_wrap(p, 0x30, (size_t) (attr_start - p));

    /* RDN SET */
    p = der_wrap(p, 0x31, (size_t) (set_start - p));

    /* Name SEQUENCE */
    p = der_wrap(p, 0x30, (size_t) (name_start - p));

    return p;
}

static uint8_t *der_write_subject_public_key_info(uint8_t *p,
                                                  const uint8_t *pubkey,
                                                  size_t pubkey_len)
{
    /*
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *     algorithm        AlgorithmIdentifier,
     *     subjectPublicKey BIT STRING
     * }
     */

    uint8_t *start = p;

    /* subjectPublicKey is second, so write it first when writing backwards */
    p = der_write_bit_string(p, pubkey, pubkey_len);

    /* algorithm is first */
    p = der_write_algorithm_identifier(p);

    p = der_wrap(p, 0x30, (size_t) (start - p));

    return p;
}

static uint8_t *der_write_empty_attributes(uint8_t *p)
{
    /*
     * CertificationRequestInfo attributes field:
     *
     * attributes [0] Attributes
     *
     * For empty attributes, DER encoding is:
     *
     *   A0 00
     */
    p = der_write_len(p, 0);
    p = der_write_tag(p, 0xA0);
    return p;
}

static uint8_t *der_write_certification_request_info(uint8_t *p,
                                                     const char *common_name,
                                                     const uint8_t *pubkey,
                                                     size_t pubkey_len)
{
    /*
     * CertificationRequestInfo ::= SEQUENCE {
     *     version       INTEGER { v1(0) },
     *     subject       Name,
     *     subjectPKInfo SubjectPublicKeyInfo,
     *     attributes    [0] Attributes
     * }
     */

    uint8_t *start = p;

    /* attributes is last */
    p = der_write_empty_attributes(p);

    /* subjectPKInfo */
    p = der_write_subject_public_key_info(p, pubkey, pubkey_len);

    /* subject */
    p = der_write_subject(p, common_name);

    /* version = 0 */
    p = der_write_integer_zero(p);

    p = der_wrap(p, 0x30, (size_t) (start - p));

    return p;
}

int csr_build_certification_request_info(const char *common_name,
                                         const uint8_t *pubkey,
                                         size_t pubkey_len,
                                         uint8_t *out,
                                         size_t out_size,
                                         size_t *out_len)
{
    uint8_t *p;

    if (common_name == NULL ||
        pubkey == NULL ||
        pubkey_len == 0 ||
        out == NULL ||
        out_size == 0 ||
        out_len == NULL) {
        return -1;
    }

    p = out + out_size;
    p = der_write_certification_request_info(p, common_name, pubkey, pubkey_len);

    *out_len = (size_t) ((out + out_size) - p);
    memmove(out, p, *out_len);

    printf("CSR CRI generated (%u bytes)\r\n", (unsigned) *out_len);

    return 0;
}

int csr_assemble(const uint8_t *cri,
                 size_t cri_len,
                 const uint8_t *signature,
                 size_t signature_len,
                 uint8_t *out,
                 size_t out_size,
                 size_t *out_len)
{
    uint8_t *p;
    uint8_t *start;

    if (cri == NULL ||
        cri_len == 0 ||
        signature == NULL ||
        signature_len == 0 ||
        out == NULL ||
        out_size == 0 ||
        out_len == NULL) {
        return -1;
    }

    p = out + out_size;
    start = p;

    /* signature BIT STRING */
    p = der_write_bit_string(p, signature, signature_len);

    /* signatureAlgorithm */
    p = der_write_algorithm_identifier(p);

    /* certificationRequestInfo */
    p = der_write_raw(p, cri, cri_len);

    /* final CSR SEQUENCE */
    p = der_wrap(p, 0x30, (size_t) (start - p));

    *out_len = (size_t) ((out + out_size) - p);
    memmove(out, p, *out_len);

    printf("CSR assembled (%u bytes)\r\n", (unsigned) *out_len);

    return 0;
}

int csr_generate(const char *common_name,
                 const uint8_t *pubkey,
                 size_t pubkey_len,
                 const uint8_t *signature,
                 size_t signature_len,
                 uint8_t *out,
                 size_t out_size,
                 size_t *out_len)
{
    uint8_t *p;
    uint8_t *start;

    if (common_name == NULL ||
        pubkey == NULL ||
        pubkey_len == 0 ||
        signature == NULL ||
        signature_len == 0 ||
        out == NULL ||
        out_size == 0 ||
        out_len == NULL) {
        return -1;
    }

    p = out + out_size;
    start = p;

    /*
     * CertificationRequest ::= SEQUENCE {
     *     certificationRequestInfo CertificationRequestInfo,
     *     signatureAlgorithm       AlgorithmIdentifier,
     *     signature                BIT STRING
     * }
     *
     * Writing backwards:
     *   1. signature
     *   2. signatureAlgorithm
     *   3. certificationRequestInfo
     *   4. wrap final SEQUENCE
     */

    /* signature BIT STRING */
    p = der_write_bit_string(p, signature, signature_len);

    /* signatureAlgorithm */
    p = der_write_algorithm_identifier(p);

    /* certificationRequestInfo */
    p = der_write_certification_request_info(p, common_name, pubkey, pubkey_len);

    /* final CSR SEQUENCE */
    p = der_wrap(p, 0x30, (size_t) (start - p));

    *out_len = (size_t) ((out + out_size) - p);

    memmove(out, p, *out_len);

    printf("CSR generated (%u bytes)\r\n", (unsigned) *out_len);

    return 0;
}
