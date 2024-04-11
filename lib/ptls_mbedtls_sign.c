/*
* Copyright (c) 2023, Christian Huitema
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to
* deal in the Software without restriction, including without limitation the
* rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
* sell copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
* IN THE SOFTWARE.
*/

#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/build_info.h"
#include "mbedtls/pk.h"
#include "mbedtls/pem.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_values.h"
#include "ptls_mbedtls.h"

static const unsigned char ptls_mbedtls_oid_ec_key[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
static const unsigned char ptls_mbedtls_oid_rsa_key[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
static const unsigned char ptls_mbedtls_oid_ed25519[] = { 0x2b, 0x65, 0x70 };

static const ptls_mbedtls_signature_scheme_t rsa_signature_schemes[] = {
    {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256, PSA_ALG_SHA_256},
    {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384, PSA_ALG_SHA_384},
    {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512, PSA_ALG_SHA_512},
    {UINT16_MAX, PSA_ALG_NONE}};
static const ptls_mbedtls_signature_scheme_t secp256r1_signature_schemes[] = {
    {PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PSA_ALG_SHA_256}, {UINT16_MAX, PSA_ALG_NONE}};
static const ptls_mbedtls_signature_scheme_t secp384r1_signature_schemes[] = {
    {PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384, PSA_ALG_SHA_384}, {UINT16_MAX, PSA_ALG_NONE}};
static const ptls_mbedtls_signature_scheme_t secp521r1_signature_schemes[] = {
    {PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512, PSA_ALG_SHA_512}, {UINT16_MAX, PSA_ALG_NONE}};
static const ptls_mbedtls_signature_scheme_t ed25519_signature_schemes[] = {
    {PTLS_SIGNATURE_ED25519, PSA_ALG_NONE}, {UINT16_MAX, PSA_ALG_NONE}};

#if defined(MBEDTLS_PEM_PARSE_C)

static int ptls_mbedtls_parse_der_length(const unsigned char* pem_buf, size_t pem_len, size_t* px, size_t *pl)
{
    int ret = 0;
    size_t x = *px;
    size_t l = pem_buf[x++];

    if (l > 128) {
        size_t ll = l & 0x7F;
        l = 0;
        while (ll > 0 && x + l < pem_len) {
            l *= 256;
            l += pem_buf[x++];
            ll--;
        }
    }

    *pl = l;
    *px = x;

    return ret;
}

static int ptls_mbedtls_parse_ecdsa_field(const unsigned char* pem_buf, size_t pem_len, size_t* key_index, size_t* key_length)
{
    int ret = 0;
    int param_index_index = -1;
    int param_length = 0;
    size_t x = 0;

    // const unsigned char head = { 0x30, l-2, 0x02, 0x01, 0x01, 0x04 }
    if (pem_len < 16 ||
        pem_buf[x++] != 0x30 /* type = sequence */)
    {
        ret = -1;
    }
    else {
        size_t l = 0;
        ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l);

        if (x + l != pem_len) {
            ret = -1;
        }
    }
    if (ret == 0){
        if (pem_buf[x++] != 0x02 /* type = int */ ||
            pem_buf[x++] != 0x01 /* length of int = 1 */ ||
            pem_buf[x++] != 0x01 /* version = 1 */ ||
            pem_buf[x++] != 0x04 /*octet string */ ||
            pem_buf[x] + x >= pem_len) {
            ret = -1;
        }
        else {
            *key_index = x + 1;
            *key_length = pem_buf[x];
            x += 1 + pem_buf[x];

            if (x < pem_len && pem_buf[x] == 0xa0) {
                /* decode the EC parameters, identify the curve */
                x++;
                if (x + pem_buf[x] >= pem_len) {
                    /* EC parameters extend beyond buffer */
                    ret = -1;
                }
                else {
                    x += pem_buf[x] + 1;
                }
            }

            if (ret == 0 && x < pem_len) {
                /* skip the public key parameter */
                if (pem_buf[x++] != 0xa1 ||
                    x >= pem_len) {
                    ret = -1;
                }
                else {
                    size_t l = 0;
                    ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l);
                    x += l;
                }
            }

            if (x != pem_len) {
                ret = -1;
            }
        }
    }
    return ret;
}

/* On input, key_index points at the "key information" in a
* "private key" message. For EDDSA, this contains an
* octet string carrying the key itself. On return, key index
* and key length are updated to point at the key field.
*/
static int ptls_mbedtls_parse_eddsa_key(const unsigned char* pem_buf, size_t pem_len,
    size_t* key_index, size_t* key_length)
{
    int ret = 0;
    size_t x = *key_index;
    size_t l_key = 0;

    if (*key_length < 2 || pem_buf[x++] != 0x04) {
        ret = -1;
    } else {
        ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_key);
        if (x + l_key != *key_index + *key_length) {
            ret = -1;
        }
        else {
            *key_index = x;
            *key_length = l_key;
        }
    }
    return ret;
}

/* If using PKCS8 encoding, the "private key" field contains the
* same "ecdsa field" found in PEM "EC PRIVATE KEY" files. We
* use the same parser, but we need to reset indices so they
* reflect the unwrapped key.
*/
int ptls_mbedtls_parse_ec_private_key(const unsigned char* pem_buf, size_t pem_len,
    size_t* key_index, size_t* key_length)
{
    size_t x_offset = 0;
    size_t x_len = 0;
    int ret = ptls_mbedtls_parse_ecdsa_field(pem_buf + *key_index, *key_length, &x_offset, &x_len);

    if (ret == 0) {
        *key_index += x_offset;
        *key_length = x_len;
    }
    return ret;
}

int test_parse_private_key_field(const unsigned char* pem_buf, size_t pem_len,
    size_t* oid_index, size_t *oid_length,
    size_t* key_index, size_t* key_length)
{
    int ret = 0;
    size_t l_oid = 0;
    size_t x_oid = 0;
    size_t l_key = 0;
    size_t x_key = 0;

    size_t x = 0;
    /*  const unsigned char head = {0x30, l - 2, 0x02, 0x01, 0x00} */
    if (pem_len < 16 ||
        pem_buf[x++] != 0x30 /* type = sequence */)
    {
        ret = -1;
    }
    else {
        size_t l = 0;
        ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l);

        if (x + l != pem_len) {
            ret = -1;
        }
    }
    if (ret == 0) {
        if (pem_buf[x++] != 0x02 /* type = int */ ||
            pem_buf[x++] != 0x01 /* length of int = 1 */ ||
            pem_buf[x++] != 0x00 /* version = 0 */ ||
            pem_buf[x++] != 0x30 /* sequence */){
            ret = -1;
        }
        else {
            /* the sequence contains the OID and optional key attributes,
            * which we ignore for now.
            */
            size_t l_seq = 0;
            size_t x_seq;
            ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_seq);
            x_seq = x;
            if (x + l_seq >= pem_len ||
                pem_buf[x++] != 0x06) {
                ret = -1;
            }
            else {
                l_oid = pem_buf[x++];
                x_oid = x;
                if (x + l_oid > x_seq + l_seq) {
                    ret = -1;
                }
                else {
                    x = x_seq + l_seq;
                }
            }
        }
    }
    if (ret == 0) {
        /* At that point the oid has been identified.
        * The next parameter is an octet string containing the key info.
        */
        size_t l = 0;
        if (x + 2 > pem_len ||
            pem_buf[x++]  != 0x04){
            ret = -1;
        }
        else {
            ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_key);
            x_key = x;
            x += l_key;
            if (x > pem_len) {
                ret = -1;
            }
        }
    }
    *oid_index = x_oid;
    *oid_length = l_oid;
    *key_index = x_key;
    *key_length = l_key;

    return ret;
}

int ptls_mbedtls_get_der_key(mbedtls_pem_context* pem,
    mbedtls_pk_type_t * pk_type,
    const unsigned char* key, size_t keylen,
    const unsigned char* pwd, size_t pwdlen,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
#endif

    if (keylen == 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    mbedtls_pem_init(pem);

#if defined(MBEDTLS_RSA_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    }
    else {
        ret = mbedtls_pem_read_buffer(pem,
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            key, pwd, pwdlen, &len);
    }

    if (ret == 0) {
        * pk_type = MBEDTLS_PK_RSA;
        return ret;
    }
    else if (ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH) {
        return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
    }
    else if (ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED) {
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    }
    else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    }
    else {
        ret = mbedtls_pem_read_buffer(pem,
            "-----BEGIN EC PRIVATE KEY-----",
            "-----END EC PRIVATE KEY-----",
            key, pwd, pwdlen, &len);
    }
    if (ret == 0) {
        * pk_type = MBEDTLS_PK_ECKEY;
        return ret;
    }
    else if (ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH) {
        return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
    }
    else if (ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED) {
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    }
    else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    }
    else {
        ret = mbedtls_pem_read_buffer(pem,
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            key, NULL, 0, &len);
        if (ret == 0) {
            /* info is unknown */
            return ret;
        }
        else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
            return ret;
        }
    }

#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    }
    else {
        ret = mbedtls_pem_read_buffer(pem,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----END ENCRYPTED PRIVATE KEY-----",
            key, NULL, 0, &len);
    }
    if (ret == 0) {
        /* infor is unknown */
        return ret;
    }
    else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif /* MBEDTLS_PKCS12_C || MBEDTLS_PKCS5_C */
    return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
}
#endif

const ptls_mbedtls_signature_scheme_t* ptls_mbedtls_select_signature_scheme(
    const ptls_mbedtls_signature_scheme_t *available,
    const uint16_t *algorithms, size_t num_algorithms)
{
    const ptls_mbedtls_signature_scheme_t* scheme;
    /* select the algorithm, driven by server-isde preference of `available` */
    for (scheme = available; scheme->scheme_id != UINT16_MAX; ++scheme) {
        for (size_t i = 0; i != num_algorithms; ++i) {
            if (algorithms[i] == scheme->scheme_id) {
                return scheme;
            }
        }
    }
    return NULL;
}

int ptls_mbedtls_set_available_schemes(
    ptls_mbedtls_sign_certificate_t* signer)
{
    int ret = 0;
    psa_algorithm_t algo = psa_get_key_algorithm(&signer->attributes);
    size_t nb_bits = psa_get_key_bits(&signer->attributes);

    switch (algo) {
    case PSA_ALG_RSA_PKCS1V15_SIGN_RAW:
        signer->schemes = rsa_signature_schemes;
        break;
    case PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256):
        signer->schemes = secp256r1_signature_schemes;
        break;
    case PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384):
        signer->schemes = secp384r1_signature_schemes;
        break;
    case PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_512):
        signer->schemes = secp521r1_signature_schemes;
        break;
    case PSA_ALG_ECDSA_BASE:
        switch (nb_bits) {
        case 521:
            signer->schemes = secp521r1_signature_schemes;
            break;
        case 384:
            signer->schemes = secp384r1_signature_schemes;
            break;
        case 256:
            signer->schemes = secp256r1_signature_schemes;
            break;
        default:
            signer->schemes = secp256r1_signature_schemes;
            ret = -1;
            break;
        }
        break;
    case PSA_ALG_ED25519PH:
        signer->schemes = ed25519_signature_schemes;
        break;
    default:
        ret = -1;
    }

    return ret;
}

/*
* Sign a certificate
* - step1, selected a signature algorithm compatible with the public key algorithm
*   and with the list specified by the application.
* - step2, compute the hash with the specified algorithm.
* - step3, compute the signature of the hash using psa_sign_hash.
* 
* In the case of RSA, we use the algorithm PSA_ALG_RSA_PKCS1V15_SIGN_RAW, which
* pads the hash according to PKCS1V15 before doing the private key operation.
* The implementation of RSA/PKCS1V15 also includes a verification step to protect
* against key attacks through partial faults.
* 
* MBEDTLS has a "psa_sign_message" that combines step2 and step3. However, it
* requires specifying an algorithm type that exactly specifies the signature
* algorithm, such as "RSA with SHA384". This is not compatible with the
* "RSA sign raw" algorithm. Instead, we decompose the operation in two steps.
* There is no performance penalty doing so, as "psa_sign_message" is only
* a convenience API.
*/

int ptls_mbedtls_sign_certificate(ptls_sign_certificate_t* _self, ptls_t* tls,
    ptls_async_job_t** async, uint16_t* selected_algorithm,
    ptls_buffer_t* outbuf, ptls_iovec_t input, const uint16_t* algorithms, size_t num_algorithms)
{
    int ret = 0;
    ptls_mbedtls_sign_certificate_t* self = (ptls_mbedtls_sign_certificate_t*)
        (((unsigned char*)_self) - offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
    /* First, find the set of compatible algorithms */
    const ptls_mbedtls_signature_scheme_t* scheme =
        ptls_mbedtls_select_signature_scheme(self->schemes, algorithms, num_algorithms);

    if (scheme == NULL) {
        ret = PTLS_ERROR_INCOMPATIBLE_KEY;
    }
    else {
        /* First prepare the hash */
        unsigned char hash_buffer[PTLS_MAX_DIGEST_SIZE];
        unsigned char* hash_value = NULL;
        size_t hash_length = 0;

        if (scheme->hash_algo == PSA_ALG_NONE) {
            hash_value = input.base;
            hash_length = input.len;
        }
        else {
            if (psa_hash_compute(scheme->hash_algo, input.base, input.len, hash_buffer, PTLS_MAX_DIGEST_SIZE, &hash_length) != PSA_SUCCESS) {
                ret = PTLS_ERROR_NOT_AVAILABLE;
            }
            else {
                hash_value = hash_buffer;
            }
        }
        if (ret == 0) {
            psa_algorithm_t sign_algo = psa_get_key_algorithm(&self->attributes);
            size_t nb_bits = psa_get_key_bits(&self->attributes);
            size_t nb_bytes = (nb_bits + 7) / 8;
            if (nb_bits == 0) {
                if (sign_algo == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
                    /* assume at most 4096 bit key */
                    nb_bytes = 512;
                }
                else {
                    /* Max size assumed, secp521r1 */
                    nb_bytes = 124;
                }
            } else if (sign_algo != PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
                nb_bytes *= 2;
            }
            if ((ret = ptls_buffer_reserve(outbuf, nb_bytes)) == 0) {
                size_t signature_length = 0;

                if (psa_sign_hash(self->key_id, sign_algo, hash_value, hash_length,
                    outbuf->base + outbuf->off, nb_bytes, &signature_length) != 0) {
                    ret = PTLS_ERROR_INCOMPATIBLE_KEY;
                }
                else {
                    outbuf->off += signature_length;
                }
            }
        }
    }
    return ret;
}

void ptls_mbedtls_dispose_sign_certificate(ptls_sign_certificate_t *_self)
{
    if (_self != NULL) {
        ptls_mbedtls_sign_certificate_t* self = (ptls_mbedtls_sign_certificate_t*)
        (((unsigned char*)_self) - offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
        /* Destroy the key */
        psa_destroy_key(self->key_id);
        psa_reset_key_attributes(&self->attributes);
        memset(self, 0, sizeof(ptls_mbedtls_sign_certificate_t));
        free(self);
    }
}
/*
* An RSa key is encoded in DER as:
* RSAPrivateKey ::= SEQUENCE {
*   version             INTEGER,  -- must be 0
*   modulus             INTEGER,  -- n
*   publicExponent      INTEGER,  -- e
*   privateExponent     INTEGER,  -- d
*   prime1              INTEGER,  -- p
*   prime2              INTEGER,  -- q
*   exponent1           INTEGER,  -- d mod (p-1)
*   exponent2           INTEGER,  -- d mod (q-1)
*   coefficient         INTEGER,  -- (inverse of q) mod p
* }
* 
* The number of key bits is the size in bits of the integer N.
* We must decode the length in octets of the integer representation,
* then subtract the number of zeros at the beginning of the data.
*/
int ptls_mbedtls_rsa_get_key_bits(const unsigned char* key_value, size_t key_length, size_t * p_nb_bits)
{
    int ret = 0;
    size_t nb_bytes = 0;
    size_t nb_bits = 0;
    size_t x = 0;

    if (key_length > 16 && key_value[x++] == 0x30) {
        /* get the length of the sequence. */
        size_t l = 0;
        ret = ptls_mbedtls_parse_der_length(key_value, key_length, &x, &l);

        if (x + l != key_length) {
            ret = -1;
        }
    }

    if (ret == 0 &&
        key_value[x] == 0x02 &&
        key_value[x + 1] == 0x01 &&
        key_value[x + 2] == 0x00 &&
        key_value[x + 3] == 0x02) {
        x += 4;
        ret = ptls_mbedtls_parse_der_length(key_value, key_length, &x, &nb_bytes);
    }
    else {
        ret = -1;
    }

    if (ret == 0) {
        unsigned char v = key_value[x];
        nb_bits = 8 * nb_bytes;

        if (v == 0) {
            nb_bits -= 8;
        }
        else {
            while ((v & 0x80) == 0) {
                nb_bits--;
                v <<= 1;
            }
        }
    }
    *p_nb_bits = nb_bits;
    return ret;
}

void ptls_mbedtls_set_rsa_key_attributes(ptls_mbedtls_sign_certificate_t* signer,
    const unsigned char * key_value, size_t key_length)
{
    size_t nb_bits = 0;
    psa_set_key_usage_flags(&signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&signer->attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
    psa_set_key_type(&signer->attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    if (ptls_mbedtls_rsa_get_key_bits(key_value, key_length, &nb_bits) == 0) {
        psa_set_key_bits(&signer->attributes, nb_bits);
    }
}

int ptls_mbedtls_set_ec_key_attributes(ptls_mbedtls_sign_certificate_t* signer, size_t key_length)
{
    int ret = 0;

    psa_set_key_usage_flags(&signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&signer->attributes, PSA_ALG_ECDSA_BASE);
    psa_set_key_type(&signer->attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    if (key_length == 32) {
        psa_set_key_algorithm(&signer->attributes,
            PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_bits(&signer->attributes, 256);
    }
    else if (key_length == 48) {
        psa_set_key_algorithm(&signer->attributes,
            PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384));
        psa_set_key_bits(&signer->attributes, 384);
    }
    else if (key_length == 66) {
        psa_set_key_algorithm(&signer->attributes,
            PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_512));
        psa_set_key_bits(&signer->attributes, 521);
    }
    else {
        ret = -1;
    }

    return ret;
}



int ptls_mbedtls_load_private_key(ptls_context_t* ctx, char const* pem_fname)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    unsigned char* buf;
    mbedtls_pem_context pem = { 0 };
    mbedtls_pk_type_t pk_type = 0;
    mbedtls_svc_key_id_t key_id = 0;
    size_t key_length = 0;
    size_t key_index = 0;
    ptls_mbedtls_sign_certificate_t* signer = (ptls_mbedtls_sign_certificate_t*)malloc(sizeof(ptls_mbedtls_sign_certificate_t));

    if (signer == NULL) {
        return(PTLS_ERROR_NO_MEMORY);
    }
    memset(signer, 0, sizeof(ptls_mbedtls_sign_certificate_t));
    signer->attributes = psa_key_attributes_init();

    if ((ret = mbedtls_pk_load_file(pem_fname, &buf, &n)) != 0) {
        if (ret == MBEDTLS_ERR_PK_ALLOC_FAILED) {
            return(PTLS_ERROR_NO_MEMORY);
        }
        else {
            return(PTLS_ERROR_NOT_AVAILABLE);
        }
    }
    ret = ptls_mbedtls_get_der_key(&pem, &pk_type, buf, n, NULL, 0, NULL, NULL);

    /* We cannot use the platform API:
    mbedtls_zeroize_and_free(buf, n);
    so we do our own thing.
    */
    memset(buf, 0, n);
    free(buf);

    if (ret == 0) {
        if (pk_type == MBEDTLS_PK_RSA) {
            key_length = pem.private_buflen;
            ptls_mbedtls_set_rsa_key_attributes(signer, pem.private_buf, key_length);
        }
        else if (pk_type == MBEDTLS_PK_ECKEY) {
            ret = ptls_mbedtls_parse_ecdsa_field(pem.private_buf, pem.private_buflen, &key_index, &key_length);
            if (ret == 0) {
                ret = ptls_mbedtls_set_ec_key_attributes(signer, key_length);
            }
        }
        else if (pk_type == MBEDTLS_PK_NONE) {
            /* TODO: not clear whether MBDED TLS supports ED25519 yet. Probably not. */
            /* Should have option to encode RSA or ECDSA using PKCS8 */
            size_t oid_index = 0;
            size_t oid_length = 0;

            psa_set_key_usage_flags(&signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
            ret = test_parse_private_key_field(pem.private_buf, pem.private_buflen, &oid_index, &oid_length, &key_index, &key_length);
            if (ret == 0) {
                /* need to parse the OID in order to set the parameters */

                if (oid_length == sizeof(ptls_mbedtls_oid_ec_key) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_ec_key, sizeof(ptls_mbedtls_oid_ec_key)) == 0) {
                    ret = ptls_mbedtls_parse_ec_private_key(pem.private_buf, pem.private_buflen, &key_index, &key_length);
                    if (ret == 0) {
                        ret = ptls_mbedtls_set_ec_key_attributes(signer, key_length);
                    }
                }
                else if (oid_length == sizeof(ptls_mbedtls_oid_ed25519) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_ed25519, sizeof(ptls_mbedtls_oid_ed25519)) == 0) {
                    /* We recognized ED25519 -- PSA_ECC_FAMILY_TWISTED_EDWARDS -- PSA_ALG_ED25519PH */
                    psa_set_key_algorithm(&signer->attributes, PSA_ALG_PURE_EDDSA);
                    psa_set_key_type(&signer->attributes, PSA_ECC_FAMILY_TWISTED_EDWARDS);
                    ret = ptls_mbedtls_parse_eddsa_key(pem.private_buf, pem.private_buflen, &key_index, &key_length);
                    psa_set_key_bits(&signer->attributes, 256);
                }
                else if (oid_length == sizeof(ptls_mbedtls_oid_rsa_key) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_rsa_key, sizeof(ptls_mbedtls_oid_rsa_key)) == 0) {
                    /* We recognized RSA */
                    key_length = pem.private_buflen;
                    ptls_mbedtls_set_rsa_key_attributes(signer, pem.private_buf, key_length);
                }
                else {
                    ret = PTLS_ERROR_NOT_AVAILABLE;
                }
            }
        }
        else {
            ret = -1;
        }

        if (ret == 0) {
            /* Now that we have the DER or bytes for the key, try import into PSA */
            psa_status_t status = psa_import_key(&signer->attributes, pem.private_buf + key_index, key_length, &signer->key_id);

            if (status != PSA_SUCCESS) {
                ret = -1;
            }
            else {
                ret = ptls_mbedtls_set_available_schemes(signer);
            }
        }
        /* Free the PEM buffer */
        mbedtls_pem_free(&pem);
    }
    if (ret == 0) {
        signer->super.cb = ptls_mbedtls_sign_certificate;
        ctx->sign_certificate = &signer->super;
    } else {
        /* Dispose of what we have allocated. */
        ptls_mbedtls_dispose_sign_certificate(&signer->super);
    }
    return ret;
}

/* Handling of certificates.
* Certificates in picotls are used both at the client and the server side.
* 
* The server is programmed with a copy of the certificate chain linking
* the local key and identity to a certificate authority. Picotls formats
* that key and sends it as part of the "server hello". It is signed with
* the server key.
* 
* On the server side, picotls expects?
* 
* The client is programmed with a list of root certificates. It should
* process the list received from the server and verifies that it does
* correctly link the server certificate to one of the certificates in the
* root list.
* 
* Mbedtls documents a series of certificate related API in `x509_crt.h`.
* 
* On the server side, we read the certificates from a PEM encoded
* file, and provide it to the server.
* 
* int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen)
*     => parse the DER code in the buffer, documents a cerificate chain
*        in MbetTLS format.
* 
* int mbedtls_x509_crt_parse(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen)
*    => Parse one DER-encoded or one or more concatenated PEM-encoded certificates and
*       add them to the chained list. 
* 
* int mbedtls_x509_crt_verify(mbedtls_x509_crt *crt, mbedtls_x509_crt *trust_ca, mbedtls_x509_crl *ca_crl, const char *cn, uint32_t *flags, int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*), void *p_vrfy)
*    => check the certificate chain (crt) against a list of trusted ca (trust_ca) and
*       a specified "common name". "ca_crl" is a revocation list.
* 
* Public key operations such as "verify message" require a key-id.  We should obtain that key ID by using "psa_import_key":
* 
* psa_status_t psa_import_key(const psa_key_attributes_t *attributes, const uint8_t *data, size_t data_length, mbedtls_svc_key_id_t *key)
* 
* The data and data length are probably obtained 
 */

 /* Read certificates from a file using MbedTLS functions.
 * We only use the PEM function to parse PEM files, find
 * up to 16 certificates, and convert the base64 encoded
 * data to DER encoded binary. No attempt is made to verify
 * that these actually are certificates.
 */
ptls_iovec_t* picoquic_mbedtls_get_certs_from_file(char const * pem_fname, size_t * count)
{
    ptls_iovec_t* vec = (ptls_iovec_t*)malloc(sizeof(ptls_iovec_t) * 16);

    *count = 0;
    if (vec != NULL) {
        size_t buf_length;
        unsigned char* buf = NULL;
        /* The load file function simply loads the file content in memory */
        if (mbedtls_pk_load_file(pem_fname, &buf, &buf_length) == 0) {
            int ret = 0;
            size_t length_already_read = 0;

            while (ret == 0 && *count < 16 && length_already_read < (size_t)buf_length) {
                mbedtls_pem_context pem = { 0 };
                size_t length_read = 0;

                /* PEM context setup. */
                mbedtls_pem_init(&pem);
                /* Read a buffer for PEM information and store the resulting data into the specified context buffers. */
                ret = mbedtls_pem_read_buffer(&pem,
                    "-----BEGIN CERTIFICATE-----",
                    "-----END CERTIFICATE-----",
                    buf + length_already_read, NULL, 0, &length_read);
                if (ret == 0) {
                    /* Certificate was read successfully. PEM buffer contains the base64 value */
                    uint8_t* cert = (uint8_t*)malloc(pem.private_buflen);
                    if (cert == NULL) {
                        ret = PTLS_ERROR_NO_MEMORY;
                    }
                    else {
                        vec[*count].base = cert;
                        vec[*count].len = pem.private_buflen;
                        *count += 1;
                    }
                }
                mbedtls_pem_free(&pem);
                length_already_read += length_read;
            }

            free(buf);
        }
    }
    return vec;
}

/* verify certificate.
* Picotls and then picoquic use a two phase API:
* 
* - During initialization, prepare a "verify certificate callback"
* - During the handshake, picotls executes the callback.
* 
* The setup call for the "stack" verifier is:
* 
* picoquic_openssl_get_openssl_certificate_verifier(char const * cert_root_file_name,
*   unsigned int * is_cert_store_not_empty)
*
* For openssl, this creates a structure:
* 
* typedef struct st_ptls_openssl_verify_certificate_t {
*    ptls_verify_certificate_t super;
*    X509_STORE *cert_store;
*    ptls_openssl_override_verify_certificate_t *override_callback;
* } ptls_openssl_verify_certificate_t;
*
* 
 */

/* The "verify sign" callback is called to verify the final handshake message
* of the server, using the public key present in the server certificate. 
* The "verify_ctx" is set during the "verify_cert" callback, i.e., the public
* key. 
* 
* The MBEDTLS call is:
* psa_status_t psa_verify_message(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t *input, size_t input_length, const uint8_t *signature, size_t signature_length)
* in which:
* * key is passed by "ID"
* * alg is the signature algorithm,
* * input, input_length is the data,
* * signature, signature length is the reported signature.
* 
* This means that "verify_ctx" should pass the value of type mbedtls_svc_key_id_t.
*/


static int mbedptls_verify_sign(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature)
{
    /* Obtain the key parameters, etc. */
#if 0
    EVP_PKEY *key = verify_ctx;
    const ptls_openssl_signature_scheme_t *scheme;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
#endif
    int ret = 0;
   ptls_mbedtls_signature_scheme_t* schemes;
    if (data.base == NULL)
        goto Exit;

    /* Find whether the signature scheme is supported */
    ptls_mbedtls_set_schemes_from_key_params(/*psa_algorithm_t*/ key_algo, key_nb_bits, &schemes);

    for (; scheme->scheme_id != UINT16_MAX; ++scheme)
        if (scheme->scheme_id == algo)
            goto SchemeFound;
    ret = PTLS_ALERT_ILLEGAL_PARAMETER;
    goto Exit;

SchemeFound:
    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* Do the verification, using appropriate scheme
    * OpenSSl uses 3/4 steps:
    * - verify init: setting context, scheme, key.
    * - something about RSA
    * - verify update, passing the content
    * - verify final, comparing the signature.
    * Should this be abstracted for individual testing?
     */
    {
        if (EVP_DigestVerifyInit(ctx, &pkey_ctx, scheme->scheme_md(), NULL, key) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }

        if (EVP_PKEY_id(key) == EVP_PKEY_RSA) {
            if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
                ret = PTLS_ERROR_LIBRARY;
                goto Exit;
            }
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1) {
                ret = PTLS_ERROR_LIBRARY;
                goto Exit;
            }
            if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, scheme->scheme_md()) != 1) {
                ret = PTLS_ERROR_LIBRARY;
                goto Exit;
            }
        }
        if (EVP_DigestVerifyUpdate(ctx, data.base, data.len) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_DigestVerifyFinal(ctx, signature.base, signature.len) != 1) {
            ret = PTLS_ALERT_DECRYPT_ERROR;
            goto Exit;
        }
    }

    ret = 0;

    /* Finally, free the context and the verify_ctx data */
Exit:
    if (ctx != NULL)
        EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(key);
    return ret;
}


/* The verify cert call back in openssl.c calls the SSL APIs:
* - convert the "certs" list obtained from TLS message into a structure
*   acceptable by OpenSSL,
* - call "verify_cert_chain(self->cert_store, cert, chain, ptls_is_server(tls), server_name, &ossl_x509_err)"
* - if there is an "override" callback defined, call that. even if there
*   are no certificates specified.
* - if all is good and there is a cert provided, retrieve the public key from the cert
*   and put that in the "verify_data" parameter
* - set the "verifier" function pointer to "verify_sig"
* 
*/

static int mbedtls_verify_cert(ptls_verify_certificate_t *_self, ptls_t *tls, const char *server_name,
    int (**verifier)(void *, uint16_t, ptls_iovec_t, ptls_iovec_t), void **verify_data, ptls_iovec_t *certs,
    size_t num_certs)
{
    size_t i;
    int ret = 0;
    ptls_mbedtls_verify_certificate_t *self = (ptls_mbedtls_verify_certificate_t *)_self;
    mbedtls_x509_crt chain_head = { 0 };
    //X509 *cert = NULL;
    //STACK_OF(X509) *chain = sk_X509_new_null();

    /* If any certs are given, convert them to OpenSSL representation, then verify the cert chain. If no certs are given, just give
    * the override_callback to see if we want to stay fail open. */
    if (num_certs != 0) {
        mbedtls_x509_crt* previous_chain = &chain_head;
        uint32_t flags = 0;
#if 0
        if ((cert = to_x509(certs[0])) == NULL) {
            ret = PTLS_ALERT_BAD_CERTIFICATE;
            goto Exit;
        }
#endif
        for (i = 0; i != num_certs; ++i) {
            ret = mbedtls_x509_crt_parse(previous_chain, certs[i].base, certs[i].len);
            if (previous_chain->next == NULL) {
                ret = PTLS_ALERT_BAD_CERTIFICATE;
                break;
            }
            previous_chain = previous_chain->next;
        }

        if (ret == 0) {
            ret = mbedtls_x509_crt_verify(chain_head.next, self->trust_ca, NULL /* ca_crl */, server_name, &flags,
                self->f_vrfy, self->p_vrfy);
        }
    } else {
        ret = PTLS_ALERT_CERTIFICATE_REQUIRED;
    }

    if (ret == 0 && num_certs > 0) {
        /* extract public key for verifying the TLS handshake signature.
         * we need to allocate a buffer to hold the key. The size of the buffer
         * is not obvious. What is the maximum size that we support?
         * Maybe RSA with 8K bits, i.e., 1KB -- but the format includes
         * the modulo N (1KB) and the public exponent (shorter). 2KB should
         * be enough. Otherwise, we have an error case.
         * 
         * the exported public key should then be fed to:
         * psa_status_t psa_import_key(const psa_key_attributes_t *attributes, const uint8_t *data, size_t data_length, mbedtls_svc_key_id_t *key)
         * 
         * The difficulty is to find the proper key attributes:
         * signer->attributes = psa_key_attributes_init();
         * PSA_KEY_USAGE_VERIFY_HASH -- because this is a public key?
         * Algorithm dependent flags, similar to what is done for private key.
         * 
         */
        uint8_t buffer[2048];
        psa_key_attributes_t attributes = psa_key_attributes_init();
        int length_written = mbedtls_pk_write_pubkey_der(&chain_head.next->pk, buffer, sizeof(buffer));
        if (length_written <= 0 || length_written > sizeof(buffer) ) {
            ret = PTLS_ALERT_BAD_CERTIFICATE;
        }
        else {
            mbedtls_svc_key_id_t key;
            size_t start_byte = sizeof(buffer) - length_written;
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH);
            /* TODO: add attributes like key type. Maybe parse the ASN1 to find the values. */
            /* TODO, tests: using private key, examine the ASN1 */
            /* TODO: verify that the key format is correct. */
            if (psa_import_key(&attributes, buffer + start_byte, length_written, &key) != 0) {
                ret = PTLS_ALERT_BAD_CERTIFICATE;
            }
            else {
                /* TODO: create a verifier blob, set verify data, etc. */
            }
        }
    }

Exit:
    if (chain_head.next != NULL) {
        mbedtls_x509_crt_free(chain_head.next);
    }
    return ret;
}

/* The init in open ssl does : */

int ptls_mbedssl_init_verify_certificate(ptls_mbedtls_verify_certificate_t *self, mbedtls_x509_crt *trust_ca)
{
    /* The init between the {{}, ..} fills the "ptls_verify_certificate_t" member. */
    *self = (ptls_mbedtls_verify_certificate_t){{mbedtls_verify_cert, default_signature_schemes}, NULL};

    /* The "cert store will be set to an OpenSSL default if not specified. */
    if (store != NULL) {
        self->trust_ca = trust_ca;
    } else {
        /* No default store available in MbedTLS */
        return -1;
    }

    return 0;
}

/* Use openssl functions to create a certficate verifier */
ptls_mbedtls_verify_certificate_t* picoquic_mbdedtls_get_openssl_certificate_verifier(char const * cert_root_file_name,
    unsigned int * is_cert_store_not_empty)
{
    ptls_mbdedtls_verify_certificate_t * verifier = (ptls_mbdedtls_verify_certificate_t*)malloc(sizeof(ptls_mbdedtls_verify_certificate_t));
    if (verifier != NULL) {
        X509_STORE* store = X509_STORE_new();

        if (cert_root_file_name != NULL && store != NULL) {
            int file_ret = 0;
            X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
            if ((file_ret = X509_LOOKUP_load_file(lookup, cert_root_file_name, X509_FILETYPE_PEM)) == 1) {
                *is_cert_store_not_empty = 1;
            }
        }
#ifdef PTLS_OPENSSL_VERIFY_CERTIFICATE_ENABLE_OVERRIDE
        ptls_mbdedtls_init_verify_certificate(verifier, store, NULL);
#else
        ptls_mbdedtls_init_verify_certificate(verifier, store);
#endif

        // If we created an instance of the store, release our reference after giving it to the verify_certificate callback.
        // The callback internally increased the reference counter by one.
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        if (store != NULL) {
            X509_STORE_free(store);
        }
#endif
    }
    return verifier;
}



ptls_verify_certificate_t* picoquic_openssl_get_certificate_verifier(char const* cert_root_file_name,
    unsigned int* is_cert_store_not_empty)
{
    ptls_openssl_verify_certificate_t* verifier = picoquic_openssl_get_openssl_certificate_verifier(cert_root_file_name,
        is_cert_store_not_empty);
    return (verifier == NULL) ? NULL : (ptls_verify_certificate_t*)&verifier->super;
}

void picoquic_openssl_dispose_certificate_verifier(ptls_verify_certificate_t* verifier) {
    ptls_openssl_dispose_verify_certificate((ptls_openssl_verify_certificate_t*)verifier);
}
