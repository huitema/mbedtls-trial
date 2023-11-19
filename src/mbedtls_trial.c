#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include "mbedtls/build_info.h"
#if 0
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#endif
#include "ptls_mbedtls.h"
#include "picotls/minicrypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/pem.h"
#include "mbedtls/error.h"

int test_random();
int test_hash(ptls_hash_algorithm_t* algo, ptls_hash_algorithm_t* ref);
int test_label(ptls_hash_algorithm_t* hash, ptls_hash_algorithm_t* ref);
int test_cipher(ptls_cipher_algorithm_t* cipher, ptls_cipher_algorithm_t* cipher_ref);
int test_aead(ptls_aead_algorithm_t* algo, ptls_hash_algorithm_t* hash, ptls_aead_algorithm_t* ref, ptls_hash_algorithm_t* hash_ref);
int test_key_exchange(ptls_key_exchange_algorithm_t* client, ptls_key_exchange_algorithm_t* server);
int test_load_key();
int test_load_der();

int main(int argc, char ** argv)
{
    ptls_cipher_algorithm_t* cipher_test[5] = {
        &ptls_mbedtls_aes128ecb,
        &ptls_mbedtls_aes128ctr,
        &ptls_mbedtls_aes256ecb,
        &ptls_mbedtls_aes256ctr,
        &ptls_mbedtls_chacha20
    };
    ptls_cipher_algorithm_t* cipher_ref[5] = {
        &ptls_minicrypto_aes128ecb,
        &ptls_minicrypto_aes128ctr,
        &ptls_minicrypto_aes256ecb,
        &ptls_minicrypto_aes256ctr,
        &ptls_minicrypto_chacha20
    };
    int ret = 0;

    /* Initialize the PSA crypto library. */
    if ((ret = ptls_mbedtls_init()) != 0) {
        fprintf(stdout, "psa_crypto_init fails.");
    }
    else {
        ret = test_random();
        printf("test random returns: %d\n", ret);

        if (ret == 0) {
            ret = test_hash(&ptls_mbedtls_sha256, &ptls_minicrypto_sha256);
            printf("test hash returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_label(&ptls_mbedtls_sha256, &ptls_minicrypto_sha256);
            printf("test label returns: %d\n", ret);
        }

        if (ret == 0) {
            for (int i = 0; i < 5; i++) {
                if (test_cipher(cipher_test[i], cipher_ref[i]) != 0) {
                    printf("test cipher %d fails\n", i);
                    ret = -1;
                }
            }
            printf("test ciphers returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_aead(&ptls_mbedtls_aes128gcm, &ptls_mbedtls_sha256, &ptls_minicrypto_aes128gcm, &ptls_minicrypto_sha256);
            printf("test aeads returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_key_exchange(&ptls_mbedtls_secp256r1, &ptls_minicrypto_secp256r1);
            if (ret != 0) {
                printf("test key exchange secp256r1 mbedtls to minicrypto fails\n");
            }
            else {
                ret = test_key_exchange(&ptls_minicrypto_secp256r1, &ptls_mbedtls_secp256r1);
                if (ret != 0) {
                    printf("test key exchange secp256r1 minicrypto to mbedtls fails\n");
                }
            }
            ret = test_key_exchange(&ptls_mbedtls_x25519, &ptls_minicrypto_x25519);
            if (ret != 0) {
                printf("test key exchange x25519 mbedtls to minicrypto fails\n");
            }
            else {
                ret = test_key_exchange(&ptls_minicrypto_x25519, &ptls_mbedtls_x25519);
                if (ret != 0) {
                    printf("test key exchange x25519 minicrypto to mbedtls fails\n");
                }
            }
            printf("test key exchange returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_load_key();
        }
        if (ret == 0) {
            ret = test_load_der();
        }

        /* Deinitialize the PSA crypto library. */
        ptls_mbedtls_free();
    }


    return (ret == 0) ? 0 : -1;
}

#define PTLS_MBEDTLS_RANDOM_TEST_LENGTH 1021

int test_random()
{
    /* The random test is just trying to check that we call the API properly. 
     * This is done by getting a vector of 1021 bytes, computing the sum of
     * all values, and comparing to theoretical min and max,
     * computed as average +- 8*standard deviation for sum of 1021 terms.
     * 8 random deviations results in an extremely low probability of random
     * failure.
     * Note that this does not actually test the random generator.
     */

    uint8_t buf[PTLS_MBEDTLS_RANDOM_TEST_LENGTH];
    uint64_t sum = 0;
    const uint64_t max_sum_1021 = 149505;
    const uint64_t min_sum_1021 = 110849;
    int ret = 0;

    ptls_mbedtls_random_bytes(buf, PTLS_MBEDTLS_RANDOM_TEST_LENGTH);
    for (size_t i = 0; i < PTLS_MBEDTLS_RANDOM_TEST_LENGTH; i++) {
        sum += buf[i];
    }
    if (sum > max_sum_1021 || sum < min_sum_1021) {
        ret = -1;
    }

    return ret;
}

int hash_trial(ptls_hash_algorithm_t* algo, const uint8_t* input, size_t len1, size_t len2, uint8_t* final_hash)
{
    int ret = 0;
    ptls_hash_context_t* hash_ctx = algo->create();

    hash_ctx->update(hash_ctx, input, len1);
    if (len2 > 0) {
        hash_ctx->update(hash_ctx, input + len1, len2);
    }
    hash_ctx->final(hash_ctx, final_hash, PTLS_HASH_FINAL_MODE_FREE);

    return ret;
}

int hash_reset_trial(ptls_hash_algorithm_t* algo, const uint8_t* input, size_t len1, size_t len2, 
    uint8_t* hash1, uint8_t* hash2)
{
    int ret = 0;
    ptls_hash_context_t* hash_ctx = algo->create();

    hash_ctx->update(hash_ctx, input, len1);
    hash_ctx->final(hash_ctx, hash1, PTLS_HASH_FINAL_MODE_RESET);
    hash_ctx->update(hash_ctx, input + len1, len2);
    hash_ctx->final(hash_ctx, hash2, PTLS_HASH_FINAL_MODE_FREE);

    return ret;
}

int test_hash(ptls_hash_algorithm_t* algo, ptls_hash_algorithm_t* ref)
{
    int ret = 0;
    uint8_t input[1234];
    uint8_t final_hash[32];
    uint8_t final_ref[32];
    uint8_t hash1[32], hash2[32], href1[32], href2[32];

    memset(input, 0xba, sizeof(input));

    ret = hash_trial(algo, input, sizeof(input), 0, final_hash);
    if (ret == 0) {
        ret = hash_trial(ref, input, sizeof(input), 0, final_ref);
    }
    if (ret == 0) {
        if (memcmp(final_hash, final_ref, ref->digest_size) != 0) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = hash_trial(algo, input, sizeof(input) - 17, 17, final_hash);
    }
    if (ret == 0) {
        if (memcmp(final_hash, final_ref, ref->digest_size) != 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = hash_reset_trial(algo, input, sizeof(input) - 126, 126, hash1, hash2);
    }
    if (ret == 0) {
        ret = hash_reset_trial(ref, input, sizeof(input) - 126, 126, href1, href2);
    }
    if (ret == 0) {
        if (memcmp(hash1, href1, ref->digest_size) != 0) {
            ret = -1;
        }
        else if (memcmp(hash2, href2, ref->digest_size) != 0) {
            ret = -1;
        }
    }

    return ret;
}

int cipher_trial(ptls_cipher_algorithm_t * cipher, const uint8_t * key, const uint8_t * iv, int is_enc, const uint8_t * v_in, uint8_t * v_out1, uint8_t * v_out2, size_t len)
{
    int ret = 0;
    ptls_cipher_context_t* test_cipher = ptls_cipher_new(cipher, is_enc, key);
    if (test_cipher == NULL) {
        ret = -1;
    } else {
        if (test_cipher->do_init != NULL) {
            ptls_cipher_init(test_cipher, iv);
        }
        ptls_cipher_encrypt(test_cipher, v_out1, v_in, len);
        if (test_cipher->do_init != NULL) {
            ptls_cipher_init(test_cipher, iv);
        }
        ptls_cipher_encrypt(test_cipher, v_out2, v_out1, len);
        ptls_cipher_free(test_cipher);
    }

    return ret;
}

int test_cipher(ptls_cipher_algorithm_t * cipher, ptls_cipher_algorithm_t * cipher_ref)
{
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t v_in[16];
    uint8_t v_out_1a[16], v_out_2a[16], v_out_1b[16], v_out_2b[16], v_out_1d[16], v_out_2d[16];
    int ret = 0;

    /* Set initial values */
    memset(key, 0x55, sizeof(key));
    memset(iv, 0x33, sizeof(iv));
    memset(v_in, 0xaa, sizeof(v_in));

    /* Encryption test */
    ret = cipher_trial(cipher, key, iv, 1, v_in, v_out_1a, v_out_2a, 16);
    if (ret == 0) {
        ret = cipher_trial(cipher_ref, key, iv, 1, v_in, v_out_1b, v_out_2b, 16);
    }
    if (ret == 0) {
        if (memcmp(v_out_1a, v_out_1b, 16) != 0) {
            ret = -1;
        }
        else if (memcmp(v_out_2a, v_out_2b, 16) != 0) {
            ret = -1;
        }
    }
    /* decryption test */
    if (ret == 0) {
        ret = cipher_trial(cipher, key, iv, 0, v_out_2a, v_out_1d, v_out_2d, 16);
    }
    if (ret == 0) {
        if (memcmp(v_out_1a, v_out_1d, 16) != 0) {
            ret = -1;
        }
        else if (memcmp(v_out_2d, v_in, 16) != 0) {
            ret = -1;
        }
    }

    return ret;
}

int label_test(ptls_hash_algorithm_t * hash, uint8_t * v_out, size_t o_len, const uint8_t * secret,
    char const * label, char const * label_prefix)
{
    uint8_t h_val_v[32];
    ptls_iovec_t h_val = { 0 };
    ptls_iovec_t s_vec = { 0 };
    s_vec.base = (uint8_t *)secret;
    s_vec.len = 32;
    h_val.base = h_val_v;
    h_val.len = 32;
    memset(h_val_v, 0, sizeof(h_val_v));

    ptls_hkdf_expand_label(hash, v_out, o_len, s_vec, label, h_val, label_prefix);
    return 0;
}

int test_label(ptls_hash_algorithm_t* hash, ptls_hash_algorithm_t* ref)
{
    int ret = 0;
    uint8_t v_out[16], v_ref[16];
    uint8_t secret[32];
    char const* label = "label";
    char const* label_prefix = "label_prefix";
    memset(secret, 0x5e, sizeof(secret));

    ret = label_test(hash, v_out, 16, secret, label, label_prefix);

    if (ret == 0) {
        ret = label_test(ref, v_ref, 16, secret, label, label_prefix);
    }

    if (ret == 0 && memcmp(v_out, v_ref, 16) != 0) {
        ret = -1;
    }

    return ret;
}


int aead_trial(ptls_aead_algorithm_t * algo, ptls_hash_algorithm_t * hash, const uint8_t * secret, int is_enc, 
    const uint8_t * v_in, size_t len, uint8_t * aad, size_t aad_len, uint64_t seq, uint8_t * v_out, size_t * o_len)
{
    int ret = 0;
    ptls_aead_context_t* aead = ptls_aead_new(algo, hash, is_enc, secret, "test_aead");

    if (aead == NULL) {
        ret = -1;
    }
    else{
        if (is_enc) {
            *o_len = ptls_aead_encrypt(aead, v_out, v_in, len, seq, aad, aad_len);
            if (*o_len != len + algo->tag_size) {
                ret = -1;
            }
        }
        else {
            *o_len = ptls_aead_decrypt(aead, v_out, v_in, len, seq, aad, aad_len);
            if (*o_len != len - algo->tag_size) {
                ret = -1;
            }
        }
        ptls_aead_free(aead);
    }
    return ret;
}

int test_aead(ptls_aead_algorithm_t* algo, ptls_hash_algorithm_t* hash, ptls_aead_algorithm_t* ref, ptls_hash_algorithm_t* hash_ref)
{
    uint8_t secret[32];
    uint8_t v_in[1234];
    uint8_t aad[17];
    uint8_t v_out_a[1250], v_out_b[1250], v_out_r[1250];
    size_t olen_a, olen_b, olen_r;
    uint64_t seq = 12345;
    int ret = 0;

    memset(secret, 0x58, sizeof(secret));
    memset(v_in, 0x12, sizeof(v_in));
    memset(aad, 0xaa, sizeof(aad));

    ret = aead_trial(algo, hash, secret, 1, v_in, sizeof(v_in), aad, sizeof(aad), seq, v_out_a, &olen_a);
    if (ret == 0) {
        ret = aead_trial(ref, hash_ref, secret, 1, v_in, sizeof(v_in), aad, sizeof(aad), seq, v_out_b, &olen_b);
    }
    if (ret == 0 && (olen_a != olen_b || memcmp(v_out_a, v_out_b, olen_a) != 0)) {
        ret = -1;
    }
    if (ret == 0) {
        ret = aead_trial(ref, hash_ref, secret, 0, v_out_a, olen_a, aad, sizeof(aad), seq, v_out_r, &olen_r);
    }
    if (ret == 0 && (olen_r != sizeof(v_in) || memcmp(v_in, v_out_r, sizeof(v_in)) != 0)) {
        ret = -1;
    }
    return ret;
}

/* Test key exchanges. We copy paste the code from "test.h".
* in production, we should reuse this code.
 */

int test_key_exchange(ptls_key_exchange_algorithm_t *client, ptls_key_exchange_algorithm_t *server)
{
    ptls_key_exchange_context_t *ctx;
    ptls_iovec_t client_secret, server_pubkey, server_secret;
    int f_ret;
    int ret = 0;

    /* fail */
    if ((f_ret = server->exchange(server, &server_pubkey, &server_secret, (ptls_iovec_t) { NULL })) == 0) {
        ret = -1;
    }
    if (ret == 0) {
        /* perform ecdh */
        ret = client->create(client, &ctx);
        if (ret == 0) {
            ret = server->exchange(server, &server_pubkey, &server_secret, ctx->pubkey);
        }
        if (ret == 0) {
            ret = ctx->on_exchange(&ctx, 1, &client_secret, server_pubkey);
        }
        if (ret == 0) {
            if (client_secret.len != server_secret.len ||
                memcmp(client_secret.base, server_secret.base, client_secret.len) != 0) {
                ret = -1;
            }
        }
    }

    free(client_secret.base);
    free(server_pubkey.base);
    free(server_secret.base);

    if (ret == 0) {
        /* client abort */
        ret = client->create(client, &ctx);
        if (ret == 0) {
            ret = ctx->on_exchange(&ctx, 1, NULL, ptls_iovec_init(NULL, 0));
        }
        if (ctx != NULL) {
            ret = -1;
        }
    }

    return ret;
}

/*
Sign certificate has to implement a callback:

if ((ret = tls->ctx->sign_certificate->cb(
tls->ctx->sign_certificate, tls, tls->is_server ? &tls->server.async_job : NULL, &algo, sendbuf,
ptls_iovec_init(data, datalen), signature_algorithms != NULL ? signature_algorithms->list : NULL,
signature_algorithms != NULL ? signature_algorithms->count : 0)) != 0) {

or:

static int sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
ptls_buffer_t *outbuf, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)

The callback "super" type is ptls_sign_certificate_t, defined by the macro:
PTLS_CALLBACK_TYPE(int, sign_certificate, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
ptls_buffer_t *output, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms);

The notation is simple: input buffer and supported algorithms as input, selected algo and output buffer as output.
Output buffer is already partially filled.

For PSA/MbedTLS, see:
https://mbed-tls.readthedocs.io/en/latest/getting_started/psa/
Using PSA, Signing a message with RSA provides the following sequence:

-- Set key attributes --
psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
psa_set_key_bits(&attributes, 1024);

-- Import the key --
status = psa_import_key(&attributes, key, key_len, &key_id);
if (status != PSA_SUCCESS) {
    printf("Failed to import key\n");
    return;
}

-- Sign message using the key --
status = psa_sign_hash(key_id, PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
    hash, sizeof(hash),
    signature, sizeof(signature),
    &signature_length);

TODO: verify that Picotls does compute the hash before calling sign.
TODO: verify that there are "sign raw" implementations for ECDSA, EDDSA

-- Verify hash:
psa_status_t psa_verify_hash(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length)

Load a key in memory

int mbedtls_pk_parse_keyfile(mbedtls_pk_context* ctx,
    const char* path, const char* pwd,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

But before using the psa API, the key must be imported. That means the key has to
be expressed in the proper x509/DER format.

*/



int test_load_one_key(char const * path)
{
    mbedtls_pk_context ctx = { 0 };

    int ret = mbedtls_pk_parse_keyfile(&ctx, path, NULL, NULL, NULL);

    return ret;
}


#define ASSET_DIR ..\\..\\data
#define ASSET_RSA_KEY "..\\..\\data\\rsa\\key.pem"
#define ASSET_RSA_PKCS8_KEY "..\\..\\data\\rsa-pkcs8\\key.pem"
#define ASSET_SECP256R1_KEY "..\\..\\data\\secp256r1\\key.pem"
#define ASSET_SECP384R1_KEY "..\\..\\data\\secp384r1\\key.pem"
#define ASSET_SECP521R1_KEY "..\\..\\data\\secp521r1\\key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "..\\..\\data\\secp256r1-pkcs8\\key.pem"
#define ASSET_ED25519_KEY "..\\..\\data\\ed25519\\key.pem"


int test_load_key()
{
    int ret = test_load_one_key(ASSET_RSA_KEY);

    if (ret == 0) {
        ret = test_load_one_key(ASSET_SECP256R1_KEY);
    }

    return ret;
}


#if defined(MBEDTLS_PEM_PARSE_C)

int test_parse_der_length(unsigned char* pem_buf, size_t pem_len, size_t* px, size_t *pl)
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

int test_parse_ecdsa_field(unsigned char* pem_buf, size_t pem_len, size_t* key_index, size_t* key_length)
{
    int ret = 0;
    int param_index_index = -1;
    int param_length = 0;
    size_t x = 0;
#if 0
    static const unsigned char oid_secp256r1[10] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    static const unsigned char oid_secp384r1[7] = { 0x06, 0x05, 0x2b, 0x80, 0x04, 0x00, 0x24 };
    static const unsigned char oid_secp512r1[7] = { 0x06, 0x05, 0x2b, 0x80, 0x04, 0x00, 0x25 };
#endif

    // const unsigned char head = { 0x30, l-2, 0x02, 0x01, 0x01, 0x04 }
    if (pem_len < 16 ||
        pem_buf[x++] != 0x30 /* type = sequence */)
    {
        ret = -1;
    }
    else {
        size_t l = 0;
        ret = test_parse_der_length(pem_buf, pem_len, &x, &l);

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
#if 1
                    size_t l = 0;
                    ret = test_parse_der_length(pem_buf, pem_len, &x, &l);
                    x += l;
#else
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
                    x += l;
#endif
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
int test_parse_eddsa_key(unsigned char* pem_buf, size_t pem_len,
    size_t* key_index, size_t* key_length)
{
    int ret = 0;
    size_t x = *key_index;
    size_t l_key = 0;

    if (*key_length < 2 || pem_buf[x++] != 0x04) {
        ret = -1;
    } else {
        ret = test_parse_der_length(pem_buf, pem_len, &x, &l_key);
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
int test_parse_ec_private_key(unsigned char* pem_buf, size_t pem_len,
    size_t* key_index, size_t* key_length)
{
    size_t x_offset = 0;
    size_t x_len = 0;
    int ret = test_parse_ecdsa_field(pem_buf + *key_index, *key_length, &x_offset, &x_len);

    if (ret == 0) {
        *key_index += x_offset;
        *key_length = x_len;
    }
    return ret;
}

int test_parse_private_key_field(unsigned char* pem_buf, size_t pem_len,
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
        ret = test_parse_der_length(pem_buf, pem_len, &x, &l);

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
            ret = test_parse_der_length(pem_buf, pem_len, &x, &l_seq);
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
            ret = test_parse_der_length(pem_buf, pem_len, &x, &l_key);
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

int mbedtls_get_asn1_key(mbedtls_pem_context* pem,
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

static const unsigned char ptls_mbedtls_oid_ec_key[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
static const unsigned char ptls_mbedtls_oid_rsa_key[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
static const unsigned char ptls_mbedtls_oid_ed25519[] = { 0x2b, 0x65, 0x70 };

int test_load_one_der_key(char const* path)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    unsigned char* buf;
    mbedtls_pem_context pem = { 0 };
    mbedtls_pk_type_t pk_type = 0;
    mbedtls_svc_key_id_t key_id = 0;
    size_t key_index = 0;
    size_t key_length = 0;
    unsigned char hash[32];
    const unsigned char h0[32] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32
    };
    unsigned char signature[512];
    size_t signature_length = 0;
    unsigned int signature_type = 0;


    if ((ret = mbedtls_pk_load_file(path, &buf, &n)) != 0) {
        return ret;
    }
    ret = mbedtls_get_asn1_key(&pem, &pk_type, buf, n, NULL, 0, NULL, NULL);

    /* We cannot use the platform API:
        mbedtls_zeroize_and_free(buf, n);
        so we do our own thing.
    */
    memset(buf, 0, n);
    free(buf);

    if (ret == 0) {
        psa_key_attributes_t attributes = psa_key_attributes_init();
        if (pk_type == MBEDTLS_PK_RSA) {
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
            psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
            psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
            key_length = pem.private_buflen;
        }
        else if (pk_type == MBEDTLS_PK_ECKEY) {
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
            psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_BASE);
            psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
            ret = test_parse_ecdsa_field(pem.private_buf, pem.private_buflen, &key_index, &key_length);
        }
        else if (pk_type == MBEDTLS_PK_NONE) {
            /* TODO: not clear whether MBDED TLS supports ED25519 yet. Probably not. */
            /* Should have option to encode RSA or ECDSA using PKCS8 */
            size_t oid_index = 0;
            size_t oid_length = 0;

            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
            ret = test_parse_private_key_field(pem.private_buf, pem.private_buflen, &oid_index, &oid_length, &key_index, &key_length);
            if (ret == 0) {
                /* need to parse the OID in order to set the parameters */

                if (oid_length == sizeof(ptls_mbedtls_oid_ec_key) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_ec_key, sizeof(ptls_mbedtls_oid_ec_key)) == 0) {
                    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
                    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_BASE);
                    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
                    ret = test_parse_ec_private_key(pem.private_buf, pem.private_buflen, &key_index, &key_length);
                }
                else if (oid_length == sizeof(ptls_mbedtls_oid_ed25519) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_ed25519, sizeof(ptls_mbedtls_oid_ed25519)) == 0) {
                    /* We recognized ED25519 -- PSA_ECC_FAMILY_TWISTED_EDWARDS -- PSA_ALG_ED25519PH*/
                    psa_set_key_algorithm(&attributes, PSA_ALG_PURE_EDDSA);
                    psa_set_key_type(&attributes, PSA_ECC_FAMILY_TWISTED_EDWARDS);
                    ret = test_parse_eddsa_key(pem.private_buf, pem.private_buflen, &key_index, &key_length);
                }
                else if (oid_length == sizeof(ptls_mbedtls_oid_rsa_key) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_rsa_key, sizeof(ptls_mbedtls_oid_rsa_key)) == 0) {
                    /* We recognized RSA */
                    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
                    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
                    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
                }
                else {
                    ret = -1;
                }
            }
        }
        else {
            ret = -1;
        }

        if (ret == 0) {
            /* Now that we have the DER or bytes for the key, try import into PSA */
            psa_status_t status = psa_import_key(&attributes, pem.private_buf + key_index, key_length, &key_id);

            if (status != PSA_SUCCESS) {
                ret = -1;
            }
            else {
                /* get the key algorithm */
                psa_algorithm_t algo = psa_get_key_algorithm(&attributes);
                /* Try to sign something */
                memcpy(hash, h0, 32);
                /* Sign message using the key */
                status = psa_sign_hash(key_id, algo,
                    hash, sizeof(hash),
                    signature, sizeof(signature),
                    &signature_length);
                if (status != PSA_SUCCESS) {
                    printf("Failed to sign\n");
                    ret = -1;
                }
                else {
                    printf("Signed a message, key: %s, signature size: %zu\n", path, signature_length);
                }
                /* Destroy the key */
                psa_destroy_key(key_id);
            }
        }
        /* Free the attributes */
        psa_reset_key_attributes(&attributes);

        /* Free the PEM buffer */
        mbedtls_pem_free(&pem);
    }

    return ret;
}

int test_load_der()
{
    int ret = 0;
    if (ret == 0) {
        ret = test_load_one_der_key(ASSET_RSA_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_der_key(ASSET_SECP256R1_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_der_key(ASSET_SECP384R1_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_der_key(ASSET_SECP521R1_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_der_key(ASSET_SECP256R1_PKCS8_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_der_key(ASSET_RSA_PKCS8_KEY);
    }

#if 0
    /* Commenting out ED25519 for now, probably not supported yet in MBEDTLS/PSA */
    if (ret == 0) {
        ret = test_load_one_der_key(ASSET_ED25519_KEY);
    }
#endif

    return ret;
}
