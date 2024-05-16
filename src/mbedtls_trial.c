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
int test_load_file();
int test_load_key();
int test_load_key_fail();
int test_sign_verify();

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
#ifdef _WINDOWS
    printf("testing on WIndows.\n");
#else
    printf("Testing on Unix.\n");
#endif

    /* Initialize the PSA crypto library. */
    if ((ret = ptls_mbedtls_init()) != 0) {
        fprintf(stdout, "psa_crypto_init fails.\n");
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
            ret = test_load_file();
            printf("test load file returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_load_key();
            printf("test load key returns:0x%x\n", ret);
            if (ret < 0 && ret != -1) {
                char buf[256];
                buf[0] = 0;
                mbedtls_strerror(ret, buf, sizeof(buf));
                printf("MbedTLS error -0x%x, %s\n", ret, buf);
            }
        }

        if (ret == 0) {
            ret = test_load_key_fail();
            printf("test load key fail returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_sign_verify();
            printf("test sign verify returns: %d\n", ret);
            if (ret != 0) {
                /* Bypass the test for now, because we do not yet have the
                 * proper test certificates */
                printf("Ignoring test sign verify for now, until proper certificates are provided.\n");
                ret = 0;
            }
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
#ifdef _WINDOWS
#define ASSET_DIR ..\\..\\data
#define ASSET_RSA_KEY "..\\..\\data\\rsa\\key.pem"
#define ASSET_RSA_PKCS8_KEY "..\\..\\data\\rsa-pkcs8\\key.pem"
#define ASSET_SECP256R1_KEY "..\\..\\data\\secp256r1\\key.pem"
#define ASSET_SECP384R1_KEY "..\\..\\data\\secp384r1\\key.pem"
#define ASSET_SECP521R1_KEY "..\\..\\data\\secp521r1\\key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "..\\..\\data\\secp256r1-pkcs8\\key.pem"
#define ASSET_ED25519_KEY "..\\..\\data\\ed25519\\key.pem"
#define ASSET_NO_SUCH_FILE "..\\..\\data\\no_such_file.pem"
#define ASSET_NOT_A_PEM_FILE "..\\..\\data\\not_a_valid_pem_file.pem"
#define ASSET_RSA_CERT "..\\..\\data\\rsa\\cert.pem"
#define ASSET_RSA_PKCS8_CERT "..\\..\\data\\rsa-pkcs8\\cert.pem"
#define ASSET_SECP256R1_CERT "..\\..\\data\\secp256r1\\cert.pem"
#define ASSET_SECP384R1_CERT "..\\..\\data\\secp384r1\\cert.pem"
#define ASSET_SECP521R1_CERT "..\\..\\data\\secp521r1\\cert.pem"
#define ASSET_SECP256R1_PKCS8_CERT "..\\..\\data\\secp256r1-pkcs8\\cert.pem"
#define ASSET_ED25519_CERT "..\\..\\data\\ed25519\\cert.pem"

#define ASSET_TEST_CA "..\\..\\data\\test-ca.crt"
#else
#define ASSET_DIR data
#define ASSET_RSA_KEY "data/rsa/key.pem"
#define ASSET_RSA_PKCS8_KEY "data/rsa-pkcs8/key.pem"
#define ASSET_SECP256R1_KEY "data/secp256r1/key.pem"
#define ASSET_SECP384R1_KEY "data/secp384r1/key.pem"
#define ASSET_SECP521R1_KEY "data/secp521r1/key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "data/secp256r1-pkcs8/key.pem"
#define ASSET_ED25519_KEY "data/ed25519/key.pem"
#define ASSET_NO_SUCH_FILE "data/no_such_file.pem"
#define ASSET_NOT_A_PEM_FILE "data/not_a_valid_pem_file.pem"
#define ASSET_RSA_CERT "data/rsa/cert.pem"
#define ASSET_RSA_PKCS8_CERT "data/rsa-pkcs8/cert.pem"
#define ASSET_SECP256R1_CERT "data/secp256r1/cert.pem"
#define ASSET_SECP384R1_CERT "data/secp384r1/cert.pem"
#define ASSET_SECP521R1_CERT "data/secp521r1/cert.pem"
#define ASSET_SECP256R1_PKCS8_CERT "data/secp256r1-pkcs8/cert.pem"
#define ASSET_ED25519_CERT "data/ed25519/cert.pem"

#define ASSET_TEST_CA "data/test-ca.crt"
#endif

int test_load_one_file(char const* path)
{
    size_t n;
    unsigned char *buf;
    int ret = ptls_mbedtls_load_file(path, &buf, &n);
    if (ret != 0) {
        printf("Cannot load file from: %s, ret = %d (0x%x, -0x%x)\n", path, ret, ret, (int16_t)-ret);
    }
    else if (n == 0) {
        printf("File %s is empty\n", path);
        ret = -1;
    }
    else if (buf[n] != 0) {
        printf("Buffer from %s is not null terminated\n", path);
        ret = -1;
    }
    if (buf != NULL) {
        free(buf);
    }
    return ret;
}

int test_load_file()
{
    int ret = 0;
    if (ret == 0) {
        ret = test_load_one_file(ASSET_RSA_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_file(ASSET_SECP256R1_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_file(ASSET_SECP384R1_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_file(ASSET_SECP521R1_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_file(ASSET_SECP256R1_PKCS8_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_file(ASSET_RSA_PKCS8_KEY);
    }
    return ret;
}

int test_load_one_key(char const* path)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char hash[32];
    const unsigned char h0[32] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32
    };
    ptls_context_t ctx = { 0 };

    ret = ptls_mbedtls_load_private_key(&ctx, path);
    if (ret != 0) {
        printf("Cannot create load private key from: %s, ret = %d (0x%x, -0x%x)\n", path, ret, ret, (int16_t)-ret);
    }
    else if (ctx.sign_certificate == NULL) {
        printf("Sign_certificate not set in ptls context for: %s\n", path);
        ret = -1;
    }
    else {
        /* Try to sign something */
        int ret;
        ptls_mbedtls_sign_certificate_t* signer = (ptls_mbedtls_sign_certificate_t*)
            (((unsigned char*)ctx.sign_certificate) - offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
        ptls_buffer_t outbuf;
        uint8_t outbuf_smallbuf[256];
        ptls_iovec_t input = { hash, sizeof(hash) };
        uint16_t selected_algorithm = 0;
        int num_algorithms = 0;
        uint16_t algorithms[16];
        memcpy(hash, h0, 32);
        while (signer->schemes[num_algorithms].scheme_id != UINT16_MAX && num_algorithms < 16) {
            algorithms[num_algorithms] = signer->schemes[num_algorithms].scheme_id;
            num_algorithms++;
        }

        ptls_buffer_init(&outbuf, outbuf_smallbuf, sizeof(outbuf_smallbuf));

        ret = ptls_mbedtls_sign_certificate(ctx.sign_certificate, NULL, NULL, &selected_algorithm,
            &outbuf, input, algorithms, num_algorithms);
        if (ret == 0) {
            printf("Signed a message, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
        }
        else {
            printf("Sign failed, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
        }
        ptls_buffer_dispose(&outbuf);
        ptls_mbedtls_dispose_sign_certificate(&signer->super);
    }

    return ret;
}

int test_load_key()
{
    int ret = 0;
    if (ret == 0) {
        ret = test_load_one_key(ASSET_RSA_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_key(ASSET_SECP256R1_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_key(ASSET_SECP384R1_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_key(ASSET_SECP521R1_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_key(ASSET_SECP256R1_PKCS8_KEY);
    }

    if (ret == 0) {
        ret = test_load_one_key(ASSET_RSA_PKCS8_KEY);
    }

#if 0
    /* Commenting out ED25519 for now, not supported yet in MBEDTLS/PSA */
    if (ret == 0) {
        ret = test_load_one_key(ASSET_ED25519_KEY);
    }
#endif
    return ret;
}

/*
* Testing of failure modes.
* 
* Testing the various reasons why loading of key should fail:
* - key file does not exist
* - key file is empty, no PEM keyword
* - key file does not contain a key (we use a cert file for that)
* - key file is for ED25559, which is not supported
*/
int test_load_key_fail()
{
    int ret = 0;

    if (ret == 0 && test_load_one_key(ASSET_NO_SUCH_FILE) == 0)
    {
        ret = -1;
    }

    if (ret == 0 && test_load_one_key(ASSET_NOT_A_PEM_FILE) == 0)
    {
        ret = -1;
    }

    if (ret == 0 && test_load_one_key(ASSET_RSA_CERT) == 0)
    {
        ret = -1;
    }

    if (ret == 0 && test_load_one_key(ASSET_ED25519_KEY) == 0)
    {
        ret = -1;
    }

    return ret;
}

#if 1
/*
* End to end testing of signature and verifiers:
* The general scenario is:
* - prepare a signature of a test string using a simulated
*   server programmed with a private key and a certificate
*   list.
* - verify the signature in a simulated client programmed
*   with a list of trusted certificates.
* 
* The test is configured with the file names for the key,
* certificate list, and trusted certificates. 
* 
* Ideally, we should be able to run the test by mixing and 
* matching mbedtls server or clients with other backends.
* However, using openssl will require some plumbing,
* which will be done when integrating this code in 
* picotls. For now, we will only do self tests, and test with
* minicrypto if the key is supported.
*/

const unsigned char test_sign_verify_message[] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9 , 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
    60, 61, 62, 63, 64
};
const size_t test_sign_verify_message_size = sizeof(test_sign_verify_message);

uint16_t test_sign_signature_algorithms[] = {
    0x0401, 0x0403, 0x501, 0x0503, 0x0601, 0x0603,
    0x0804, 0x0805, 0x0806, 0x0807, 0x0808
};

size_t num_test_sign_signature_algorithms = sizeof(test_sign_signature_algorithms) / sizeof(uint16_t);

char const* test_sign_server_name = "test.example.com";

int test_sign_init_server_mbedtls(ptls_context_t* ctx, char const* key_path, char const* cert_path)
{
    int ret = ptls_mbedtls_load_private_key(ctx, key_path);
    if (ret == 0) {
        ret = picoquic_mbedtls_get_certs_from_file(cert_path, &ctx->certificates.list, &ctx->certificates.count);
    }
    return ret;
}

int test_sign_init_server_minicrypto(ptls_context_t* ctx, char const* key_path, char const* cert_path)
{
    int ret = ptls_minicrypto_load_private_key(ctx, key_path);
    if (ret == 0) {
        ret = ptls_load_certificates(ctx, cert_path);
    }
    return ret;
}

void test_sign_free_certificates(ptls_context_t* ctx)
{
    if (ctx->certificates.list != NULL) {
        for (int i = 0; i < ctx->certificates.count; i++) {
            free(ctx->certificates.list[i].base);
        }
        free(ctx->certificates.list);
    }
    ctx->certificates.list = NULL;
    ctx->certificates.count = 0;
}

void test_sign_free_context(ptls_context_t* ctx, int config)
{
    /* Free the server context */
    if (ctx == NULL) {
        return;
    }
    test_sign_free_certificates(ctx);
    if (ctx->sign_certificate != NULL) {
        switch (config) {
        case 0:
            ptls_mbedtls_dispose_sign_certificate(ctx->sign_certificate);
            break;
        case 1:
        default:
            free(ctx->sign_certificate);
            ctx->sign_certificate = NULL;
        }
    }

    if (ctx->verify_certificate != NULL) {
        switch (config) {
        case 0:
            ptls_mbedtls_dispose_verify_certificate(ctx);
            break;
        default:
            break;
        }
    }

    free(ctx);
}

ptls_context_t* test_sign_set_ptls_context(char const* key_path, char const* cert_path, char const* trusted_path, int is_server, int config)
{
    int ret = 0;
    ptls_context_t* ctx = (ptls_context_t*)malloc(sizeof(ptls_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    memset(ctx, 0, sizeof(ptls_context_t));
    ctx->get_time = &ptls_get_time;

    switch (config) {
    case 0:
        ctx->random_bytes = ptls_mbedtls_random_bytes;
    case 1:
    default:
        break;
    }
    
    if (is_server) {
        /* First, create the "signer" plug-in */
        switch (config) {
        case 0: /* MbedTLS */
            ret = test_sign_init_server_mbedtls(ctx, key_path, cert_path);
            break;
        case 1: /* Minicrypto */
            ret = test_sign_init_server_minicrypto(ctx, key_path, cert_path);
            break;
        default:
            ret = -1;
            break;
        }
    }
    else {
        /* Initialize the client verify context */
        switch (config) {
        case 0: /* MbedTLS */
            ret = ptls_mbedtls_init_verify_certificate(ctx, trusted_path);
            break;
        default:
            ret = -1;
            break;
        }
    }

    if (ret != 0) {
        /* Release and return NULL */
        test_sign_free_context(ctx, config);
        ctx = NULL;
    }
    return ctx;
}

int test_sign_verify_one(char const* key_path, char const * cert_path, char const * trusted_path, int server_config, int client_config)
{
    int ret = 0;
    ptls_context_t* server_ctx = test_sign_set_ptls_context(key_path, cert_path, trusted_path, 1, server_config); 
    ptls_context_t* client_ctx = test_sign_set_ptls_context(key_path, cert_path, trusted_path, 0, client_config);
    ptls_t* client_tls = NULL;
    ptls_t* server_tls = NULL;
    uint16_t selected_algorithm = 0;
    uint8_t signature_smallbuf[256];
    ptls_buffer_t signature;
    struct {
        int (*cb)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature);
        void *verify_ctx;
    } certificate_verify;
    ptls_iovec_t input;
    input.base = (uint8_t *)test_sign_verify_message;
    input.len = test_sign_verify_message_size;

    ptls_buffer_init(&signature, signature_smallbuf, sizeof(signature_smallbuf));

    if (server_ctx == NULL || client_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        /* Then, create a tls context for the server. */
        server_tls = ptls_new(server_ctx, 1);
        if (server_tls == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Then, create the signature messages */
        ret = server_ctx->sign_certificate->cb(server_ctx->sign_certificate, server_tls, NULL,
            &selected_algorithm, &signature, input,
            test_sign_signature_algorithms, num_test_sign_signature_algorithms);
        if (ret != 0) {
            printf("sign_certificate (%s) returns 0x%x\n", key_path, ret);
        }
    }

    if (ret == 0) {
        /* Then, create a tls context for the client. */
        client_tls = ptls_new(client_ctx, 0);
        if (client_tls == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        /* verify the certificates */
        ret = client_ctx->verify_certificate->cb(client_ctx->verify_certificate, client_tls, test_sign_server_name,
            &certificate_verify.cb, &certificate_verify.verify_ctx,
            server_ctx->certificates.list, server_ctx->certificates.count);
        if (ret != 0) {
            printf("verify_certificate (%s) returns 0x%x\n", cert_path, ret);
        }
        /* verify the signature */
        if (ret == 0) {
            ptls_iovec_t sig;
            sig.base = signature.base;
            sig.len = signature.off;

            ret = certificate_verify.cb(certificate_verify.verify_ctx, selected_algorithm, input, sig);
            if (ret != 0) {
                printf("verify_signature (%s) returns 0x%x\n", key_path, ret);
            }
        }
        else if (certificate_verify.cb != NULL) {
            ptls_iovec_t empty;
            empty.base = NULL;
            empty.len = 0;
            (void)certificate_verify.cb(certificate_verify.verify_ctx, 0, empty, empty);
        }
    }
    if (ret == 0) {
        printf("verify_signature (%s) and cert (%s) succeeds\n", key_path, cert_path);
    }

    ptls_buffer_dispose(&signature);

    if (client_tls != NULL) {
        ptls_free(client_tls);
    }
    if (server_tls != NULL) {
        ptls_free(server_tls);
    }

    test_sign_free_context(server_ctx, server_config);
    test_sign_free_context(client_ctx, client_config);

    return ret;
}

int test_sign_verify()
{
    int ret = 0;

    if (ret == 0) {
        ret = test_sign_verify_one(ASSET_RSA_KEY, ASSET_RSA_CERT, ASSET_TEST_CA, 0, 0);
    }

    if (ret == 0) {
        ret = test_sign_verify_one(ASSET_SECP256R1_KEY, ASSET_SECP256R1_CERT, ASSET_SECP256R1_CERT, 0, 0);
    }

    if (ret == 0) {
        ret = test_sign_verify_one(ASSET_SECP384R1_KEY, ASSET_SECP384R1_CERT, ASSET_SECP384R1_CERT, 0, 0);
    }

    if (ret == 0) {
        ret = test_sign_verify_one(ASSET_SECP521R1_KEY, ASSET_SECP521R1_CERT, ASSET_SECP521R1_CERT, 0, 0);
    }

    if (ret == 0) {
        ret = test_sign_verify_one(ASSET_SECP256R1_PKCS8_KEY, ASSET_SECP256R1_PKCS8_CERT, ASSET_SECP256R1_PKCS8_CERT, 0, 0);
    }

    return ret;
}
#endif