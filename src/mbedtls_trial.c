#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include "mbedtls/build_info.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "ptls_mbedtls.h"
#include "picotls/minicrypto.h"

int test_hash(ptls_hash_algorithm_t* algo, ptls_hash_algorithm_t* ref);
int test_label(ptls_hash_algorithm_t* hash, ptls_hash_algorithm_t* ref);
int test_cipher(ptls_cipher_algorithm_t* cipher, ptls_cipher_algorithm_t* cipher_ref);
int test_aead(ptls_aead_algorithm_t* algo, ptls_hash_algorithm_t* hash, ptls_aead_algorithm_t* ref, ptls_hash_algorithm_t* hash_ref);

int main(arg, argv)
{
    psa_status_t status = PSA_SUCCESS;
    ptls_cipher_algorithm_t* cipher_test[4] = {
        &ptls_mbedtls_aes128ecb,
        &ptls_mbedtls_aes128ctr,
        &ptls_mbedtls_aes256ecb,
        &ptls_mbedtls_aes256ctr };
    ptls_cipher_algorithm_t* cipher_ref[4] = {
        &ptls_minicrypto_aes128ecb,
        &ptls_minicrypto_aes128ctr,
        &ptls_minicrypto_aes256ecb,
        &ptls_minicrypto_aes256ctr };

    /* Initialize the PSA crypto library. */
    if ((status = psa_crypto_init()) != PSA_SUCCESS) {
        fprintf(stdout, "psa_crypto_init fails.");
    }
    else {
        int ret = 0;

        ret = test_hash(&ptls_mbedtls_sha256, &ptls_minicrypto_sha256);
        printf("test hash returns: %d\n", ret);

        if (ret == 0) {
            ret = test_label(&ptls_mbedtls_sha256, &ptls_minicrypto_sha256);
            printf("test label returns: %d\n", ret);
        }

        if (ret == 0) {
            for (int i = 0; i < 4; i++) {
                if (test_cipher(cipher_test[i], cipher_ref[i]) != 0) {
                    printf("test cipher %d fails", i);
                    ret = -1;
                }
            }
            printf("test ciphers returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_aead(&ptls_mbedtls_aes128gcm, &ptls_mbedtls_sha256, &ptls_minicrypto_aes128gcm, &ptls_minicrypto_sha256);
            printf("test aeads returns: %d\n", ret);
        }

        if (ret != 0 && status == PSA_SUCCESS) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
        /* Deinitialize the PSA crypto library. */
        mbedtls_psa_crypto_free();
    }
    return status == PSA_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
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