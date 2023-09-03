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

int test_cipher(ptls_cipher_algorithm_t* cipher, ptls_cipher_algorithm_t* cipher_ref);

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

        for (int i = 0; i < 4; i++) {
            if (test_cipher(cipher_test[i], cipher_ref[i]) != 0) {
                printf("test cipher %d fails", i);
                ret = -1;
            }
        }
        printf("test ciphers returns: %d\n", ret);

        /* Deinitialize the PSA crypto library. */
        mbedtls_psa_crypto_free();
    }
    return status == PSA_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
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