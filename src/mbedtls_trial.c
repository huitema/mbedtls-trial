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


int main(arg, argv)
{
    psa_status_t status = PSA_SUCCESS;

#if 0
    /* Check usage */
    if (argc != 2) {
        puts(usage);
        return EXIT_FAILURE;
    }
#endif

    /* Initialize the PSA crypto library. */
    if ((status = psa_crypto_init()) != PSA_SUCCESS) {
        fprintf(stdout, "psa_crypto_init fails.");
    }
    else {
#if 0
        /* Run the demo */
        PSA_CHECK(aead_demo(argv[1]));
#endif
        /* Deinitialize the PSA crypto library. */
        mbedtls_psa_crypto_free();
    }
    return status == PSA_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

#if 0
void init_message(uint8_t * m, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++) {
        m[i] = seed++;
    }
}

int aead_trial()
{

}

void aead_demo(ptls_aead_algorithm_t* algo)
{
    uint8_t b1[127];
    uint8_t b2[135];
    uint8_t key[32];
    uint8_t iv[PTLS_MAX_IV_SIZE];
    uint8_t encrypted[256];
    uint8_t decrypted[256];
    

    /* Set the value of the messages */
    init_message(b1, sizeof(b1), 123);
    init_message(b2, sizeof(b2), 45);
    init_message(key, sizeof(key), 67);
    init_message(iv, sizeof(iv), 78);
    /* Create the encryption and decryption contexts */

}
#endif