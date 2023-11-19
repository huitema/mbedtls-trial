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
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_values.h"

#if 0
void ptls_mbedtls_sign()
{
    psa_status_t psa_sign_hash(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t * hash, size_t hash_length, uint8_t * signature, size_t signature_size, size_t * signature_length);
}

int ptls_mbedtls_load_private_key(ptls_context_t* ctx, char const* pem_fname)
{
    ptls_asn1_pkcs8_private_key_t pkey = {{0}};
    int ret = ptls_pem_parse_private_key(pem_fname, &pkey, NULL);

    if (ret != 0)
        goto err;

    /* Check that this is the expected key type.
    * At this point, the minicrypto library only supports ECDSA keys.
    * In theory, we could add support for RSA keys at some point.
    */
    if (pkey.algorithm_length != sizeof(ptls_asn1_algorithm_ecdsa) ||
        memcmp(pkey.vec.base + pkey.algorithm_index, ptls_asn1_algorithm_ecdsa, sizeof(ptls_asn1_algorithm_ecdsa)) != 0) {
        ret = -1;
        goto err;
    }

    ret = ptls_set_ecdsa_private_key(ctx, &pkey, NULL);

err:
    if (pkey.vec.base) {
        ptls_clear_memory(pkey.vec.base, pkey.vec.len);
        free(pkey.vec.base);
    }
    return ret;
}
#endif
