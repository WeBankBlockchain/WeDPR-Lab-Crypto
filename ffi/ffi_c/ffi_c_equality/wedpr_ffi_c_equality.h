#ifndef _WEDPR_CRYPTO_H_
#define _WEDPR_CRYPTO_H_

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "WedprUtilities.h"

extern "C" {
/**
 * C interface for 'encrypt_message'.
 */
int8_t wedpr_pairing_bls128_encrypt_message(const CInputBuffer *raw_plaintext,
                                            COutputBuffer *output_ciphertext);

/**
 * C interface for 'equality_test'.
 */
int8_t wedpr_pairing_bls128_equality_test(const CInputBuffer *raw_cipher1,
                                          const CInputBuffer *raw_cipher2);
}

#endif