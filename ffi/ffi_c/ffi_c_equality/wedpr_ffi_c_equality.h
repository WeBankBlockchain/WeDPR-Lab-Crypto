#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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

/**
 * C interface for 'peks_test'.
 */
int8_t wedpr_pairing_bls128_peks_test(const CInputBuffer *peks_cipher,
                                      const CInputBuffer *trapdoor_cipher);
