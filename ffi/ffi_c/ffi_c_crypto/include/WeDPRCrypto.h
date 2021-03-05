#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" {
/**
 * C interface for 'wedpr_secp256k1_ecies_encrypt'.
 */
char* wedpr_secp256k1_ecies_encrypt(char* encoded_public_key, char* encoded_plaintext);

/**
 * C interface for 'wedpr_secp256k1_ecies_decrypt'.
 */
char* wedpr_secp256k1_ecies_decrypt(char* encoded_private_key, char* encoded_ciphertext);

/**
 * C interface for 'wedpr_keccak256_hash'.
 */
char* wedpr_keccak256_hash(const char* encoded_message);

/**
 * C interface for 'wedpr_sm3_hash'.
 */
char* wedpr_sm3_hash(const char* encoded_message);

/**
 * C interface for 'wedpr_secp256k1_gen_key_pair'.
 */
char* wedpr_secp256k1_gen_key_pair(void);

/**
 * C interface for 'wedpr_secp256k1_derive_public_key'.
 */
char* wedpr_secp256k1_derive_public_key(const char* encoded_private_key);

/**
 * C interface for 'wedpr_secp256k1_sign'.
 */
char* wedpr_secp256k1_sign(const char* encoded_private_key, const char* encoded_message_hash);

/**
 * C interface for 'wedpr_secp256k1_verify'.
 */
int8_t wedpr_secp256k1_verify(const char* encoded_public_key, const char* encoded_message_hash,
    const char* encoded_signature);

/**
 * C interface for 'wedpr_secp256k1_recover_public_key'.
 */
char* wedpr_secp256k1_recover_public_key(
    const char* encoded_message_hash, const char* encoded_signature);

/**
 * C interface for 'wedpr_sm2_gen_key_pair'.
 */
char* wedpr_sm2_gen_key_pair(void);

/**
 * C interface for 'wedpr_sm2_derive_public_key'.
 */
char* wedpr_sm2_derive_public_key(const char* encoded_private_key);

/**
 * C interface for 'wedpr_sm2_sign'.
 */
char* wedpr_sm2_sign(const char* encoded_private_key, const char* encoded_message_hash);

/**
 * C interface for 'wedpr_sm2_sign_fast'.
 */
char* wedpr_sm2_sign_fast(const char* encoded_private_key, const char* encoded_public_key,
    const char* encoded_message_hash);

/**
 * C interface for 'wedpr_sm2_verify'.
 */
int8_t wedpr_sm2_verify(const char* encoded_public_key, const char* encoded_message_hash,
    const char* encoded_signature);

/**
 * C interface for 'wedpr_curve25519_vrf_derive_public_key'.
 */
char* wedpr_curve25519_vrf_derive_public_key(const char* encoded_private_key);

/**
 * C interface for 'wedpr_curve25519_vrf_prove_utf8'.
 */
char* wedpr_curve25519_vrf_prove_utf8(const char* encoded_private_key, const char* utf8_message);

/**
 * C interface for 'wedpr_curve25519_vrf_prove_fast_utf8'.
 */
char* wedpr_curve25519_vrf_prove_fast_utf8(
    const char* encoded_private_key, const char* encoded_public_key, const char* utf8_message);

/**
 * C interface for 'wedpr_curve25519_vrf_verify_utf8'.
 */
int8_t wedpr_curve25519_vrf_verify_utf8(
    const char* encoded_public_key, const char* utf8_message, const char* encoded_proof);

/**
 * C interface for 'wedpr_curve25519_vrf_proof_to_hash'.
 */
char* wedpr_curve25519_vrf_proof_to_hash(const char* encoded_proof);

/**
 * C interface for 'wedpr_curve25519_vrf_is_valid_public_key'.
 */
int8_t wedpr_curve25519_vrf_is_valid_public_key(const char* encoded_public_key);
}
