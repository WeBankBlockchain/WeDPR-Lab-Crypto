#ifndef _WEDPR_CRYPTO_H_
#define _WEDPR_CRYPTO_H_
#include "WedprUtilities.h"

extern "C" {

// AES/SM4 crate v2: encrypt/decrypt use a versioned CBC-HMAC-SHA256
// encrypt-then-MAC envelope. Bare legacy CBC ciphertexts are rejected.
// A fresh unpredictable 16-byte IV is required for every encryption.
// Encryption output capacity: 16 * (plaintext_length / 16 + 1) + 40 bytes.
// IV, version and ciphertext are authenticated before any plaintext is returned.
// For these four binary APIs, insufficient output capacity returns -1, writes
// the required capacity to output->len, and leaves output->data untouched.

/// C interface for 'wedpr_aes256_encrypt'.
int8_t wedpr_aes256_encrypt(const CInputBuffer* raw_plaintext, const CInputBuffer* raw_key,
    const CInputBuffer* raw_iv, COutputBuffer* output_ciphertext);

/// C interface for 'wedpr_aes256_decrypt'.
int8_t wedpr_aes256_decrypt(const CInputBuffer* raw_ciphertext, const CInputBuffer* raw_key,
    const CInputBuffer* raw_iv, COutputBuffer* output_plaintext);

/// C interface for 'wedpr_sm4_encrypt'.
int8_t wedpr_sm4_encrypt(const CInputBuffer* raw_plaintext, const CInputBuffer* raw_key,
    const CInputBuffer* raw_iv, COutputBuffer* output_ciphertext);

/// C interface for 'wedpr_sm4_decrypt'.
int8_t wedpr_sm4_decrypt(const CInputBuffer* raw_ciphertext, const CInputBuffer* raw_key,
    const CInputBuffer* raw_iv, COutputBuffer* output_plaintext);

/// C interface for 'wedpr_keccak256_hash'.
int8_t wedpr_keccak256_hash(const CInputBuffer* raw_message, COutputBuffer* output_hash);

/// C interface for 'wedpr_sm3_hash'.
int8_t wedpr_sm3_hash(const CInputBuffer* raw_message, COutputBuffer* output_hash);

/// C interface for 'wedpr_sha256_hash'.
int8_t wedpr_sha256_hash(const CInputBuffer* raw_message, COutputBuffer* output_hash);

/// C interface for 'wedpr_ripemd160_hash'.
int8_t wedpr_ripemd160_hash(const CInputBuffer* raw_message, COutputBuffer* output_hash);

/// C interface for 'wedpr_sha3_hash'.
int8_t wedpr_sha3_hash(const CInputBuffer* raw_message, COutputBuffer* output_hash);

/// C interface for 'wedpr_blake2b_hash'.
int8_t wedpr_blake2b_hash(const CInputBuffer* message_input, COutputBuffer* output_hash);

/// C interface for 'wedpr_secp256k1_gen_key_pair'.
int8_t wedpr_secp256k1_gen_key_pair(
    COutputBuffer* output_public_key, COutputBuffer* output_private_key);

/// C interface for 'wedpr_secp256k1_derive_public_key'.
int8_t wedpr_secp256k1_derive_public_key(
    const CInputBuffer* raw_private_key, COutputBuffer* output_public_key);

/// C interface for 'wedpr_secp256k1_sign'.
int8_t wedpr_secp256k1_sign(const CInputBuffer* raw_private_key,
    const CInputBuffer* raw_message_hash, COutputBuffer* output_signature);

/// C interface for 'wedpr_secp256k1_verify'.
int8_t wedpr_secp256k1_verify(const CInputBuffer* raw_public_key,
    const CInputBuffer* raw_message_hash, const CInputBuffer* raw_signature);

/// C interface for 'wedpr_secp256k1_recover_public_key'.
int8_t wedpr_secp256k1_recover_public_key(const CInputBuffer* raw_message_hash,
    const CInputBuffer* raw_signature, COutputBuffer* output_public_key);

/// C interface for 'wedpr_sm2_gen_key_pair'.
int8_t wedpr_sm2_gen_key_pair(COutputBuffer* output_public_key, COutputBuffer* output_private_key);

/// C interface for 'wedpr_sm2_derive_public_key'.
int8_t wedpr_sm2_derive_public_key(
    const CInputBuffer* raw_private_key, COutputBuffer* output_public_key);

/// C interface for 'wedpr_sm2_sign'.
int8_t wedpr_sm2_sign(const CInputBuffer* raw_private_key, const CInputBuffer* raw_message_hash,
    COutputBuffer* output_signature);

/// C interface for 'wedpr_sm2_sign_fast'.
int8_t wedpr_sm2_sign_fast(const CInputBuffer* raw_private_key, const CInputBuffer* raw_public_key,
    const CInputBuffer* raw_message_hash, COutputBuffer* output_signature);

/// C interface for 'wedpr_sm2_verify'.
int8_t wedpr_sm2_verify(const CInputBuffer* raw_public_key, const CInputBuffer* raw_message_hash,
    const CInputBuffer* raw_signature);

/// C interface for 'wedpr_ed25519_gen_key_pair'.
int8_t wedpr_ed25519_gen_key_pair(
    COutputBuffer* output_public_key, COutputBuffer* output_private_key);

/// C interface for 'wedpr_ed25519_derive_public_key'.
int8_t wedpr_ed25519_derive_public_key(
    const CInputBuffer* raw_private_key, COutputBuffer* output_public_key);

/// C interface for 'wedpr_ed25519_sign'.
int8_t wedpr_ed25519_sign(const CInputBuffer* raw_private_key, const CInputBuffer* raw_message_hash,
    COutputBuffer* output_signature);

/// C interface for 'wedpr_ed25519_verify'.
int8_t wedpr_ed25519_verify(const CInputBuffer* raw_public_key,
    const CInputBuffer* raw_message_hash, const CInputBuffer* raw_signature);

/// C interface for 'wedpr_curve25519_vrf_derive_public_key'.
int8_t wedpr_curve25519_vrf_derive_public_key(
    const CInputBuffer* raw_private_key, COutputBuffer* output_public_key);

/// C interface for 'wedpr_curve25519_vrf_prove_utf8'.
int8_t wedpr_curve25519_vrf_prove_utf8(const CInputBuffer* raw_private_key,
    const CInputBuffer* raw_utf8_message, COutputBuffer* output_proof);

/// C interface for 'wedpr_curve25519_vrf_prove_fast_utf8'.
int8_t wedpr_curve25519_vrf_prove_fast_utf8(const CInputBuffer* raw_private_key,
    const CInputBuffer* raw_public_key, const CInputBuffer* raw_utf8_message,
    COutputBuffer* output_proof);

/// C interface for 'wedpr_curve25519_vrf_verify_utf8'.
int8_t wedpr_curve25519_vrf_verify_utf8(const CInputBuffer* raw_public_key,
    const CInputBuffer* raw_utf8_message, const CInputBuffer* raw_proof);

/// C interface for 'wedpr_curve25519_vrf_proof_to_hash'.
int8_t wedpr_curve25519_vrf_proof_to_hash(
    const CInputBuffer* raw_proof, COutputBuffer* output_hash);

/// C interface for 'wedpr_curve25519_vrf_is_valid_public_key'.
int8_t wedpr_curve25519_vrf_is_valid_public_key(const CInputBuffer* raw_public_key);

/// C interface for 'wedpr_secp256k1_vrf_derive_public_key'.
int8_t wedpr_secp256k1_vrf_derive_public_key(
    const CInputBuffer* raw_private_key, COutputBuffer* output_public_key);

/// C interface for 'wedpr_secp256k1_vrf_prove_utf8'.
// Legacy secp256k1 VRF proof operations are disabled and return -1. Never use
// output buffers after failure. Key derivation/validation remain available.
int8_t wedpr_secp256k1_vrf_prove_utf8(const CInputBuffer* raw_private_key,
    const CInputBuffer* raw_utf8_message, COutputBuffer* output_proof);

/// C interface for 'wedpr_secp256k1_vrf_prove_fast_utf8'.
int8_t wedpr_secp256k1_vrf_prove_fast_utf8(const CInputBuffer* raw_private_key,
    const CInputBuffer* raw_public_key, const CInputBuffer* raw_utf8_message,
    COutputBuffer* output_proof);

/// C interface for 'wedpr_secp256k1_vrf_verify_utf8'.
int8_t wedpr_secp256k1_vrf_verify_utf8(const CInputBuffer* raw_public_key,
    const CInputBuffer* raw_utf8_message, const CInputBuffer* raw_proof);

/// C interface for 'wedpr_secp256k1_vrf_proof_to_hash'.
int8_t wedpr_secp256k1_vrf_proof_to_hash(
    const CInputBuffer* raw_proof, COutputBuffer* output_hash);

/// C interface for 'wedpr_secp256k1_vrf_is_valid_public_key'.
int8_t wedpr_secp256k1_vrf_is_valid_public_key(const CInputBuffer* raw_public_key);


}  // extern "C"

#endif
