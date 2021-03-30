// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Block Cipher function wrappers.

#![cfg(feature = "wedpr_f_ecies_secp256k1")]

use wedpr_l_utils::traits::BlockCipher;

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
use crate::config::BLOCK_CIPHER_AES256;

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
use crate::config::BLOCK_CIPHER_SM4;

use wedpr_ffi_common::utils::{
    c_read_raw_pointer, c_write_raw_pointer, CInputBuffer, COutputBuffer,
    FAILURE, SUCCESS,
};

// AES256 implementation.

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
#[no_mangle]
/// C interface for 'wedpr_aes256_encrypt'.
pub unsafe extern "C" fn wedpr_aes256_encrypt(
    raw_plaintext: &CInputBuffer,
    raw_key: &CInputBuffer,
    raw_iv: &CInputBuffer,
    output_ciphertext: &mut COutputBuffer,
) -> i8 {
    let plaintext = c_read_raw_pointer(raw_plaintext);
    let key = c_read_raw_pointer(&raw_key);
    let iv = c_read_raw_pointer(&raw_iv);

    let result = BLOCK_CIPHER_AES256.encrypt(&plaintext, &key, &iv);
    std::mem::forget(plaintext);
    std::mem::forget(key);
    std::mem::forget(iv);
    let ciphertext = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&ciphertext, output_ciphertext);
    SUCCESS
}

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
#[no_mangle]
/// C interface for 'wedpr_aes256_decrypt'.
pub unsafe extern "C" fn wedpr_aes256_decrypt(
    raw_ciphertext: &CInputBuffer,
    raw_key: &CInputBuffer,
    raw_iv: &CInputBuffer,
    output_plaintext: &mut COutputBuffer,
) -> i8 {
    let ciphertext = c_read_raw_pointer(raw_ciphertext);
    let key = c_read_raw_pointer(&raw_key);
    let iv = c_read_raw_pointer(&raw_iv);

    let result = BLOCK_CIPHER_AES256.decrypt(&ciphertext, &key, &iv);
    std::mem::forget(ciphertext);
    std::mem::forget(key);
    std::mem::forget(iv);
    let plaintext = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&plaintext, output_plaintext);
    SUCCESS
}

// SM4 implementation.

#[cfg(feature = "wedpr_l_crypto_block_cipher_sm4")]
#[no_mangle]
/// C interface for 'wedpr_sm4_encrypt'.
pub unsafe extern "C" fn wedpr_sm4_encrypt(
    raw_plaintext: &CInputBuffer,
    raw_key: &CInputBuffer,
    raw_iv: &CInputBuffer,
    output_ciphertext: &mut COutputBuffer,
) -> i8 {
    let plaintext = c_read_raw_pointer(raw_plaintext);
    let key = c_read_raw_pointer(&raw_key);
    let iv = c_read_raw_pointer(&raw_iv);

    let result = BLOCK_CIPHER_SM4.encrypt(&plaintext, &key, &iv);
    std::mem::forget(plaintext);
    std::mem::forget(key);
    std::mem::forget(iv);
    let ciphertext = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&ciphertext, output_ciphertext);
    SUCCESS
}

#[cfg(feature = "wedpr_l_crypto_block_cipher_sm4")]
#[no_mangle]
/// C interface for 'wedpr_sm4_decrypt'.
pub unsafe extern "C" fn wedpr_sm4_decrypt(
    raw_ciphertext: &CInputBuffer,
    raw_key: &CInputBuffer,
    raw_iv: &CInputBuffer,
    output_plaintext: &mut COutputBuffer,
) -> i8 {
    let ciphertext = c_read_raw_pointer(raw_ciphertext);
    let key = c_read_raw_pointer(&raw_key);
    let iv = c_read_raw_pointer(&raw_iv);

    let result = BLOCK_CIPHER_SM4.decrypt(&ciphertext, &key, &iv);
    std::mem::forget(ciphertext);
    std::mem::forget(key);
    std::mem::forget(iv);
    let plaintext = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&plaintext, output_plaintext);
    SUCCESS
}
