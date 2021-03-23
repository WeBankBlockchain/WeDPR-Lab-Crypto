// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Block Cipher function wrappers.

#![cfg(feature = "wedpr_f_ecies_secp256k1")]

use wedpr_l_utils::traits::BlockCipher;

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
use crate::config::AES;

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
use crate::config::SM4;

use wedpr_ffi_common::utils::{
    c_pointer_to_rust_bytes, set_c_pointer, CPointInput, CPointOutput, FAILURE,
    SUCCESS,
};

// AES256 implementation.

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
#[no_mangle]
/// C interface for 'wedpr_aes256_encrypt'.
pub unsafe extern "C" fn wedpr_aes256_encrypt(
    message_input: &CPointInput,
    key_input: &CPointInput,
    iv_input: &CPointInput,
    encrypt_data_result: &mut CPointOutput,
) -> i8 {
    let message = c_pointer_to_rust_bytes(message_input);
    let key = c_pointer_to_rust_bytes(&key_input);
    let iv = c_pointer_to_rust_bytes(&iv_input);
    let result = AES.encrypt(&message, &key, &iv);
    std::mem::forget(message);
    std::mem::forget(key);
    std::mem::forget(iv);
    let encrypt_data = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&encrypt_data, encrypt_data_result);
    SUCCESS
}

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
#[no_mangle]
/// C interface for 'wedpr_aes256_decrypt'.
pub unsafe extern "C" fn wedpr_aes256_decrypt(
    encrypt_data_input: &CPointInput,
    key_input: &CPointInput,
    iv_input: &CPointInput,
    plaintext_result: &mut CPointOutput,
) -> i8 {
    let encrypt_data = c_pointer_to_rust_bytes(encrypt_data_input);
    let key = c_pointer_to_rust_bytes(&key_input);
    let iv = c_pointer_to_rust_bytes(&iv_input);

    let result = AES.decrypt(&encrypt_data, &key, &iv);
    std::mem::forget(encrypt_data);
    std::mem::forget(key);
    std::mem::forget(iv);
    let plaintext = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&plaintext, plaintext_result);
    SUCCESS
}

// SM4 implementation.

#[cfg(feature = "wedpr_l_crypto_block_cipher_sm4")]
#[no_mangle]
/// C interface for 'wedpr_sm4_encrypt'.
pub unsafe extern "C" fn wedpr_sm4_encrypt(
    message_input: &CPointInput,
    key_input: &CPointInput,
    iv_input: &CPointInput,
    encrypt_data_result: &mut CPointOutput,
) -> i8 {
    let message = c_pointer_to_rust_bytes(message_input);
    let key = c_pointer_to_rust_bytes(&key_input);
    let iv = c_pointer_to_rust_bytes(&iv_input);
    let result = SM4.encrypt(&message, &key, &iv);
    std::mem::forget(message);
    std::mem::forget(key);
    std::mem::forget(iv);
    let encrypt_data = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&encrypt_data, encrypt_data_result);
    SUCCESS
}

#[cfg(feature = "wedpr_l_crypto_block_cipher_sm4")]
#[no_mangle]
/// C interface for 'wedpr_sm4_decrypt'.
pub unsafe extern "C" fn wedpr_sm4_decrypt(
    encrypt_data_input: &CPointInput,
    key_input: &CPointInput,
    iv_input: &CPointInput,
    plaintext_result: &mut CPointOutput,
) -> i8 {
    let encrypt_data = c_pointer_to_rust_bytes(encrypt_data_input);
    let key = c_pointer_to_rust_bytes(&key_input);
    let iv = c_pointer_to_rust_bytes(&iv_input);

    let result = SM4.decrypt(&encrypt_data, &key, &iv);
    std::mem::forget(encrypt_data);
    std::mem::forget(key);
    std::mem::forget(iv);
    let plaintext = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&plaintext, plaintext_result);
    SUCCESS
}
