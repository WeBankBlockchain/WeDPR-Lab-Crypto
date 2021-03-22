// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! ECIES function wrappers.

#![cfg(feature = "wedpr_f_ecies_secp256k1")]

use wedpr_l_utils::traits::Ecies;

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
use crate::config::ECIES_SECP256K1;

use wedpr_ffi_common::utils::{
    c_pointer_to_rust_bytes, set_c_pointer, CPointInput, CPointOutput, FAILURE,
    SUCCESS,
};

// Secp256k1 implementation.

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_ecies_encrypt'.
// TODO: Add wedpr_secp256k1_ecies_encrypt_utf8 to allow non-encoded UTF8 input.
pub unsafe extern "C" fn wedpr_secp256k1_ecies_encrypt(
    public_key_input: &CPointInput,
    plaintext_input: &CPointInput,
    encrypt_data_result: &mut CPointOutput,
) -> i8 {
    let public_key = c_pointer_to_rust_bytes(public_key_input);
    let plaintext = c_pointer_to_rust_bytes(&plaintext_input);
    let result = ECIES_SECP256K1.encrypt(&public_key, &plaintext);
    std::mem::forget(public_key);
    std::mem::forget(plaintext);
    let encrypt_data = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&encrypt_data, encrypt_data_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_ecies_decrypt'.
pub unsafe extern "C" fn wedpr_secp256k1_ecies_decrypt(
    private_key_input: &CPointInput,
    encrypt_data_input: &CPointInput,
    plaintext_result: &mut CPointOutput,
) -> i8 {
    let private_key = c_pointer_to_rust_bytes(private_key_input);
    let ciphertext = c_pointer_to_rust_bytes(encrypt_data_input);

    let result = ECIES_SECP256K1.decrypt(&private_key, &ciphertext);
    std::mem::forget(private_key);
    std::mem::forget(ciphertext);
    let plaintext = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&plaintext, plaintext_result);
    SUCCESS
}
