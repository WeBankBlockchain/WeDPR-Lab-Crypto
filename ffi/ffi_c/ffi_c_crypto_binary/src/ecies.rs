// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! ECIES function wrappers.

#![cfg(feature = "wedpr_f_ecies_secp256k1")]

use wedpr_l_utils::traits::Ecies;

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
use crate::config::ECIES_SECP256K1;

use wedpr_ffi_common::utils::{
    c_read_raw_pointer, c_write_raw_pointer, CInputBuffer, COutputBuffer,
    FAILURE, SUCCESS,
};

// Secp256k1 implementation.

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_ecies_encrypt'.
// TODO: Add wedpr_secp256k1_ecies_encrypt_utf8 to allow non-encoded UTF8 input.
pub unsafe extern "C" fn wedpr_secp256k1_ecies_encrypt(
    raw_public_key: &CInputBuffer,
    raw_plaintext: &CInputBuffer,
    output_ciphertext: &mut COutputBuffer,
) -> i8 {
    let public_key = c_read_raw_pointer(raw_public_key);
    let plaintext = c_read_raw_pointer(&raw_plaintext);

    let result = ECIES_SECP256K1.encrypt(&public_key, &plaintext);
    std::mem::forget(public_key);
    std::mem::forget(plaintext);
    let encrypt_data = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&encrypt_data, output_ciphertext);
    SUCCESS
}

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_ecies_decrypt'.
pub unsafe extern "C" fn wedpr_secp256k1_ecies_decrypt(
    raw_private_key: &CInputBuffer,
    raw_ciphertext: &CInputBuffer,
    output_plaintext: &mut COutputBuffer,
) -> i8 {
    let private_key = c_read_raw_pointer(raw_private_key);
    let ciphertext = c_read_raw_pointer(raw_ciphertext);

    let result = ECIES_SECP256K1.decrypt(&private_key, &ciphertext);
    std::mem::forget(private_key);
    std::mem::forget(ciphertext);
    let plaintext = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&plaintext, output_plaintext);
    SUCCESS
}
