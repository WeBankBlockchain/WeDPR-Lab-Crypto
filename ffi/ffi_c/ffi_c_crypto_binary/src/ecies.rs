// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! ECIES function wrappers.

#![cfg(not(tarpaulin_include))]
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
    raw_public_key: *const CInputBuffer,
    raw_plaintext: *const CInputBuffer,
    output_ciphertext: *mut COutputBuffer,
) -> i8 {
    let raw_public_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_public_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_public_key = &raw_public_key;
    let raw_plaintext =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_plaintext) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_plaintext = &raw_plaintext;
    let output_ciphertext =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_ciphertext)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    let public_key = match c_read_raw_pointer(raw_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let plaintext = match c_read_raw_pointer(&raw_plaintext) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = ECIES_SECP256K1.encrypt(&public_key, &plaintext);

    let encrypt_data = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&encrypt_data, output_ciphertext).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_ecies_decrypt'.
pub unsafe extern "C" fn wedpr_secp256k1_ecies_decrypt(
    raw_private_key: *const CInputBuffer,
    raw_ciphertext: *const CInputBuffer,
    output_plaintext: *mut COutputBuffer,
) -> i8 {
    let raw_private_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_private_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_private_key = &raw_private_key;
    let raw_ciphertext =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_ciphertext) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_ciphertext = &raw_ciphertext;
    let output_plaintext =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_plaintext)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    let private_key = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let ciphertext = match c_read_raw_pointer(raw_ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = ECIES_SECP256K1.decrypt(&private_key, &ciphertext);

    let plaintext = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&plaintext, output_plaintext).is_err() {
        return FAILURE;
    }
    SUCCESS
}
