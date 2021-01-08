// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! ECIES function wrappers.

#![cfg(feature = "wedpr_f_ecies_secp256k1")]

use wedpr_l_utils::traits::Ecies;

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
use crate::config::ECIES_SECP256K1;

use libc::c_char;
use std::{ffi::CString, panic, ptr};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes,
};

// Secp256k1 implementation.

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_ecies_encrypt'.
// TODO: Add wedpr_secp256k1_ecies_encrypt_utf8 to allow non-encoded UTF8 input.
pub extern "C" fn wedpr_secp256k1_ecies_encrypt(
    encoded_public_key: *mut c_char,
    encoded_plaintext: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let public_key = c_safe_c_char_pointer_to_bytes!(encoded_public_key);
        let encoded_message =
            c_safe_c_char_pointer_to_bytes!(encoded_plaintext);

        let encrypt_data = match ECIES_SECP256K1
            .encrypt(&public_key, &encoded_message)
        {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "ECIES encrypt failed, encoded_message={}, public_key={}",
                    bytes_to_string(&encoded_message),
                    bytes_to_string(&public_key)
                );
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&encrypt_data)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_ecies_decrypt'.
pub extern "C" fn wedpr_secp256k1_ecies_decrypt(
    encoded_private_key: *mut c_char,
    encoded_ciphertext: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let ciphertext = c_safe_c_char_pointer_to_bytes!(encoded_ciphertext);

        let decrypted_data =
            match ECIES_SECP256K1.decrypt(&private_key, &ciphertext) {
                Ok(v) => v,
                Err(_) => {
                    wedpr_println!(
                        "ECIES decrypt failed, ciphertext={}",
                        bytes_to_string(&ciphertext)
                    );
                    return ptr::null_mut();
                },
            };
        c_safe_bytes_to_c_char_pointer!(&decrypted_data)
    });
    c_safe_return!(result)
}
