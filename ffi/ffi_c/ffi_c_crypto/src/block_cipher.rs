// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Block Cipher function wrappers.

use wedpr_l_utils::traits::BlockCipher;

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
use crate::config::AES;

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
use crate::config::SM4;

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

// AES256 implementation.

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
#[no_mangle]
/// C interface for 'wedpr_aes256_encrypt'.
pub extern "C" fn wedpr_aes256_encrypt(
    encoded_message: *mut c_char,
    encoded_key: *mut c_char,
    encoded_iv: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let message = c_safe_c_char_pointer_to_bytes!(encoded_message);
        let key = c_safe_c_char_pointer_to_bytes!(encoded_key);
        let iv = c_safe_c_char_pointer_to_bytes!(encoded_iv);

        let encrypt_data = match AES.encrypt(&message, &key, &iv) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "AES encrypt failed, encoded_message={}, public_key={}",
                    bytes_to_string(&message),
                    bytes_to_string(&key)
                );
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&encrypt_data)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
#[no_mangle]
/// C interface for 'wedpr_aes256_decrypt'.
pub extern "C" fn wedpr_aes256_decrypt(
    encoded_encrypt_data: *mut c_char,
    encoded_key: *mut c_char,
    encoded_iv: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let encrypt_data =
            c_safe_c_char_pointer_to_bytes!(encoded_encrypt_data);
        let key = c_safe_c_char_pointer_to_bytes!(encoded_key);
        let iv = c_safe_c_char_pointer_to_bytes!(encoded_iv);

        let decrypted_data = match AES.decrypt(&encrypt_data, &key, &iv) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "AES decrypt failed, ciphertext={}",
                    bytes_to_string(&encrypt_data)
                );
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&decrypted_data)
    });
    c_safe_return!(result)
}

// SM4 implementation.

#[cfg(feature = "wedpr_l_crypto_block_cipher_sm4")]
#[no_mangle]
/// C interface for 'wedpr_sm4_encrypt'.
pub extern "C" fn wedpr_sm4_encrypt(
    encoded_message: *mut c_char,
    encoded_key: *mut c_char,
    encoded_iv: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let message = c_safe_c_char_pointer_to_bytes!(encoded_message);
        let key = c_safe_c_char_pointer_to_bytes!(encoded_key);
        let iv = c_safe_c_char_pointer_to_bytes!(encoded_iv);

        let encrypt_data = match SM4.encrypt(&message, &key, &iv) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "AES encrypt failed, encoded_message={}, public_key={}",
                    bytes_to_string(&message),
                    bytes_to_string(&key)
                );
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&encrypt_data)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_l_crypto_block_cipher_sm4")]
#[no_mangle]
/// C interface for 'wedpr_sm4_decrypt'.
pub extern "C" fn wedpr_sm4_decrypt(
    encoded_encrypt_data: *mut c_char,
    encoded_key: *mut c_char,
    encoded_iv: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let encrypt_data =
            c_safe_c_char_pointer_to_bytes!(encoded_encrypt_data);
        let key = c_safe_c_char_pointer_to_bytes!(encoded_key);
        let iv = c_safe_c_char_pointer_to_bytes!(encoded_iv);

        let decrypted_data = match SM4.decrypt(&encrypt_data, &key, &iv) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "SM4 decrypt failed, ciphertext={}",
                    bytes_to_string(&encrypt_data)
                );
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&decrypted_data)
    });
    c_safe_return!(result)
}
