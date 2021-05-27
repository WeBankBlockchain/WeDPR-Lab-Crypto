// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#![cfg(not(tarpaulin_include))]

//! Block cipher function wrappers.

#![cfg(any(
    feature = "wedpr_f_crypto_block_cipher_aes",
    feature = "wedpr_f_crypto_block_cipher_sm4"
))]

use wedpr_l_utils::traits::BlockCipher;

use crate::get_result_jobject;

#[cfg(feature = "wedpr_f_crypto_block_cipher_aes")]
use crate::config::BLOCK_CIPHER_AES256;

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
use crate::config::BLOCK_CIPHER_SM4;

use jni::{
    objects::{JClass, JObject, JValue},
    sys::jobject,
    JNIEnv,
};

use jni::sys::jbyteArray;
use wedpr_ffi_common::utils::{
    java_bytes_to_jbyte_array, java_jbytes_to_bytes,
    java_set_error_field_and_extract_jobject,
};

// AES 256 implementation.

#[cfg(feature = "wedpr_f_crypto_block_cipher_aes")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->aes256Encrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_aes256Encrypt(
    _env: JNIEnv,
    _class: JClass,
    message_jbyte_array: jbyteArray,
    key_jbyte_array: jbyteArray,
    iv_jbyte_array: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let message_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, message_jbyte_array);
    let key_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, key_jbyte_array);
    let iv_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, iv_jbyte_array);

    let encrypted_data = match BLOCK_CIPHER_AES256.encrypt(
        &message_bytes,
        &key_bytes,
        &iv_bytes,
    ) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "AES encrypt failed, message_bytes={:?}",
                    &message_bytes
                ),
            )
        },
    };

    java_safe_set_byte_array_field!(
        _env,
        result_jobject,
        &encrypted_data,
        "encryptedData"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_l_crypto_block_cipher_aes")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->aes256Decrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_aes256Decrypt(
    _env: JNIEnv,
    _class: JClass,
    encrypted_data_jbyte_array: jbyteArray,
    key_jbyte_array: jbyteArray,
    iv_jbyte_array: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encrypted_data = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        encrypted_data_jbyte_array
    );
    let key = java_safe_jbytes_to_bytes!(_env, result_jobject, key_jbyte_array);
    let iv = java_safe_jbytes_to_bytes!(_env, result_jobject, iv_jbyte_array);

    let decrypted_data =
        match BLOCK_CIPHER_AES256.decrypt(&encrypted_data, &key, &iv) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "AES decrypt failed, ciphertext={:?}",
                        &encrypted_data
                    ),
                )
            },
        };

    java_safe_set_byte_array_field!(
        _env,
        result_jobject,
        &decrypted_data,
        "decryptedData"
    );
    result_jobject.into_inner()
}

// SM4 implementation.

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sm4Encrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm4Encrypt(
    _env: JNIEnv,
    _class: JClass,
    message_jbyte_array: jbyteArray,
    key_jbyte_array: jbyteArray,
    iv_jbyte_array: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let message_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, message_jbyte_array);
    let key_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, key_jbyte_array);
    let iv_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, iv_jbyte_array);

    let encrypted_data =
        match BLOCK_CIPHER_SM4.encrypt(&message_bytes, &key_bytes, &iv_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "sm4 encrypt failed, message_bytes={:?}",
                        &message_bytes
                    ),
                )
            },
        };

    java_safe_set_byte_array_field!(
        _env,
        result_jobject,
        &encrypted_data,
        "encryptedData"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sm4Decrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm4Decrypt(
    _env: JNIEnv,
    _class: JClass,
    encrypted_data_jbyte_array: jbyteArray,
    key_jbyte_array: jbyteArray,
    iv_jbyte_array: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encrypted_data = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        encrypted_data_jbyte_array
    );
    let key = java_safe_jbytes_to_bytes!(_env, result_jobject, key_jbyte_array);
    let iv = java_safe_jbytes_to_bytes!(_env, result_jobject, iv_jbyte_array);

    let decrypted_data =
        match BLOCK_CIPHER_SM4.decrypt(&encrypted_data, &key, &iv) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "AES decrypt failed, ciphertext={:?}",
                        &encrypted_data
                    ),
                )
            },
        };

    java_safe_set_byte_array_field!(
        _env,
        result_jobject,
        &decrypted_data,
        "decryptedData"
    );
    result_jobject.into_inner()
}
