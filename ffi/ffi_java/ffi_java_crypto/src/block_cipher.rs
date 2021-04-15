// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

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
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, java_jstring_to_bytes,
    java_set_error_field_and_extract_jobject,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, java_jstring_to_bytes,
    java_set_error_field_and_extract_jobject,
};

// AES-256 implementation.

#[cfg(feature = "wedpr_f_crypto_block_cipher_aes")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->aes256Encrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_aes256Encrypt(
    _env: JNIEnv,
    _class: JClass,
    encoded_message_jstring: JString,
    encoded_key_jstring: JString,
    encoded_iv_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let message_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jstring
    );
    let key_bytes =
        java_safe_jstring_to_bytes!(_env, result_jobject, encoded_key_jstring);
    let iv_bytes =
        java_safe_jstring_to_bytes!(_env, result_jobject, encoded_iv_jstring);

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
                    "AES encrypt failed, message_bytes={}",
                    bytes_to_string(&message_bytes)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&encrypted_data),
        "encryptedData"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_crypto_block_cipher_aes")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->aes256Decrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_aes256Decrypt(
    _env: JNIEnv,
    _class: JClass,
    encoded_encrypted_data_jstring: JString,
    encoded_key_jstring: JString,
    encoded_iv_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encrypted_data = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_encrypted_data_jstring
    );
    let key =
        java_safe_jstring_to_bytes!(_env, result_jobject, encoded_key_jstring);
    let iv =
        java_safe_jstring_to_bytes!(_env, result_jobject, encoded_iv_jstring);

    let decrypted_data =
        match BLOCK_CIPHER_AES256.decrypt(&encrypted_data, &key, &iv) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "AES decrypt failed, ciphertext={}",
                        bytes_to_string(&encrypted_data)
                    ),
                )
            },
        };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&decrypted_data),
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
    encoded_message_jstring: JString,
    encoded_key_jstring: JString,
    encoded_iv_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let message_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jstring
    );
    let key_bytes =
        java_safe_jstring_to_bytes!(_env, result_jobject, encoded_key_jstring);
    let iv_bytes =
        java_safe_jstring_to_bytes!(_env, result_jobject, encoded_iv_jstring);

    let encrypted_data =
        match BLOCK_CIPHER_SM4.encrypt(&message_bytes, &key_bytes, &iv_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "AES encrypt failed, message_bytes={}",
                        bytes_to_string(&message_bytes)
                    ),
                )
            },
        };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&encrypted_data),
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
    encoded_encrypted_data_jstring: JString,
    encoded_key_jstring: JString,
    encoded_iv_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encrypted_data = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_encrypted_data_jstring
    );
    let key =
        java_safe_jstring_to_bytes!(_env, result_jobject, encoded_key_jstring);
    let iv =
        java_safe_jstring_to_bytes!(_env, result_jobject, encoded_iv_jstring);

    let decrypted_data =
        match BLOCK_CIPHER_SM4.decrypt(&encrypted_data, &key, &iv) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "SM4 decrypt failed, ciphertext={}",
                        bytes_to_string(&encrypted_data)
                    ),
                )
            },
        };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&decrypted_data),
        "decryptedData"
    );
    result_jobject.into_inner()
}
