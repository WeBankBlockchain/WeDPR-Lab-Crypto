// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Block cipher function wrappers.

#![cfg(not(tarpaulin_include))]
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

#[cfg(all(
    test,
    feature = "wedpr_f_crypto_block_cipher_aes",
    feature = "wedpr_f_crypto_block_cipher_sm4"
))]
mod security_tests {
    use super::*;

    // Exercise the exact cipher instances used by JNI. This also prevents a
    // manifest change from silently restoring the vulnerable registry crates.
    #[test]
    fn jni_cipher_instances_reject_iv_tampering() {
        fn check<C: BlockCipher>(cipher: &C, key_size: usize) {
            let message = b"amount=00000100".to_vec();
            let key = vec![42u8; key_size];
            let iv = vec![17u8; 16];
            let encoded = cipher.encrypt(&message, &key, &iv).unwrap();
            assert_eq!(encoded.len(), 56);
            assert_eq!(cipher.decrypt(&encoded, &key, &iv).unwrap(), message);
            let mut changed = iv;
            changed[7] ^= b'0' ^ b'9';
            assert!(cipher.decrypt(&encoded, &key, &changed).is_err());
        }
        check(&*BLOCK_CIPHER_AES256, 32);
        check(&*BLOCK_CIPHER_SM4, 16);
    }
}

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
    if result_jobject.into_inner().is_null() {
        return std::ptr::null_mut();
    }

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
                "AES encrypt failed",
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
    if result_jobject.into_inner().is_null() {
        return std::ptr::null_mut();
    }

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
                    "AES decrypt failed",
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
    if result_jobject.into_inner().is_null() {
        return std::ptr::null_mut();
    }

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
                    "AES encrypt failed",
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
    if result_jobject.into_inner().is_null() {
        return std::ptr::null_mut();
    }

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
                    "SM4 decrypt failed",
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
