// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! ECIES function wrappers.

#![cfg(feature = "wedpr_f_ecies_secp256k1")]

extern crate jni;

use wedpr_l_utils::traits::Ecies;

use crate::{config, get_result_jobject};

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
use config::ECIES_SECP256K1;

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

// Secp256k1 implementation.

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1EciesEncrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1EciesEncrypt(
    _env: JNIEnv,
    _class: JClass,
    public_key_jbyte_array: jbyteArray,
    message_hash_jbyte_array: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let public_key = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        public_key_jbyte_array
    );
    let encoded_message = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        message_hash_jbyte_array
    );

    let encrypted_data =
        match ECIES_SECP256K1.encrypt(&public_key, &encoded_message) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "ECIES encrypt failed, encoded_message={:?}, \
                         public_key={:?}",
                        &encoded_message, &public_key
                    ),
                )
            },
        };

    java_safe_set_bytes_binary_field!(
        _env,
        result_jobject,
        &encrypted_data,
        "encryptedData"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1EciesDecrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1EciesDecrypt(
    _env: JNIEnv,
    _class: JClass,
    private_key_jbyte_array: jbyteArray,
    ciphertext_jbyte_array: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        private_key_jbyte_array
    );
    let ciphertext = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        ciphertext_jbyte_array
    );

    let decrypted_data = match ECIES_SECP256K1
        .decrypt(&private_key, &ciphertext)
    {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!("ECIES decrypt failed, ciphertext={:?}", &ciphertext),
            )
        },
    };

    java_safe_set_bytes_binary_field!(
        _env,
        result_jobject,
        &decrypted_data,
        "decryptedData"
    );
    result_jobject.into_inner()
}
