// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! ECIES function wrappers.

#![cfg(feature = "wedpr_f_ecies_secp256k1")]

#[cfg(all(feature = "wedpr_f_base64", feature = "wedpr_f_hex"))]
compile_error!(
    "Feature wedpr_f_base64 and wedpr_f_hex can not be enabled at same time!"
);

#[cfg(all(not(feature = "wedpr_f_base64"), not(feature = "wedpr_f_hex")))]
compile_error!("Must use feature wedpr_f_base64 or wedpr_f_hex!");

extern crate jni;

use wedpr_l_utils::traits::Ecies;

use crate::{config, get_result_jobject};

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
use config::ECIES_SECP256K1;

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

// Secp256k1 implementation.

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1EciesEncrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1EciesEncrypt(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    message_hash_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let public_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, public_key_jstring);
    let encoded_message =
        java_safe_jstring_to_bytes!(_env, result_jobject, message_hash_jstring);

    let encrypted_data = match ECIES_SECP256K1
        .encrypt(&public_key, &encoded_message)
    {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "ECIES encrypt failed, encoded_message={}, public_key={}",
                    bytes_to_string(&encoded_message),
                    bytes_to_string(&public_key)
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

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1EciesDecrypt'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1EciesDecrypt(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    ciphertext_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);
    let ciphertext =
        java_safe_jstring_to_bytes!(_env, result_jobject, ciphertext_jstring);

    let decrypted_data =
        match ECIES_SECP256K1.decrypt(&private_key, &ciphertext) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "ECIES decrypt failed, ciphertext={}",
                        bytes_to_string(&ciphertext)
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
