// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Hash function wrappers.

#![cfg(all(feature = "wedpr_f_hash_keccak256", feature = "wedpr_f_hash_sm3"))]

use wedpr_l_utils::traits::Hash;

#[cfg(feature = "wedpr_f_hash_keccak256")]
use crate::config::HASH_KECCAK256;

use crate::{config, get_result_jobject};

#[cfg(feature = "wedpr_f_hash_sm3")]
use config::HASH_SM3;

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

// Keccak256 implementation.

#[cfg(feature = "wedpr_f_hash_keccak256")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->keccak256Hash'.
// TODO: Add keccak256HashUtf8 to allow non-encoded UTF8 input.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_keccak256Hash(
    _env: JNIEnv,
    _class: JClass,
    encoded_message_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encoded_message_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jstring
    );

    let hash = HASH_KECCAK256.hash(&encoded_message_bytes);

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&hash),
        "hash"
    );
    result_jobject.into_inner()
}

// SM3 implementation.

#[cfg(feature = "wedpr_f_hash_sm3")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sm3Hash'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm3Hash(
    _env: JNIEnv,
    _class: JClass,
    encoded_message_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encoded_message_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jstring
    );

    let hash = HASH_SM3.hash(&encoded_message_bytes);

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&hash),
        "hash"
    );
    result_jobject.into_inner()
}
