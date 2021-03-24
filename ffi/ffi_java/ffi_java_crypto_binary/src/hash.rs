// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Hash function wrappers.

#![cfg(all(feature = "wedpr_f_hash_keccak256", feature = "wedpr_f_hash_sm3"))]

use wedpr_l_utils::traits::Hash;

#[cfg(feature = "wedpr_f_hash_keccak256")]
use crate::config::HASH_KECCAK256;

use crate::{config, get_result_jobject};

#[cfg(feature = "wedpr_f_hash_sm3")]
use config::HASH_SM3;

#[cfg(feature = "wedpr_f_hash_sha3")]
use config::HASH_SHA3;

#[cfg(feature = "wedpr_f_hash_ripemd160")]
use config::HASH_RIPEMD160;

#[cfg(feature = "wedpr_f_hash_blake2b")]
use config::HASH_BLAKE2B;

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

// Keccak256 implementation.

#[cfg(feature = "wedpr_f_hash_keccak256")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->keccak256Hash'.
// TODO: Add keccak256HashUtf8 to allow non-encoded UTF8 input.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_keccak256Hash(
    _env: JNIEnv,
    _class: JClass,
    encoded_message_jbytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);
    let encoded_message_bytes = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jbytes
    );

    let hash = HASH_KECCAK256.hash(&encoded_message_bytes);

    java_safe_set_bytes_binary_field!(_env, result_jobject, &hash, "hash");
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
    encoded_message_jbytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encoded_message_bytes = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jbytes
    );

    let hash = HASH_SM3.hash(&encoded_message_bytes);

    java_safe_set_bytes_binary_field!(_env, result_jobject, &hash, "hash");
    result_jobject.into_inner()
}

// RIPEMD160 implementation.

#[cfg(feature = "wedpr_f_hash_ripemd160")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->ripemd160Hash'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_ripemd160Hash(
    _env: JNIEnv,
    _class: JClass,
    encoded_message_jbytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encoded_message_bytes = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jbytes
    );

    let hash = HASH_RIPEMD160.hash(&encoded_message_bytes);

    java_safe_set_bytes_binary_field!(_env, result_jobject, &hash, "hash");
    result_jobject.into_inner()
}

// SHA3 implementation.

#[cfg(feature = "wedpr_f_hash_sha3")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sha3Hash'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sha3Hash(
    _env: JNIEnv,
    _class: JClass,
    encoded_message_jbytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encoded_message_bytes = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jbytes
    );

    let hash = HASH_SHA3.hash(&encoded_message_bytes);

    java_safe_set_bytes_binary_field!(_env, result_jobject, &hash, "hash");
    result_jobject.into_inner()
}

// BLAKE2B implementation.

#[cfg(feature = "wedpr_f_hash_blake2b")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->blake2bHash'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_blake2bHash(
    _env: JNIEnv,
    _class: JClass,
    encoded_message_jbytes: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let encoded_message_bytes = java_safe_jbytes_to_bytes!(
        _env,
        result_jobject,
        encoded_message_jbytes
    );

    let hash = HASH_BLAKE2B.hash(&encoded_message_bytes);

    java_safe_set_bytes_binary_field!(_env, result_jobject, &hash, "hash");
    result_jobject.into_inner()
}