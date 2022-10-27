// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of FFI of equality test wrapper functions, targeting
//! Java-compatible architectures (including Android), with fast binary
//! interfaces.

#![cfg(not(tarpaulin_include))]

extern crate jni;
#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;
#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_l_macros;

use wedpr_bls12_381;

use jni::{
    objects::{JClass, JObject, JValue},
    sys::jobject,
    JNIEnv,
};

use jni::sys::jbyteArray;
use wedpr_ffi_common::utils::{
    java_bytes_to_jbyte_array, java_jbytes_to_bytes, java_new_jobject,
    java_set_error_field_and_extract_jobject,
};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.crypto'.

#[allow(dead_code)]
// Result class name is 'com.webank.wedpr.crypto.EqualityResult'.
const RESULT_EQUALITY_CLASS_NAME: &str =
    "com/webank/wedpr/crypto/EqualityResult";

#[allow(dead_code)]
fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_EQUALITY_CLASS_NAME)
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->encryptMessage'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_encryptMessage(
    _env: JNIEnv,
    _class: JClass,
    message_jbyte_array: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let message =
        java_safe_jbytes_to_bytes!(_env, result_jobject, message_jbyte_array);

    let result = wedpr_bls12_381::encrypt_message(&message);

    java_safe_set_byte_array_field!(
        _env,
        result_jobject,
        &result.to_bytes(),
        "blcCipher"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->equalityTest'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_equalityTest(
    _env: JNIEnv,
    _class: JClass,
    cipher1_jbyte_array: jbyteArray,
    cipher2_jbyte_array: jbyteArray,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let cipher1_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, cipher1_jbyte_array);
    let cipher2_bytes =
        java_safe_jbytes_to_bytes!(_env, result_jobject, cipher2_jbyte_array);

    let cipher1_struct =
        match wedpr_bls12_381::WedprBls128Cipher::from_bytes(&cipher1_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "WedprBls128Cipher recover failed, cipher1_bytes={:?}",
                        &cipher1_bytes
                    ),
                )
            },
        };
    let cipher2_struct =
        match wedpr_bls12_381::WedprBls128Cipher::from_bytes(&cipher2_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "WedprBls128Cipher recover failed, cipher2_bytes={:?}",
                        &cipher2_bytes
                    ),
                )
            },
        };

    let result =
        wedpr_bls12_381::equality_test(&cipher1_struct, &cipher2_struct);

    java_safe_set_boolean_field!(_env, result_jobject, result, "booleanResult");
    result_jobject.into_inner()
}
