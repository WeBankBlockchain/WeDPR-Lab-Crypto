// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#![cfg(not(tarpaulin_include))]

//! Library of FFI of wedpr_third_party_fisco_bcos_java_sdk wrapper functions,
//! targeting Java-compatible architectures (including Android), with fast
//! binary interfaces.

use crate::get_result_jobject;
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};
use wedpr_ffi_common::utils::{
    java_jstring_to_string, java_set_error_field_and_extract_jobject,
};
use wedpr_third_party_fisco_bcos_java_sdk;

// Curve25519 implementation.

#[no_mangle]
/// Java interface for
/// 'com.webank.fisco.bcos.wedpr.sdk.NativeInterface->curve25519VrfProveUtf8'.
pub extern "system" fn Java_com_webank_fisco_bcos_wedpr_sdk_NativeInterface_curve25519VrfProveUtf8(
    _env: JNIEnv,
    _class: JClass,
    encoded_private_key_jstring: JString,
    utf8_message_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key_str = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        encoded_private_key_jstring
    );
    let message_str = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        utf8_message_jstring
    );

    let proof =
        match wedpr_third_party_fisco_bcos_java_sdk::curve25519_vrf_prove(
            &private_key_str,
            &message_str,
        ) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "WedprCurve25519Vrf prove failed, private_key_str={}, \
                         input_bytes={}",
                        private_key_str, message_str
                    ),
                )
            },
        };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        &proof.encode(),
        "vrfProof"
    );
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.fisco.bcos.wedpr.sdk.NativeInterface->curve25519VrfVerifyUtf8'.
pub extern "system" fn Java_com_webank_fisco_bcos_wedpr_sdk_NativeInterface_curve25519VrfVerifyUtf8(
    _env: JNIEnv,
    _class: JClass,
    encoded_public_key_jstring: JString,
    utf8_message_jstring: JString,
    encoded_proof_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let public_key_str = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        encoded_public_key_jstring
    );
    let message_str = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        utf8_message_jstring
    );
    let proof_str = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        encoded_proof_jstring
    );
    let proof = match wedpr_third_party_fisco_bcos_java_sdk::vrf_proof::decode(
        &proof_str,
    ) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "WedprCurve25519Vrf decode failed, proof_str={}",
                    &proof_str,
                ),
            )
        },
    };

    let result = wedpr_third_party_fisco_bcos_java_sdk::curve25519_vrf_verify(
        &public_key_str,
        &message_str,
        &proof,
    );

    java_safe_set_boolean_field!(_env, result_jobject, result, "booleanResult");
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.fisco.bcos.wedpr.sdk.
/// NativeInterface->curve25519VrfDerivePublicKey'.
pub extern "system" fn Java_com_webank_fisco_bcos_wedpr_sdk_NativeInterface_curve25519VrfDerivePublicKey(
    _env: JNIEnv,
    _class: JClass,
    encoded_private_key_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key_str = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        encoded_private_key_jstring
    );

    let public_key =
        wedpr_third_party_fisco_bcos_java_sdk::curve25519_vrf_gen_pubkey(
            &private_key_str,
        );

    java_safe_set_string_field!(_env, result_jobject, public_key, "publicKey");
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.fisco.bcos.wedpr.sdk.NativeInterface->curve25519VrfProofToHash'.
pub extern "system" fn Java_com_webank_fisco_bcos_wedpr_sdk_NativeInterface_curve25519VrfProofToHash(
    _env: JNIEnv,
    _class: JClass,
    encoded_proof_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let proof_str = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        encoded_proof_jstring
    );
    let proof = match wedpr_third_party_fisco_bcos_java_sdk::vrf_proof::decode(
        &proof_str,
    ) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "WedprCurve25519Vrf decode failed, proof_str={}",
                    &proof_str,
                ),
            )
        },
    };

    let hash_str = match wedpr_third_party_fisco_bcos_java_sdk::curve25519_vrf_proof_to_hash(&proof) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "WedprCurve25519Vrf proof_to_bytes failed, proof_str={}",
                    &proof_str,
                ),
            )
        },
    };

    java_safe_set_string_field!(_env, result_jobject, hash_str, "hash");
    result_jobject.into_inner()
}

#[no_mangle]
/// Java interface for
/// 'com.webank.fisco.bcos.wedpr.sdk.
/// NativeInterface->curve25519VrfIsValidPublicKey'.
pub extern "system" fn Java_com_webank_fisco_bcos_wedpr_sdk_NativeInterface_curve25519VrfIsValidPublicKey(
    _env: JNIEnv,
    _class: JClass,
    encoded_public_key_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let public_key_str = java_safe_jstring_to_string!(
        _env,
        result_jobject,
        encoded_public_key_jstring
    );

    let result =
        wedpr_third_party_fisco_bcos_java_sdk::curve25519_vrf_is_valid_pubkey(
            &public_key_str,
        );

    java_safe_set_boolean_field!(_env, result_jobject, result, "booleanResult");
    result_jobject.into_inner()
}
