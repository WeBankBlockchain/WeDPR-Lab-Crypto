// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! VRF function wrappers.

#![cfg(feature = "wedpr_f_vrf_curve25519")]

use crate::get_result_jobject;

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, java_jstring_to_bytes, java_jstring_to_string,
    java_set_error_field_and_extract_jobject,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, java_jstring_to_bytes, java_jstring_to_string,
    java_set_error_field_and_extract_jobject,
};

#[cfg(feature = "wedpr_f_vrf_curve25519")]
use wedpr_l_crypto_vrf_curve25519::WedprCurve25519Vrf;
use wedpr_l_utils::{tool::string_to_bytes_utf8, traits::Vrf};

// Curve25519 implementation.

#[cfg(feature = "wedpr_f_vrf_curve25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->curve25519VrfProveUtf8'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519VrfProveUtf8(
    _env: JNIEnv,
    _class: JClass,
    encoded_private_key_jstring: JString,
    utf8_message_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let private_key_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_private_key_jstring
    );
    let message_bytes = java_safe_jstring_to_bytes_utf8!(
        _env,
        result_jobject,
        utf8_message_jstring
    );

    let proof =
        match WedprCurve25519Vrf::prove(&private_key_bytes, &message_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "WedprCurve25519Vrf prove failed, \
                         private_key_bytes={}, input_bytes={}",
                        bytes_to_string(&private_key_bytes),
                        bytes_to_string(&message_bytes)
                    ),
                )
            },
        };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&proof.encode_proof()),
        "vrfProof"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_vrf_curve25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->curve25519VrfProveFastUtf8'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519VrfProveFastUtf8(
    _env: JNIEnv,
    _class: JClass,
    encoded_private_key_jstring: JString,
    encoded_public_key_jstring: JString,
    utf8_message_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let private_key_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_private_key_jstring
    );
    let public_key_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_public_key_jstring
    );
    let message_bytes = java_safe_jstring_to_bytes_utf8!(
        _env,
        result_jobject,
        utf8_message_jstring
    );

    let proof = match WedprCurve25519Vrf::prove_fast(
        &private_key_bytes,
        &public_key_bytes,
        &message_bytes,
    ) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "WedprCurve25519Vrf prove failed, private_key_bytes={}, \
                     input_bytes={}",
                    bytes_to_string(&private_key_bytes),
                    bytes_to_string(&message_bytes)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&proof.encode_proof()),
        "vrfProof"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_vrf_curve25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->curve25519VrfVerifyUtf8'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519VrfVerifyUtf8(
    _env: JNIEnv,
    _class: JClass,
    encoded_public_key_jstring: JString,
    utf8_message_jstring: JString,
    encoded_proof_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let public_key_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_public_key_jstring
    );
    let message_bytes = java_safe_jstring_to_bytes_utf8!(
        _env,
        result_jobject,
        utf8_message_jstring
    );
    let proof_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_proof_jstring
    );
    let proof = match WedprCurve25519Vrf::decode_proof(&proof_bytes) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "WedprCurve25519Vrf decode failed, proof_bytes={}",
                    bytes_to_string(&proof_bytes),
                ),
            )
        },
    };

    let result = proof.verify(&public_key_bytes, &message_bytes);

    java_safe_set_boolean_field!(_env, result_jobject, result, "booleanResult");
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_vrf_curve25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->curve25519VrfDerivePublicKey'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519VrfDerivePublicKey(
    _env: JNIEnv,
    _class: JClass,
    encoded_private_key_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let private_key_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_private_key_jstring
    );

    let public_key = WedprCurve25519Vrf::derive_public_key(&private_key_bytes);

    java_safe_set_bytes_field!(_env, result_jobject, public_key, "publicKey");
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_vrf_curve25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->curve25519VrfProofToHash'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519VrfProofToHash(
    _env: JNIEnv,
    _class: JClass,
    encoded_proof_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let proof_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_proof_jstring
    );
    let proof = match WedprCurve25519Vrf::decode_proof(&proof_bytes) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "WedprCurve25519Vrf decode failed, proof_bytes={}",
                    bytes_to_string(&proof_bytes),
                ),
            )
        },
    };

    let hash_bytes = match proof.proof_to_hash() {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "WedprCurve25519Vrf proof_to_bytes failed, proof_bytes={}",
                    bytes_to_string(&proof_bytes),
                ),
            )
        },
    };

    java_safe_set_bytes_field!(_env, result_jobject, hash_bytes, "hash");
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_vrf_curve25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->curve25519VrfIsValidPubKey'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519VrfIsValidPublicKey(
    _env: JNIEnv,
    _class: JClass,
    encoded_public_key_jstring: JString,
) -> jobject
{
    let result_jobject = get_result_jobject(&_env);

    let public_key_bytes = java_safe_jstring_to_bytes!(
        _env,
        result_jobject,
        encoded_public_key_jstring
    );

    let result = WedprCurve25519Vrf::is_valid_public_key(&public_key_bytes);

    java_safe_set_boolean_field!(_env, result_jobject, result, "booleanResult");
    result_jobject.into_inner()
}
