// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Signature function wrappers.

#![cfg(any(
    feature = "wedpr_f_signature_secp256k1",
    feature = "wedpr_f_signature_sm2",
    feature = "wedpr_f_signature_ed25519"
))]

use wedpr_l_utils::traits::Signature;

use crate::get_result_jobject;

#[cfg(feature = "wedpr_f_signature_secp256k1")]
use crate::config::SIGNATURE_SECP256K1;

#[cfg(feature = "wedpr_f_signature_sm2")]
use crate::config::SIGNATURE_SM2;

#[cfg(feature = "wedpr_f_signature_ed25519")]
use crate::config::SIGNATURE_ED25519;

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

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1GenKeyPair'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1GenKeyPair(
    _env: JNIEnv,
    _class: JClass,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let (pk, sk) = SIGNATURE_SECP256K1.generate_keypair();

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&pk),
        "publicKey"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&sk),
        "privateKey"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1DerivePublicKey'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1DerivePublicKey(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);

    let public_key = match SIGNATURE_SECP256K1.derive_public_key(&private_key) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "secp256k1 derive_public_key failed, private_key={}",
                    bytes_to_string(&private_key)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&public_key),
        "publicKey"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&private_key),
        "privateKey"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1Sign'.
// TODO: Add secp256k1SignUtf8 to allow non-encoded UTF8 input.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1Sign(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    msg_hash_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);

    let signature = match SIGNATURE_SECP256K1.sign(&private_key, &msg_hash) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "secp256k1 sign failed, msg_hash={}",
                    bytes_to_string(&msg_hash)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&signature),
        "signature"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1Verify'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1Verify(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    msg_hash_jstring: JString,
    signature_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let public_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, public_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);
    let signature =
        java_safe_jstring_to_bytes!(_env, result_jobject, signature_jstring);

    let result = SIGNATURE_SECP256K1.verify(&public_key, &msg_hash, &signature);

    java_safe_set_boolean_field!(_env, result_jobject, result, "booleanResult");
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->secp256k1RecoverPublicKey'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_secp256k1RecoverPublicKey(
    _env: JNIEnv,
    _class: JClass,
    msg_hash_jstring: JString,
    signature_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);
    let signature =
        java_safe_jstring_to_bytes!(_env, result_jobject, signature_jstring);

    let result =
        match SIGNATURE_SECP256K1.recover_public_key(&msg_hash, &signature) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "secp256k1 recover failed, msg_hash={}",
                        bytes_to_string(&msg_hash)
                    ),
                )
            },
        };

    java_safe_set_bytes_field!(_env, result_jobject, result, "publicKey");
    result_jobject.into_inner()
}

// SM2 implementation.

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sm2GenKeyPair'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm2GenKeyPair(
    _env: JNIEnv,
    _class: JClass,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let (pk, sk) = SIGNATURE_SM2.generate_keypair();

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&pk),
        "publicKey"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&sk),
        "privateKey"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sm2DerivePublicKey'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm2DerivePublicKey(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);

    let public_key = match SIGNATURE_SM2.derive_public_key(&private_key) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "sm2 derive_public_key failed, private_key={}",
                    bytes_to_string(&private_key)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&public_key),
        "publicKey"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&private_key),
        "privateKey"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sm2Sign'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm2Sign(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    msg_hash_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);

    let signature = match SIGNATURE_SM2.sign(&private_key, &msg_hash) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "sm2 sign failed, msg_hash={}",
                    bytes_to_string(&msg_hash)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&signature),
        "signature"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sm2SignFast'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm2SignFast(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    public_key_jstring: JString,
    msg_hash_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);
    let public_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, public_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);

    let signature =
        match SIGNATURE_SM2.sign_fast(&private_key, &public_key, &msg_hash) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &_env,
                    &result_jobject,
                    &format!(
                        "sm2 sign failed, msg_hash={}",
                        bytes_to_string(&msg_hash)
                    ),
                )
            },
        };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&signature),
        "signature"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sm2Verify'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm2Verify(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    msg_hash_jstring: JString,
    signature_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let public_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, public_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);
    let signature =
        java_safe_jstring_to_bytes!(_env, result_jobject, signature_jstring);

    let result = SIGNATURE_SM2.verify(&public_key, &msg_hash, &signature);

    java_safe_set_boolean_field!(_env, result_jobject, result, "booleanResult");
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->sm2ComputeHashE'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm2ComputeHashE(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    msg_hash_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let public_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, public_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);

    let result = match SIGNATURE_SM2.compute_hash_e(&public_key, &msg_hash) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "sm2 compute_e, msg_hash={}",
                    bytes_to_string(&msg_hash)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&result),
        "hash"
    );
    result_jobject.into_inner()
}

// ED25519 implementation.

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->ed25519GenKeyPair'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_ed25519GenKeyPair(
    _env: JNIEnv,
    _class: JClass,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let (pk, sk) = SIGNATURE_ED25519.generate_keypair();

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&pk),
        "publicKey"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&sk),
        "privateKey"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->ed25519DerivePublicKey'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_ed25519DerivePublicKey(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);

    let public_key = match SIGNATURE_ED25519.derive_public_key(&private_key) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "sm2 derive_public_key failed, private_key={}",
                    bytes_to_string(&private_key)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&public_key),
        "publicKey"
    );
    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&private_key),
        "privateKey"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->ed25519Sign'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_ed25519Sign(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    msg_hash_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let private_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, private_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);

    let signature = match SIGNATURE_ED25519.sign(&private_key, &msg_hash) {
        Ok(v) => v,
        Err(_) => {
            return java_set_error_field_and_extract_jobject(
                &_env,
                &result_jobject,
                &format!(
                    "sm2 sign failed, msg_hash={}",
                    bytes_to_string(&msg_hash)
                ),
            )
        },
    };

    java_safe_set_string_field!(
        _env,
        result_jobject,
        bytes_to_string(&signature),
        "signature"
    );
    result_jobject.into_inner()
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// Java interface for
/// 'com.webank.wedpr.crypto.NativeInterface->ed25519Verify'.
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_ed25519Verify(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    msg_hash_jstring: JString,
    signature_jstring: JString,
) -> jobject {
    let result_jobject = get_result_jobject(&_env);

    let public_key =
        java_safe_jstring_to_bytes!(_env, result_jobject, public_key_jstring);
    let msg_hash =
        java_safe_jstring_to_bytes!(_env, result_jobject, msg_hash_jstring);
    let signature =
        java_safe_jstring_to_bytes!(_env, result_jobject, signature_jstring);

    let result = SIGNATURE_ED25519.verify(&public_key, &msg_hash, &signature);

    java_safe_set_boolean_field!(_env, result_jobject, result, "booleanResult");
    result_jobject.into_inner()
}
