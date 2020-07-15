extern crate jni;

use ffi_common::utils;

extern crate crypto;

use crypto::hash;
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jobject},
    JNIEnv,
};

const CRYPTO_RESULT_JAVA_PATH: &str = "Lcom/webank/wedpr/crypto/CryptoResult;";
// const CRYPTO_RESULT_JAVA_PATH: &str = "Lorg/fisco/bcos/sdk/crypto/CryptoNativeResult;";
// org.fisco.bcos.sdk.crypto.CryptoNativeResult

#[no_mangle]
// pub extern "system" fn Java_org_fisco_bcos_sdk_crypto_CryptoNativeInterface_keccak256(
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_keccak256(
    _env: JNIEnv,
    _class: JClass,
    message_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let message = jString_to_string!(_env, jobject_result, message_jstring);
    let hash_data = match hash::keccak256_hex(&message) {
        Ok(v) => v,
        Err(_) => {
            return utils::set_error_jobject(&_env, &jobject_result, "jni keccak256_hex failed")
        }
    };

    add_string_to_jobject!(_env, jobject_result, hash_data, "hash");

    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_sm3(
// pub extern "system" fn Java_org_fisco_bcos_sdk_crypto_CryptoNativeInterface_sm3(
    _env: JNIEnv,
    _class: JClass,
    message_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let message = jString_to_string!(_env, jobject_result, message_jstring);
    let hash_data = match hash::sm3_hex(&message) {
        Ok(v) => v,
        Err(_) => return utils::set_error_jobject(&_env, &jobject_result, "jni sm3_hex failed"),
    };

    add_string_to_jobject!(_env, jobject_result, hash_data, "hash");

    jobject_result.into_inner()
}
