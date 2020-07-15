extern crate jni;

use ffi_common::utils;

extern crate crypto;

use crypto::signature::Signature;
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jobject},
    JNIEnv,
};

// const CRYPTO_RESULT_JAVA_PATH: &str = "Lcom/webank/wedpr/crypto/CryptoResult;";
const CRYPTO_RESULT_JAVA_PATH: &str = "Lorg/fisco/bcos/sdk/crypto/CryptoNativeResult;";


#[no_mangle]
pub extern "system" fn Java_org_fisco_bcos_sdk_crypto_CryptoNativeInterface_sm2Sign(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    message_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let private_key = jString_to_string!(_env, jobject_result, private_key_jstring);

    let message = jString_to_string!(_env, jobject_result, message_jstring);
    let sign_obj = crypto::signature::WeDPRSm2p256v1::default();
    let encrypt_data = match sign_obj.sign(&private_key, &message) {
        Ok(v) => v,
        Err(_) => {
            return utils::set_error_jobject(
                &_env,
                &jobject_result,
                "jni WeDPRSm2p256v1 sign failed",
            )
        }
    };

    add_string_to_jobject!(_env, jobject_result, encrypt_data, "signature");

    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_org_fisco_bcos_sdk_crypto_CryptoNativeInterface_sm2verify(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    message_jstring: JString,
    signature_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let public_key = jString_to_string!(_env, jobject_result, public_key_jstring);

    let message = jString_to_string!(_env, jobject_result, message_jstring);
    let signature = jString_to_string!(_env, jobject_result, signature_jstring);
    let sign_obj = crypto::signature::WeDPRSm2p256v1::default();
    let result = sign_obj.verify(&public_key, &message, &signature);
    set_bool_field_to_jobject!(_env, jobject_result, result, "verifyResult");

    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_org_fisco_bcos_sdk_crypto_CryptoNativeInterface_sm2keyPair(
    _env: JNIEnv,
    _class: JClass,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let sign_obj = crypto::signature::WeDPRSm2p256v1::default();
    let (pk, sk) = sign_obj.generate_keypair();

    add_string_to_jobject!(_env, jobject_result, pk, "publicKey");
    add_string_to_jobject!(_env, jobject_result, sk, "privteKey");

    jobject_result.into_inner()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
