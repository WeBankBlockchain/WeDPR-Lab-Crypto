extern crate jni;
use ffi_common::utils;

extern crate crypto;

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};

const CRYPTO_RESULT_JAVA_PATH: &str = "Lcom/webank/wedpr/crypto/CryptoResult;";

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519GenVRFProof(
    _env: JNIEnv,
    _class: JClass,
    vrf_private_key_jstring: JString,
    vrf_input_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let vrf_private_key = jString_to_string!(_env, jobject_result, vrf_private_key_jstring);

    let vrf_input = jString_to_string!(_env, jobject_result, vrf_input_jstring);
    let vrf_proof_result =
        match crypto::curve_25519_vrf::curve25519_vrf_prove(&vrf_private_key, &vrf_input) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &_env,
                    &jobject_result,
                    "jni curve25519_vrf_prove generate failed",
                )
            }
        };
    add_string_to_jobject!(_env, jobject_result, vrf_proof_result.encode(), "vrfProof");
    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519VRFVerify(
    _env: JNIEnv,
    _class: JClass,
    vrf_public_key_jstring: JString,
    input_jstring: JString,
    vrf_proof_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);
    let vrf_public_key = jString_to_string!(_env, jobject_result, vrf_public_key_jstring);
    let vrf_input = jString_to_string!(_env, jobject_result, input_jstring);
    let vrf_proof_str = jString_to_string!(_env, jobject_result, vrf_proof_jstring);
    let mut vrf_verify_result = true;
    let vrf_proof_object = match crypto::curve_25519_vrf::vrf_proof::decode(&vrf_proof_str) {
        Ok(v) => v,
        Err(_) => {
            vrf_verify_result = false;
            return utils::set_error_jobject(&_env, &jobject_result, "jni vrfProof decode failed");
        }
    };
    let vrf_verify_result = crypto::curve_25519_vrf::curve25519_vrf_verify(
        &vrf_public_key,
        &vrf_input,
        &vrf_proof_object,
    );
    set_bool_field_to_jobject!(_env, jobject_result, vrf_verify_result, "vrfVerifyResult");
    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519VRFGetPubKeyFromPrivateKey(
    _env: JNIEnv,
    _class: JClass,
    vrf_private_key_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);
    let vrf_private_key = jString_to_string!(_env, jobject_result, vrf_private_key_jstring);
    let vrf_public_key = crypto::curve_25519_vrf::curve25519_vrf_gen_pubkey(&vrf_private_key);
    add_string_to_jobject!(_env, jobject_result, vrf_public_key, "vrfPublicKey");
    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519VRFProofToHash(
    _env: JNIEnv,
    _class: JClass,
    vrf_proof_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);
    let vrf_proof_str = jString_to_string!(_env, jobject_result, vrf_proof_jstring);
    let vrf_proof_object = match crypto::curve_25519_vrf::vrf_proof::decode(&vrf_proof_str) {
        Ok(v) => v,
        Err(_) => {
            return utils::set_error_jobject(&_env, &jobject_result, "jni decode vrfProof failed")
        }
    };
    let vrf_hash = match crypto::curve_25519_vrf::curve25519_vrf_proof_to_hash(&vrf_proof_object) {
        Ok(v) => v,
        Err(_) => {
            return utils::set_error_jobject(
                &_env,
                &jobject_result,
                "jni curve25519_vrf_proof_to_hash failed",
            )
        }
    };
    add_string_to_jobject!(_env, jobject_result, vrf_hash, "vrfHash");
    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_curve25519IsValidVRFPubKey(
    _env: JNIEnv,
    _class: JClass,
    vrf_public_key_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);
    let vrf_public_key = jString_to_string!(_env, jobject_result, vrf_public_key_jstring);
    let valid = crypto::curve_25519_vrf::curve25519_vrf_is_valid_pubkey(&vrf_public_key);
    set_bool_field_to_jobject!(_env, jobject_result, valid, "isValidVRFPublicKey");
    jobject_result.into_inner()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
