extern crate hex;
extern crate jni;

#[macro_use]
extern crate wedpr_macros;
#[macro_use]
extern crate ffi_macros;
extern crate common;
extern crate ecies;
use crypto::hash;
use crypto::signature::Signature;
use ffi_common::utils;

use common::error::WedprError;

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jobject},
    JNIEnv,
};

pub const SUCCESS: i8 = 0;
pub const FAILURE: i8 = -1;

#[allow(non_camel_case_types)]
pub mod backtrace_hack {

    extern crate libc;

    use self::libc::uintptr_t;
    use std::os::raw::{c_char, c_int, c_void};

    pub type backtrace_syminfo_callback = extern "C" fn(
        data: *mut c_void,
        pc: uintptr_t,
        symname: *const c_char,
        symval: uintptr_t,
        symsize: uintptr_t,
    );
    pub type backtrace_full_callback = extern "C" fn(
        data: *mut c_void,
        pc: uintptr_t,
        filename: *const c_char,
        lineno: c_int,
        function: *const c_char,
    ) -> c_int;
    pub type backtrace_error_callback =
        extern "C" fn(data: *mut c_void, msg: *const c_char, errnum: c_int);
    pub enum backtrace_state {}

    #[no_mangle]
    pub extern "C" fn __rbt_backtrace_create_state(
        _filename: *const c_char,
        _threaded: c_int,
        _error: backtrace_error_callback,
        _data: *mut c_void,
    ) -> *mut backtrace_state {
        0 as *mut _
    }

    #[no_mangle]
    pub extern "C" fn __rbt_backtrace_syminfo(
        _state: *mut backtrace_state,
        _addr: uintptr_t,
        _cb: backtrace_syminfo_callback,
        _error: backtrace_error_callback,
        _data: *mut c_void,
    ) -> c_int {
        0
    }

    #[no_mangle]
    pub extern "C" fn __rbt_backtrace_pcinfo(
        _state: *mut backtrace_state,
        _addr: uintptr_t,
        _cb: backtrace_full_callback,
        _error: backtrace_error_callback,
        _data: *mut c_void,
    ) -> c_int {
        0
    }
}

fn ecies_secp256k1_encrypt(public_key: &str, message: &str) -> Result<String, WedprError> {
    let pk = match hex::decode(public_key) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("decode publicKey failed! publicKey = {}", public_key);
            return Err(WedprError::FormatError);
        }
    };
    let msg = match hex::decode(message) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("decode message failed! message = {}", message);
            return Err(WedprError::FormatError);
        }
    };
    let encrypt_data = match ecies::encrypt(&pk, &msg) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("ecies::encrypt message failed!");
            return Err(WedprError::FormatError);
        }
    };
    Ok(hex::encode(&encrypt_data))
}

fn ecies_secp256k1_decrypt(private_key: &str, encrypt_data: &str) -> Result<String, WedprError> {
    let sk = match hex::decode(private_key) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("decode privateKey failed! privateKey = {}", private_key);
            return Err(WedprError::FormatError);
        }
    };
    let encrypt_bytes = match hex::decode(encrypt_data) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!(
                "decode encrypt_data failed! encrypt_data = {}",
                encrypt_data
            );
            return Err(WedprError::FormatError);
        }
    };
    let mes = match ecies::decrypt(&sk, &encrypt_bytes) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("ecies::decrypt message failed!");
            return Err(WedprError::FormatError);
        }
    };
    Ok(hex::encode(&mes))
}

const CRYPTO_RESULT_JAVA_PATH: &str = "com/webank/wedpr/android/CryptoResult";

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_android_NativeInterface_eciesEncrypt(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    message_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let public_key = jString_to_string!(_env, jobject_result, public_key_jstring);

    let message = jString_to_string!(_env, jobject_result, message_jstring);

    let encrypt_data = match ecies_secp256k1_encrypt(&public_key, &message) {
        Ok(v) => v,
        Err(_) => {
            return utils::set_error_jobject(
                &_env,
                &jobject_result,
                "jni ecies_secp256k1_encrypt failed",
            )
        }
    };

    add_string_to_jobject!(_env, jobject_result, encrypt_data, "encryptMessage");

    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_android_NativeInterface_eciesDecrypt(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    encrypt_message_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let private_key = jString_to_string!(_env, jobject_result, private_key_jstring);

    let encrypt_data = jString_to_string!(_env, jobject_result, encrypt_message_jstring);

    let mes = match ecies_secp256k1_decrypt(&private_key, &encrypt_data) {
        Ok(v) => v,
        Err(_) => {
            return utils::set_error_jobject(
                &_env,
                &jobject_result,
                "jni ecies_secp256k1_decrypt failed",
            )
        }
    };

    add_string_to_jobject!(_env, jobject_result, mes, "decryptMessage");

    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_android_NativeInterface_secp256k1keyPair(
    _env: JNIEnv,
    _class: JClass,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let sign_obj = crypto::signature::WeDPRSecp256k1Recover::default();
    let (pk, sk) = sign_obj.generate_keypair();
    add_string_to_jobject!(_env, jobject_result, pk, "publicKey");
    add_string_to_jobject!(_env, jobject_result, sk, "privateKey");
    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_android_NativeInterface_secp256k1Sign(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    message_jstring: JString,
) -> jobject {
    let jobject_result = utils::new_jobject(&_env, CRYPTO_RESULT_JAVA_PATH);

    let private_key = jString_to_string!(_env, jobject_result, private_key_jstring);

    let message = jString_to_string!(_env, jobject_result, message_jstring);

    let sign_obj = crypto::signature::WeDPRSecp256k1Recover::default();
    let signature = match sign_obj.sign(&private_key, &message) {
        Ok(v) => v,
        Err(_) => {
            return utils::set_error_jobject(&_env, &jobject_result, "jni secp256k1Sign failed")
        }
    };

    add_string_to_jobject!(_env, jobject_result, signature, "signature");

    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_android_NativeInterface_secp256k1verify(
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

    let sign_obj = crypto::signature::WeDPRSecp256k1Recover::default();
    let result = sign_obj.verify(&public_key, &message, &signature);

    set_bool_field_to_jobject!(_env, jobject_result, result, "result");
    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_android_NativeInterface_keccak256(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecies() {
        //        let message: &str = "847adcf9b24cf0041ddff02ffe324e30b1271c5170086f8ee799dd1123dacb2e";
        let sk = "e82a0751b7671d20d24631faa7033ee6909ed73629e1795e830b8fb8666e17b8";
        let pk = "0436f3570c796c7589a150a4d8a3de37cef15f30e141ca9a7e3162d9c2e3edb4e8db2326fe5489fdbe4ce7931779b727242f7df19c0a773f101417616e7776e789";
        let msg = "847adcf9b24cf0041ddff02ffe324e30b1271c5170086f8ee799dd1123dacb2e";

        let dec = "BFaUOdWt1k5tOHt6iXkvzvuAQinsEYzSAt1fWQFtGSLwk6hEXYGcazsHQ4mZlElw2+rEit8fxfdm/l+zy839I52LUshVuHjfFgrHdsMkaJydZVRzOQfclKujPf34F2voFM7RAiw36GpHmmJIOWsLlfFWNTBB6BKta3gDfPNVdYsT";

        //        let encrypt_data = ecies_secp256k1_encrypt(pk, msg).unwrap();
        //        let decrypt_data = ecies_secp256k1_decrypt(sk, &encrypt_data).unwrap();
        let decrypt_data = ecies_secp256k1_decrypt(sk, dec).unwrap();
        wedpr_println!("decrypt_data = {}", decrypt_data);
        assert_eq!(&decrypt_data, msg)
    }

    // #[test]
    // fn test_sign() {
    //     let messageHex = "48656c6c6f20576f726c64";
    //     let sk = "62657b923754d4a8f42b861e52c2dab6ef22e00b68da95a3c5cc994c02ccb88d";
    //     let pk = "04dfd1e5a5922cc0bd335cac7f39450c4177bbb9c60226e212516495f711a96783704c457aa49a31b88b7d41d0950e9da228c0f09dc084e3619aae2cc08f8b1195";
    //     let sign_obj = crypto::signature::WeDPRSecp256k1Recover::default();
    //     println!("test sign!");
    //     let signature = match sign_obj.sign(&sk, &messageHex) {
    //         Ok(v) => v,
    //         Err(_) => {
    //             println!("signature failed!");
    //             return;
    //         }
    //     };
    //     println!("signature = {:?}!", signature);

    // }

    #[test]
    fn test_ecies_weid() {
        //        let message: &str = "847adcf9b24cf0041ddff02ffe324e30b1271c5170086f8ee799dd1123dacb2e";
        let sk = "4c7de89606afd44874b7a74cfda9d122ac57ab0718e890c96128ba56945425c9";
        let pk = "06181cacc6f5bce5d43acf8eded49a1eefd0eaf33cb6d0f0bd38d7df2d654d35a67770da47f0c8ed2859bce3175e00164c364e1adbcacaa48cf1f959c2ab4c02";
        let msg = "847adcf9b24cf0041ddff02ffe324e30b1271c5170086f8ee799dd1123dacb2e";

        // let dec = "BFaUOdWt1k5tOHt6iXkvzvuAQinsEYzSAt1fWQFtGSLwk6hEXYGcazsHQ4mZlElw2+rEit8fxfdm/l+zy839I52LUshVuHjfFgrHdsMkaJydZVRzOQfclKujPf34F2voFM7RAiw36GpHmmJIOWsLlfFWNTBB6BKta3gDfPNVdYsT";

        let encrypt_data = ecies_secp256k1_encrypt(pk, msg).unwrap();
        let decrypt_data = ecies_secp256k1_decrypt(sk, &encrypt_data).unwrap();
        // let decrypt_data = ecies_secp256k1_decrypt(sk, dec).unwrap();
        wedpr_println!("decrypt_data = {}", decrypt_data);
        assert_eq!(&decrypt_data, msg)
    }
}
