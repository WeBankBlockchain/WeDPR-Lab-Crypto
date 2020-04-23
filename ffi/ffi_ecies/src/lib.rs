extern crate hex;
extern crate jni;

#[macro_use]
extern crate wedpr_macros;
#[macro_use]
extern crate ffi_macros;
extern crate ecies;
extern crate common;
use ffi_common::utils;
use common::utils as common_utils;

use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jobject},
    JNIEnv,
};

use common::{
    error::WedprError,
};

use std::{ffi::CStr, panic};
use libc::c_char;
use std::ptr;
use std::ffi::CString;

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
    ) -> *mut backtrace_state
    {
        0 as *mut _
    }

    #[no_mangle]
    pub extern "C" fn __rbt_backtrace_syminfo(
        _state: *mut backtrace_state,
        _addr: uintptr_t,
        _cb: backtrace_syminfo_callback,
        _error: backtrace_error_callback,
        _data: *mut c_void,
    ) -> c_int
    {
        0
    }

    #[no_mangle]
    pub extern "C" fn __rbt_backtrace_pcinfo(
        _state: *mut backtrace_state,
        _addr: uintptr_t,
        _cb: backtrace_full_callback,
        _error: backtrace_error_callback,
        _data: *mut c_void,
    ) -> c_int
    {
        0
    }
}

fn ecies_secp256k1_encrypt(public_key: &str, message: &str) -> Result<String, WedprError>{
    let pk = match hex::decode(public_key) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("decode publicKey failed! publicKey = {}", public_key);
            return Err(WedprError::FormatError);
        },
    };
    let msg = match hex::decode(message) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("decode message failed! message = {}", message);
            return Err(WedprError::FormatError);
        },
    };
    let encrypt_data = match ecies::encrypt(&pk, &msg) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("ecies::encrypt message failed!");
            return Err(WedprError::FormatError);
        },
    };
    Ok(hex::encode(&encrypt_data))
}

fn ecies_secp256k1_decrypt(private_key: &str, encrypt_data: &str) -> Result<String, WedprError>{
    let sk = match hex::decode(private_key) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("decode privateKey failed! privateKey = {}", private_key);
            return Err(WedprError::FormatError);
        },
    };
    let encrypt_bytes = match hex::decode(encrypt_data) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("decode encrypt_data failed! encrypt_data = {}", encrypt_data);
            return Err(WedprError::FormatError);
        },
    };
    let mes = match ecies::decrypt(&sk, &encrypt_bytes) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("ecies::decrypt message failed!");
            return Err(WedprError::FormatError);
        },
    };
    Ok(hex::encode(&mes))
}

const ECIES_RESULT_JAVA_PATH: &str =
    "Lcom/webank/wedpr/ecies/EciesResult;";

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_ecies_NativeInterface_eciesEncrypt(
    _env: JNIEnv,
    _class: JClass,
    public_key_jstring: JString,
    message_jstring: JString,
) -> jobject
{
    let jobject_result =
        utils::new_jobject(&_env, ECIES_RESULT_JAVA_PATH);

    let public_key = jString_to_string!(
        _env,
        jobject_result,
        public_key_jstring
    );

    let message = jString_to_string!(
        _env,
        jobject_result,
        message_jstring
    );

    let encrypt_data = match ecies_secp256k1_encrypt(&public_key, &message) {
        Ok(v) => v,
        Err(_) => {
            return utils::set_error_jobject(
                &_env,
                &jobject_result,
                "jni ecies_secp256k1_encrypt failed",
            )
        },
    };


    add_string_to_jobject!(
        _env,
        jobject_result,
        encrypt_data,
        "encryptMessage"
    );

    jobject_result.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_ecies_NativeInterface_eciesDecrypt(
    _env: JNIEnv,
    _class: JClass,
    private_key_jstring: JString,
    encrypt_message_jstring: JString,
) -> jobject
{
    let jobject_result =
        utils::new_jobject(&_env, ECIES_RESULT_JAVA_PATH);

    let private_key = jString_to_string!(
        _env,
        jobject_result,
        private_key_jstring
    );

    let encrypt_data = jString_to_string!(
        _env,
        jobject_result,
        encrypt_message_jstring
    );

    let mes = match ecies_secp256k1_decrypt(&private_key, &encrypt_data) {
        Ok(v) => v,
        Err(_) => {
            return utils::set_error_jobject(
                &_env,
                &jobject_result,
                "jni ecies_secp256k1_decrypt failed",
            )
        },
    };


    add_string_to_jobject!(
        _env,
        jobject_result,
        mes,
        "decryptMessage"
    );

    jobject_result.into_inner()
}

#[no_mangle]
pub extern "C" fn ecies_secp256k1_encrypt_c(hex_public_key: *mut c_char,
                                            hex_message: *mut c_char,) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let pk = match utils::c_char_to_string(hex_public_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("public_key_cstring c_char_to_string failed!");
                return ptr::null_mut();
            },
        };
        let message = match utils::c_char_to_string(hex_message) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("message c_char_to_string failed!");
                return ptr::null_mut();
            },
        };

        let encrypt_data = match ecies_secp256k1_encrypt(&pk, &message) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("ffi ecies_secp256k1_encrypt failed!");
                return ptr::null_mut();
            },
        };

        let return_string = match CString::new(encrypt_data) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return_string.into_raw()
    });
    match result {
        Ok(res) => res,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn ecies_secp256k1_decrypt_c(hex_private_key: *mut c_char,
                                            hex_encrypt_data: *mut c_char,) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let sk = match utils::c_char_to_string(hex_private_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("private_key_cstring c_char_to_string failed!");
                return ptr::null_mut();
            },
        };
        let encrypt_data = match utils::c_char_to_string(hex_encrypt_data) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("encrypt_data c_char_to_string failed!");
                return ptr::null_mut();
            },
        };

        let decrypt_data = match ecies_secp256k1_decrypt(&sk, &encrypt_data) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("ffi ecies_secp256k1_decrypt failed!");
                return ptr::null_mut();
            },
        };

        let return_string = match CString::new(decrypt_data) {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        return_string.into_raw()
    });
    match result {
        Ok(res) => res,
        Err(_) => ptr::null_mut(),
    }
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
}
