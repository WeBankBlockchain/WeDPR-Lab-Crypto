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

use libc::c_char;
use std::ffi::CString;
use std::panic;
use std::ptr;

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

#[no_mangle]
pub extern "C" fn ecies_secp256k1_encrypt_c(
    hex_public_key: *mut c_char,
    hex_plaintext: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let pk = match utils::c_char_to_string(hex_public_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("public_key_cstring c_char_to_string failed!");
                return ptr::null_mut();
            }
        };
        let message = match utils::c_char_to_string(hex_plaintext) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("message c_char_to_string failed!");
                return ptr::null_mut();
            }
        };

        let encrypt_data = match ecies_secp256k1_encrypt(&pk, &message) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("ffi ecies_secp256k1_encrypt failed!");
                return ptr::null_mut();
            }
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
pub extern "C" fn ecies_secp256k1_decrypt_c(
    hex_private_key: *mut c_char,
    hex_ciphertext: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let sk = match utils::c_char_to_string(hex_private_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("private_key_cstring c_char_to_string failed!");
                return ptr::null_mut();
            }
        };
        let encrypt_data = match utils::c_char_to_string(hex_ciphertext) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("encrypt_data c_char_to_string failed!");
                return ptr::null_mut();
            }
        };

        let decrypt_data = match ecies_secp256k1_decrypt(&sk, &encrypt_data) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("ffi ecies_secp256k1_decrypt failed!");
                return ptr::null_mut();
            }
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

#[no_mangle]
pub extern "C" fn wedpr_secp256k1keyPair() -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let sign_obj = crypto::signature::WeDPRSecp256k1Recover::default();
        let (pk, sk) = sign_obj.generate_keypair();
        let keypair = format!("{}|{}", pk, sk);
        let return_string = match CString::new(keypair) {
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
pub extern "C" fn wedpr_crypto_secp256k1Sign(
    hex_private_key: *mut c_char,
    message_string: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = match utils::c_char_to_string(hex_private_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("hex_private_key c_char_to_string failed!");
                return ptr::null_mut();
            }
        };

        let message = match utils::c_char_to_string(message_string) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("message_string c_char_to_string failed!");
                return ptr::null_mut();
            }
        };

        let sign_obj = crypto::signature::WeDPRSecp256k1Recover::default();
        let signature = match sign_obj.sign(&private_key, &message) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            }
        };
        let return_string = match CString::new(signature) {
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
pub extern "C" fn wedpr_secp256k1verify(
    hex_public_key: *mut c_char,
    message_string: *mut c_char,
    signature_string: *mut c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key = match utils::c_char_to_string(hex_public_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("hex_public_key c_char_to_string failed!");
                return FAILURE;
            }
        };

        let message = match utils::c_char_to_string(message_string) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("message_string c_char_to_string failed!");
                return FAILURE;
            }
        };

        let signature = match utils::c_char_to_string(signature_string) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("signature_string c_char_to_string failed!");
                return FAILURE;
            }
        };

        let sign_obj = crypto::signature::WeDPRSecp256k1Recover::default();
        let result = sign_obj.verify(&public_key, &message, &signature);
        if result == false {
            return FAILURE;
        }
        SUCCESS
    });

    match result {
        Ok(res) => res,
        Err(_) => FAILURE,
    }
}

#[no_mangle]
pub extern "C" fn wedpr_keccak256(message_string: *mut c_char) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let message = match utils::c_char_to_string(message_string) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("message_string c_char_to_string failed!");
                return ptr::null_mut();
            }
        };

        let hash_data = match hash::keccak256_hex(&message) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            }
        };
        let return_string = match CString::new(hash_data) {
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
