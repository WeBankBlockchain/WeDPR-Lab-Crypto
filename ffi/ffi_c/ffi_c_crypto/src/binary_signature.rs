// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Signature function wrappers.

#![cfg(all(
    feature = "wedpr_f_signature_secp256k1",
    feature = "wedpr_f_signature_sm2"
))]

use wedpr_l_utils::traits::Signature;

#[cfg(feature = "wedpr_f_signature_secp256k1")]
use crate::config::SIGNATURE_SECP256K1;

#[cfg(feature = "wedpr_f_signature_sm2")]
use crate::config::SIGNATURE_SM2;

use libc::c_char;
use std::{panic, ptr};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{FAILURE, SUCCESS};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{FAILURE, SUCCESS};

// Secp256k1 implementation.
#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_gen_binary_key_pair'.
pub extern "C" fn wedpr_secp256k1_gen_binary_key_pair() -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let (mut pk, sk) = SIGNATURE_SECP256K1.generate_keypair();
        if pk.len() != 65 {
            return ptr::null_mut();
        }
        if sk.len() != 32 {
            return ptr::null_mut();
        }
        pk.extend(&sk);
        pk.as_ptr() as *mut c_char
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_derive_binary_public_key'.
pub extern "C" fn wedpr_secp256k1_derive_binary_public_key(
    encoded_private_key: *mut c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| unsafe {
        let private_key_size = 32;
        let sk = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            private_key_size,
            private_key_size,
        );
        let pk = match SIGNATURE_SECP256K1.derive_public_key(&sk) {
            Ok(v) => v,
            Err(_) => {
                std::mem::forget(sk);
                return ptr::null_mut();
            },
        };
        std::mem::forget(sk);
        pk.as_ptr() as *mut c_char
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_sign_binary'.
pub extern "C" fn wedpr_secp256k1_sign_binary(
    encoded_private_key: *const c_char,
    encoded_message_hash: *const c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| unsafe {
        let private_key_size = 32;
        let private_key = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            private_key_size,
            private_key_size,
        );
        let message_hash_size = 32;
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            message_hash_size,
            message_hash_size,
        );
        let signature =
            match SIGNATURE_SECP256K1.sign(&private_key, &message_hash) {
                Ok(v) => v,
                Err(_) => {
                    std::mem::forget(private_key);
                    std::mem::forget(message_hash);
                    return ptr::null_mut();
                },
            };
        std::mem::forget(private_key);
        std::mem::forget(message_hash);
        signature.as_ptr() as *mut c_char
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_verify_binary'.
pub extern "C" fn wedpr_secp256k1_verify_binary(
    encoded_public_key: *const c_char,
    encoded_message_hash: *const c_char,
    encoded_signature: *const c_char,
    encoded_signature_len: usize,
) -> i8
{
    let result = panic::catch_unwind(|| unsafe {
        let public_key_size = 64;
        let public_key = Vec::from_raw_parts(
            encoded_public_key as *mut u8,
            public_key_size,
            public_key_size,
        );
        let message_hash_size = 32;
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            message_hash_size,
            message_hash_size,
        );
        let signature_data = Vec::from_raw_parts(
            encoded_signature as *mut u8,
            encoded_signature_len,
            encoded_signature_len,
        );
        let verify_result = match SIGNATURE_SECP256K1.verify(
            &public_key,
            &message_hash,
            &signature_data,
        ) {
            true => SUCCESS,
            false => FAILURE,
        };
        std::mem::forget(public_key);
        std::mem::forget(message_hash);
        std::mem::forget(signature_data);
        verify_result
    });
    c_safe_return_with_error_value!(result, FAILURE)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_recover_binary_public_key'.
pub extern "C" fn wedpr_secp256k1_recover_binary_public_key(
    encoded_message_hash: *const c_char,
    encoded_signature: *const c_char,
    encoded_signature_len: usize,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| unsafe {
        let message_hash_size = 32;
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            message_hash_size,
            message_hash_size,
        );
        let signature_data = Vec::from_raw_parts(
            encoded_signature as *mut u8,
            encoded_signature_len,
            encoded_signature_len,
        );
        let public_key = match SIGNATURE_SECP256K1
            .recover_public_key(&message_hash, &signature_data)
        {
            Ok(v) => v,
            Err(_) => {
                std::mem::forget(message_hash);
                std::mem::forget(signature_data);
                return ptr::null_mut();
            },
        };
        std::mem::forget(message_hash);
        std::mem::forget(signature_data);
        public_key.as_ptr() as *mut c_char
    });
    c_safe_return!(result)
}

// SM2 implementation.
#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_gen_binary_key_pair'.
pub extern "C" fn wedpr_sm2_gen_binary_key_pair() -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let (pk, sk) = SIGNATURE_SM2.generate_keypair();
        if pk.len() != 65 {
            return ptr::null_mut();
        }
        if sk.len() != 32 {
            return ptr::null_mut();
        }
        let key_pair = [pk.as_slice(), sk.as_slice()].concat();
        key_pair.as_ptr() as *mut c_char
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_derive_binary_public_key'.
pub extern "C" fn wedpr_sm2_derive_binary_public_key(
    encoded_private_key: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| unsafe {
        let private_key_size = 32;
        let sk = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            private_key_size,
            private_key_size,
        );
        let pk = match SIGNATURE_SM2.derive_public_key(&sk) {
            Ok(v) => v,
            Err(_) => {
                std::mem::forget(sk);
                return ptr::null_mut();
            },
        };
        std::mem::forget(sk);
        pk.as_ptr() as *mut c_char
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign_binary'.
pub extern "C" fn wedpr_sm2_sign_binary(
    encoded_private_key: *const c_char,
    encoded_message_hash: *const c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| unsafe {
        let private_key_size = 32;
        let private_key = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            private_key_size,
            private_key_size,
        );
        let message_hash_size = 32;
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            message_hash_size,
            message_hash_size,
        );
        let signature = match SIGNATURE_SM2.sign(&private_key, &message_hash) {
            Ok(v) => v,
            Err(_) => {
                std::mem::forget(private_key);
                std::mem::forget(message_hash);
                return ptr::null_mut();
            },
        };
        std::mem::forget(private_key);
        std::mem::forget(message_hash);
        signature.as_ptr() as *mut c_char
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign_binary_fast'.
pub extern "C" fn wedpr_sm2_sign_binary_fast(
    encoded_private_key: *const c_char,
    encoded_public_key: *const c_char,
    encoded_message_hash: *const c_char,
) -> *mut c_char
{
    let result = panic::catch_unwind(|| unsafe {
        let private_key_size = 32;
        let private_key = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            private_key_size,
            private_key_size,
        );
        let message_hash_size = 32;
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            message_hash_size,
            message_hash_size,
        );
        let public_key_size = 64;
        let public_key = Vec::from_raw_parts(
            encoded_public_key as *mut u8,
            public_key_size,
            public_key_size,
        );
        let signature = match SIGNATURE_SM2.sign_fast(
            &private_key,
            &public_key,
            &message_hash,
        ) {
            Ok(v) => v,
            Err(_) => {
                std::mem::forget(private_key);
                std::mem::forget(message_hash);
                std::mem::forget(public_key);
                return ptr::null_mut();
            },
        };
        std::mem::forget(private_key);
        std::mem::forget(message_hash);
        std::mem::forget(public_key);
        signature.as_ptr() as *mut c_char
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_verify_binary'.
pub extern "C" fn wedpr_sm2_verify_binary(
    encoded_public_key: *const c_char,
    encoded_message_hash: *const c_char,
    encoded_signature: *const c_char,
    signature_len: usize,
) -> i8
{
    let result = panic::catch_unwind(|| unsafe {
        let public_key_size = 64;
        let public_key = Vec::from_raw_parts(
            encoded_public_key as *mut u8,
            public_key_size,
            public_key_size,
        );
        let message_hash_size = 32;
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            message_hash_size,
            message_hash_size,
        );
        let signature_data = Vec::from_raw_parts(
            encoded_signature as *mut u8,
            signature_len,
            signature_len,
        );
        let verify_result = match SIGNATURE_SM2.verify(
            &public_key,
            &message_hash,
            &signature_data,
        ) {
            true => SUCCESS,
            false => FAILURE,
        };
        std::mem::forget(public_key);
        std::mem::forget(message_hash);
        std::mem::forget(signature_data);
        verify_result
    });
    c_safe_return_with_error_value!(result, FAILURE)
}
