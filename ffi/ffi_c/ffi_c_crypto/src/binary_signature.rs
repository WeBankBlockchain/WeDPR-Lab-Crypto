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
use std::panic;

const PUBLIC_KEY_SIZE_WITHOUT_PREFIX: usize = 64;
const PUBLIC_KEY_SIZE_WITH_PREFIX: usize = 65;
const SECP256K1_SIGNATURE_DATA_LENGTH: usize = 65;
const SM2_SIGNATURE_DATA_LENGTH: usize = 64;
const PRIVATE_KEY_SIZE: usize = 32;
pub const SUCCESS: i8 = 0;
pub const FAILURE: i8 = -1;

// the signature result
#[repr(C)]
pub struct SignatureResult {
    signature_data: *mut c_char,
    signature_len: usize,
}

// define keyPair
#[repr(C)]
pub struct KeyPairData {
    public_key: *mut c_char,
    public_key_len: usize,
    private_key: *mut c_char,
    private_key_len: usize,
}

#[repr(C)]
pub struct PublicKey {
    public_key: *mut c_char,
    public_key_len: usize,
}

#[macro_export]
macro_rules! c_safe_return_ret_code {
    ($result:expr) => {
        match $result {
            Ok(v) => v,
            Err(_) => FAILURE,
        }
    };
}

#[macro_export]
macro_rules! c_safe_return_public_key_object {
    ($result:expr) => {
        c_safe_return_with_error_value!($result, EMPTY_PUBLIC_KEY)
    };
}

// Secp256k1 implementation.
#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_gen_binary_key_pair'.
pub extern "C" fn wedpr_secp256k1_gen_binary_key_pair(
    key_pair: &mut KeyPairData,
) -> i8 {
    let result = panic::catch_unwind(|| {
        if key_pair.public_key_len < PUBLIC_KEY_SIZE_WITHOUT_PREFIX {
            return FAILURE;
        }
        if key_pair.private_key_len < PRIVATE_KEY_SIZE {
            return FAILURE;
        }
        unsafe {
            let (public_key, private_key) =
                SIGNATURE_SECP256K1.generate_keypair();
            let pk = std::slice::from_raw_parts_mut(
                key_pair.public_key as *mut u8,
                key_pair.public_key_len,
            );
            let sk = std::slice::from_raw_parts_mut(
                key_pair.private_key as *mut u8,
                key_pair.private_key_len,
            );
            pk[0..PUBLIC_KEY_SIZE_WITHOUT_PREFIX]
                .copy_from_slice(&public_key[1..PUBLIC_KEY_SIZE_WITH_PREFIX]);
            sk[0..PRIVATE_KEY_SIZE].copy_from_slice(&private_key);
            std::mem::forget(pk);
            std::mem::forget(sk);
            SUCCESS
        }
    });
    c_safe_return_ret_code!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_derive_binary_public_key'.
pub extern "C" fn wedpr_secp256k1_derive_binary_public_key(
    public_key: &mut PublicKey,
    encoded_private_key: *const c_char,
    encoded_private_key_len: usize,
) -> i8 {
    if public_key.public_key_len < PUBLIC_KEY_SIZE_WITHOUT_PREFIX {
        return FAILURE;
    }
    let result = panic::catch_unwind(|| unsafe {
        let sk = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            encoded_private_key_len,
            encoded_private_key_len,
        );
        let pk = match SIGNATURE_SECP256K1.derive_public_key(&sk) {
            Ok(v) => v,
            Err(_) => {
                std::mem::forget(sk);
                return FAILURE;
            },
        };
        std::mem::forget(sk);
        let public_key_slice = std::slice::from_raw_parts_mut(
            public_key.public_key as *mut u8,
            public_key.public_key_len,
        );
        public_key_slice[0..PUBLIC_KEY_SIZE_WITHOUT_PREFIX]
            .copy_from_slice(&pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX]);
        std::mem::forget(public_key_slice);
        SUCCESS
    });
    c_safe_return_ret_code!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_sign_binary'.
pub extern "C" fn wedpr_secp256k1_sign_binary(
    signature_result: &mut SignatureResult,
    encoded_private_key: *const c_char,
    encoded_private_key_len: usize,
    encoded_message_hash: *const c_char,
    encoded_message_hash_len: usize,
) -> i8 {
    if signature_result.signature_len < SECP256K1_SIGNATURE_DATA_LENGTH {
        return FAILURE;
    }
    let result = panic::catch_unwind(|| unsafe {
        let private_key = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            encoded_private_key_len,
            encoded_private_key_len,
        );
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            encoded_message_hash_len,
            encoded_message_hash_len,
        );
        let signature =
            match SIGNATURE_SECP256K1.sign(&private_key, &message_hash) {
                Ok(v) => v,
                Err(_) => {
                    std::mem::forget(private_key);
                    std::mem::forget(message_hash);
                    return FAILURE;
                },
            };
        std::mem::forget(private_key);
        std::mem::forget(message_hash);
        let signature_result_slice = std::slice::from_raw_parts_mut(
            signature_result.signature_data as *mut u8,
            signature_result.signature_len,
        );
        signature_result_slice[0..SECP256K1_SIGNATURE_DATA_LENGTH]
            .copy_from_slice(&signature);
        std::mem::forget(signature_result_slice);
        SUCCESS
    });
    c_safe_return_ret_code!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_verify_binary'.
pub extern "C" fn wedpr_secp256k1_verify_binary(
    encoded_public_key: *const c_char,
    encoded_public_key_len: usize,
    encoded_message_hash: *const c_char,
    encoded_message_hash_len: usize,
    encoded_signature: *const c_char,
    encoded_signature_len: usize,
) -> i8 {
    let result = panic::catch_unwind(|| unsafe {
        let public_key = Vec::from_raw_parts(
            encoded_public_key as *mut u8,
            encoded_public_key_len,
            encoded_public_key_len,
        );
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            encoded_message_hash_len,
            encoded_message_hash_len,
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
    public_key: &mut PublicKey,
    encoded_message_hash: *const c_char,
    encoded_message_hash_len: usize,
    encoded_signature: *const c_char,
    encoded_signature_len: usize,
) -> i8 {
    if public_key.public_key_len < PUBLIC_KEY_SIZE_WITHOUT_PREFIX {
        return FAILURE;
    }
    let result = panic::catch_unwind(|| unsafe {
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            encoded_message_hash_len,
            encoded_message_hash_len,
        );
        let signature_data = Vec::from_raw_parts(
            encoded_signature as *mut u8,
            encoded_signature_len,
            encoded_signature_len,
        );
        let pk = match SIGNATURE_SECP256K1
            .recover_public_key(&message_hash, &signature_data)
        {
            Ok(v) => v,
            Err(_) => {
                std::mem::forget(message_hash);
                std::mem::forget(signature_data);
                return FAILURE;
            },
        };
        std::mem::forget(message_hash);
        std::mem::forget(signature_data);
        let public_key_slice = std::slice::from_raw_parts_mut(
            public_key.public_key as *mut u8,
            public_key.public_key_len,
        );
        public_key_slice[0..PUBLIC_KEY_SIZE_WITHOUT_PREFIX]
            .copy_from_slice(&pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX]);
        std::mem::forget(public_key_slice);
        SUCCESS
    });
    c_safe_return_ret_code!(result)
}

// SM2 implementation.
#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_gen_binary_key_pair'.
pub extern "C" fn wedpr_sm2_gen_binary_key_pair(
    key_pair: &mut KeyPairData,
) -> i8 {
    if key_pair.public_key_len < PUBLIC_KEY_SIZE_WITHOUT_PREFIX {
        return FAILURE;
    }
    if key_pair.private_key_len < PRIVATE_KEY_SIZE {
        return FAILURE;
    }
    let result = panic::catch_unwind(|| unsafe {
        let (public_key, private_key) = SIGNATURE_SM2.generate_keypair();
        let pk = std::slice::from_raw_parts_mut(
            key_pair.public_key as *mut u8,
            key_pair.public_key_len,
        );
        let sk = std::slice::from_raw_parts_mut(
            key_pair.private_key as *mut u8,
            key_pair.private_key_len,
        );
        pk[0..PUBLIC_KEY_SIZE_WITHOUT_PREFIX]
            .copy_from_slice(&public_key[1..PUBLIC_KEY_SIZE_WITH_PREFIX]);
        sk[0..PRIVATE_KEY_SIZE].copy_from_slice(&private_key.as_ref());
        std::mem::forget(pk);
        std::mem::forget(sk);
        SUCCESS
    });
    c_safe_return_ret_code!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_derive_binary_public_key'.
pub extern "C" fn wedpr_sm2_derive_binary_public_key(
    public_key: &mut PublicKey,
    encoded_private_key: *const c_char,
    encoded_private_key_len: usize,
) -> i8 {
    // check the input length
    if public_key.public_key_len < PUBLIC_KEY_SIZE_WITHOUT_PREFIX {
        return FAILURE;
    }
    let result = panic::catch_unwind(|| unsafe {
        let sk = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            encoded_private_key_len,
            encoded_private_key_len,
        );
        let pk = match SIGNATURE_SM2.derive_public_key(&sk) {
            Ok(v) => v,
            Err(_) => {
                std::mem::forget(sk);
                return FAILURE;
            },
        };
        std::mem::forget(sk);
        let public_key_slice = std::slice::from_raw_parts_mut(
            public_key.public_key as *mut u8,
            public_key.public_key_len,
        );
        public_key_slice[0..PUBLIC_KEY_SIZE_WITHOUT_PREFIX]
            .copy_from_slice(&pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX]);
        std::mem::forget(public_key_slice);
        SUCCESS
    });
    c_safe_return_ret_code!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign_binary'.
pub extern "C" fn wedpr_sm2_sign_binary(
    signature_result: &mut SignatureResult,
    encoded_private_key: *const c_char,
    encoded_private_key_len: usize,
    encoded_message_hash: *const c_char,
    encoded_message_hash_len: usize,
) -> i8 {
    if signature_result.signature_len < SM2_SIGNATURE_DATA_LENGTH {
        return FAILURE;
    }
    let result = panic::catch_unwind(|| unsafe {
        let private_key = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            encoded_private_key_len,
            encoded_private_key_len,
        );
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            encoded_message_hash_len,
            encoded_message_hash_len,
        );
        let signature = match SIGNATURE_SM2.sign(&private_key, &message_hash) {
            Ok(v) => v,
            Err(_) => {
                std::mem::forget(private_key);
                std::mem::forget(message_hash);
                return FAILURE;
            },
        };
        std::mem::forget(private_key);
        std::mem::forget(message_hash);
        let signature_result_slice = std::slice::from_raw_parts_mut(
            signature_result.signature_data as *mut u8,
            signature_result.signature_len,
        );
        signature_result_slice[0..SM2_SIGNATURE_DATA_LENGTH]
            .copy_from_slice(&signature);
        std::mem::forget(signature_result_slice);
        SUCCESS
    });
    c_safe_return_ret_code!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign_binary_fast'.
pub extern "C" fn wedpr_sm2_sign_binary_fast(
    signature_result: &mut SignatureResult,
    encoded_private_key: *const c_char,
    encoded_private_key_len: usize,
    encoded_public_key: *const c_char,
    encoded_public_key_len: usize,
    encoded_message_hash: *const c_char,
    encoded_message_hash_len: usize,
) -> i8 {
    if signature_result.signature_len < SM2_SIGNATURE_DATA_LENGTH {
        return FAILURE;
    }
    let result = panic::catch_unwind(|| unsafe {
        let private_key = Vec::from_raw_parts(
            encoded_private_key as *mut u8,
            encoded_private_key_len,
            encoded_private_key_len,
        );
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            encoded_message_hash_len,
            encoded_message_hash_len,
        );
        let public_key = Vec::from_raw_parts(
            encoded_public_key as *mut u8,
            encoded_public_key_len,
            encoded_public_key_len,
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
                return FAILURE;
            },
        };
        std::mem::forget(private_key);
        std::mem::forget(message_hash);
        std::mem::forget(public_key);
        let signature_result_slice = std::slice::from_raw_parts_mut(
            signature_result.signature_data as *mut u8,
            signature_result.signature_len,
        );
        signature_result_slice[0..SM2_SIGNATURE_DATA_LENGTH]
            .copy_from_slice(&signature);
        std::mem::forget(signature_result_slice);
        SUCCESS
    });
    c_safe_return_ret_code!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_verify_binary'.
pub extern "C" fn wedpr_sm2_verify_binary(
    encoded_public_key: *const c_char,
    encoded_public_key_len: usize,
    encoded_message_hash: *const c_char,
    encoded_message_hash_len: usize,
    encoded_signature: *const c_char,
    signature_len: usize,
) -> i8 {
    let result = panic::catch_unwind(|| unsafe {
        let public_key = Vec::from_raw_parts(
            encoded_public_key as *mut u8,
            encoded_public_key_len,
            encoded_public_key_len,
        );
        let message_hash = Vec::from_raw_parts(
            encoded_message_hash as *mut u8,
            encoded_message_hash_len,
            encoded_message_hash_len,
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
