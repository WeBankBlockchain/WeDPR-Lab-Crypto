// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! VRF function wrappers.

#![cfg(not(tarpaulin_include))]
#![cfg(feature = "wedpr_f_vrf_secp256k1")]

use libc::c_char;
use std::{ffi::CString, panic, ptr};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE,
    SUCCESS,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE,
    SUCCESS,
};

#[cfg(feature = "wedpr_f_vrf_secp256k1")]
use wedpr_l_crypto_vrf_secp256k1::WedprSecp256k1Vrf;
use wedpr_l_utils::{tool::string_to_bytes_utf8, traits::Vrf};

// secp256k1 implementation.

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_derive_public_key'.
pub extern "C" fn wedpr_secp256k1_vrf_derive_public_key(
    encoded_private_key: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);

        let encrypt_data = WedprSecp256k1Vrf::derive_public_key(&private_key);
        c_safe_bytes_to_c_char_pointer!(&encrypt_data)
    });
    c_safe_return!(result)
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_prove_utf8'.
pub extern "C" fn wedpr_secp256k1_vrf_prove_utf8(
    encoded_private_key: *const c_char,
    utf8_message: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let message = c_safe_c_char_pointer_to_bytes_utf8!(utf8_message);

        let proof = match WedprSecp256k1Vrf::prove(&private_key, &message) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&proof.encode_proof())
    });
    c_safe_return!(result)
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_prove_fast_utf8'.
pub extern "C" fn wedpr_secp256k1_vrf_prove_fast_utf8(
    encoded_private_key: *const c_char,
    encoded_public_key: *const c_char,
    utf8_message: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let public_key = c_safe_c_char_pointer_to_bytes!(encoded_public_key);
        let message = c_safe_c_char_pointer_to_bytes_utf8!(utf8_message);

        let proof = match WedprSecp256k1Vrf::prove_fast(
            &private_key,
            &public_key,
            &message,
        ) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&proof.encode_proof())
    });
    c_safe_return!(result)
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_verify_utf8'.
pub extern "C" fn wedpr_secp256k1_vrf_verify_utf8(
    encoded_public_key: *const c_char,
    utf8_message: *const c_char,
    encoded_proof: *const c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_public_key,
            FAILURE
        );
        let message = c_safe_c_char_pointer_to_bytes_utf8_with_error_value!(
            utf8_message,
            FAILURE
        );
        let proof_bytes = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_proof,
            FAILURE
        );

        let proof = match WedprSecp256k1Vrf::decode_proof(&proof_bytes) {
            Ok(v) => v,
            Err(_) => {
                return FAILURE;
            },
        };
        match proof.verify(&public_key, &message) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_proof_to_hash'.
pub extern "C" fn wedpr_secp256k1_vrf_proof_to_hash(
    encoded_proof: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let proof_bytes = c_safe_c_char_pointer_to_bytes!(encoded_proof);
        let proof = match WedprSecp256k1Vrf::decode_proof(&proof_bytes) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            },
        };

        let hash_bytes = match proof.proof_to_hash() {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&hash_bytes)
    });
    c_safe_return!(result)
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_is_valid_public_key'.
pub extern "C" fn wedpr_secp256k1_vrf_is_valid_public_key(
    encoded_public_key: *const c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_public_key,
            FAILURE
        );

        match WedprSecp256k1Vrf::is_valid_public_key(&public_key) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}
