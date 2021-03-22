// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Hash function wrappers.

#![cfg(all(feature = "wedpr_f_hash_keccak256", feature = "wedpr_f_hash_sm3"))]

use wedpr_l_utils::traits::Hash;

#[cfg(feature = "wedpr_f_hash_keccak256")]
use crate::config::HASH_KECCAK256;

#[cfg(feature = "wedpr_f_hash_sm3")]
use crate::config::HASH_SM3;

use libc::c_char;
use std::{ffi::CString, panic, ptr};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes,
};

// Keccak256 implementation.

#[cfg(feature = "wedpr_f_hash_keccak256")]
#[no_mangle]
/// C interface for 'wedpr_keccak256_hash'.
// TODO: Add wedpr_keccak256_hash_utf8 to allow non-encoded UTF8 input.
pub extern "C" fn wedpr_keccak256_hash(
    encoded_message: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let message = c_safe_c_char_pointer_to_bytes!(encoded_message);

        let msg_hash = bytes_to_string(&HASH_KECCAK256.hash(&message));

        c_safe_string_to_c_char_pointer!(msg_hash)
    });
    c_safe_return!(result)
}

// SM3 implementation.

#[cfg(feature = "wedpr_f_hash_sm3")]
#[no_mangle]
/// C interface for 'wedpr_sm3_hash'.
pub extern "C" fn wedpr_sm3_hash(
    encoded_message: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let message = c_safe_c_char_pointer_to_bytes!(encoded_message);

        let msg_hash = bytes_to_string(&HASH_SM3.hash(&message));
        c_safe_string_to_c_char_pointer!(msg_hash)
    });
    c_safe_return!(result)
}
