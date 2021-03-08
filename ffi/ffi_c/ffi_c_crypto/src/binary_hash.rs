// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Hash function wrappers.

#![cfg(all(feature = "wedpr_f_hash_keccak256", feature = "wedpr_f_hash_sm3"))]

use wedpr_l_utils::traits::Hash;

#[cfg(feature = "wedpr_f_hash_keccak256")]
use crate::config::HASH_KECCAK256;

#[cfg(feature = "wedpr_f_hash_sm3")]
use crate::config::HASH_SM3;

use libc::c_char;
// Keccak256 implementation.
#[cfg(feature = "wedpr_f_hash_keccak256")]
#[no_mangle]
/// C interface for 'wedpr_keccak256_hash_binary'.
pub extern "C" fn wedpr_keccak256_hash_binary(
    encoded_message: *const c_char,
    message_len: usize,
) -> *mut c_char
{
    unsafe {
        // Note: Since encode_message is an object passed in by C/CPP, it should
        // not be released
        let input_message = Vec::from_raw_parts(
            encoded_message as *mut u8,
            message_len,
            message_len,
        );
        let hash_result = HASH_KECCAK256.hash(&input_message);
        std::mem::forget(input_message);
        // The ownership of hash_result has not been changed
        return hash_result.as_ptr() as *mut c_char;
    }
}

// SM3 implementation.
#[cfg(feature = "wedpr_f_hash_sm3")]
#[no_mangle]
/// C interface for 'wedpr_sm3_hash_binary'.
pub extern "C" fn wedpr_sm3_hash_binary(
    encoded_message: *const c_char,
    message_len: usize,
) -> *mut c_char
{
    unsafe {
        let input_message = Vec::from_raw_parts(
            encoded_message as *mut u8,
            message_len,
            message_len,
        );
        let hash_result = HASH_SM3.hash(&input_message);
        std::mem::forget(input_message);
        return hash_result.as_ptr() as *mut c_char;
    }
}
