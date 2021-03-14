// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Hash function wrappers.

#![cfg(all(feature = "wedpr_f_hash_keccak256", feature = "wedpr_f_hash_sm3"))]
use wedpr_l_utils::traits::Hash;

#[cfg(feature = "wedpr_f_hash_keccak256")]
use crate::config::HASH_KECCAK256;

#[cfg(feature = "wedpr_f_hash_sm3")]
use crate::config::HASH_SM3;

use libc::c_char;
const HASH_DATA_SIZE: usize = 32;
pub const SUCCESS: i8 = 0;
pub const FAILURE: i8 = -1;

// Rust to c/c++
#[repr(C)]
pub struct HashResult {
    data: *mut c_char,
    len: usize,
}

// Keccak256 implementation.
#[cfg(feature = "wedpr_f_hash_keccak256")]
#[no_mangle]
/// C interface for 'wedpr_keccak256_hash_binary'.
pub extern "C" fn wedpr_keccak256_hash_binary(
    hash_result: &mut HashResult,
    encoded_message: *const c_char,
    message_len: usize,
) -> i8 {
    unsafe {
        if hash_result.len < HASH_DATA_SIZE {
            return FAILURE;
        }
        // Note: Since encode_message is an object passed in by C/CPP, it should
        // not be released
        let input_message = Vec::from_raw_parts(
            encoded_message as *mut u8,
            message_len,
            message_len,
        );
        let hash_data = HASH_KECCAK256.hash(&input_message);
        std::mem::forget(input_message);
        let hash_data_slice = std::slice::from_raw_parts_mut(
            hash_result.data as *mut u8,
            hash_result.len,
        );
        hash_data_slice.copy_from_slice(&hash_data);
        std::mem::forget(hash_data_slice);
        SUCCESS
    }
}

// SM3 implementation.
#[cfg(feature = "wedpr_f_hash_sm3")]
#[no_mangle]
/// C interface for 'wedpr_sm3_hash_binary'.
pub extern "C" fn wedpr_sm3_hash_binary(
    hash_result: &mut HashResult,
    encoded_message: *const c_char,
    message_len: usize,
) -> i8 {
    unsafe {
        if hash_result.len < HASH_DATA_SIZE {
            return FAILURE;
        }
        let input_message = Vec::from_raw_parts(
            encoded_message as *mut u8,
            message_len,
            message_len,
        );
        let hash_data = HASH_SM3.hash(&input_message);
        std::mem::forget(input_message);
        let hash_data_slice = std::slice::from_raw_parts_mut(
            hash_result.data as *mut u8,
            hash_result.len,
        );
        hash_data_slice.copy_from_slice(&hash_data);
        std::mem::forget(hash_data_slice);
        SUCCESS
    }
}
