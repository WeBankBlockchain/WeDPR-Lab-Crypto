// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Hash function wrappers.

#![cfg(all(feature = "wedpr_f_hash_keccak256", feature = "wedpr_f_hash_sm3"))]

use wedpr_l_utils::traits::Hash;

#[cfg(feature = "wedpr_f_hash_keccak256")]
use crate::config::HASH_KECCAK256;

#[cfg(feature = "wedpr_f_hash_sm3")]
use crate::config::HASH_SM3;

#[cfg(feature = "wedpr_f_hash_sha3")]
use crate::config::HASH_SHA3;

#[cfg(feature = "wedpr_f_hash_ripemd160")]
use crate::config::HASH_RIPEMD160;

#[cfg(feature = "wedpr_f_hash_blake2b")]
use crate::config::HASH_BLAKE2B;

use wedpr_ffi_common::utils::{
    c_pointer_to_rust_bytes, set_c_pointer, CPointInput, CPointOutput, FAILURE,
    SUCCESS,
};
const HASH_256_DATA_SIZE: usize = 32;

// Keccak256 implementation.
#[cfg(feature = "wedpr_f_hash_keccak256")]
#[no_mangle]
/// C interface for 'wedpr_keccak256_hash'.
pub unsafe extern "C" fn wedpr_keccak256_hash(
    encoded_message: &CPointInput,
    hash_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(hash_result, HASH_256_DATA_SIZE);

    // Note: Since encode_message is an object passed in by C/CPP, it should
    // not be released
    let input_message = c_pointer_to_rust_bytes(encoded_message);
    let hash_data = HASH_KECCAK256.hash(&input_message);
    std::mem::forget(input_message);
    set_c_pointer(&hash_data, hash_result);
    SUCCESS
}

// SM3 implementation.

#[cfg(feature = "wedpr_f_hash_sm3")]
#[no_mangle]
/// C interface for 'wedpr_sm3_hash'.
pub unsafe extern "C" fn wedpr_sm3_hash(
    encoded_message: &CPointInput,
    hash_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(hash_result, HASH_256_DATA_SIZE);
    // Note: Since encode_message is an object passed in by C/CPP, it should
    // not be released
    let input_message = c_pointer_to_rust_bytes(encoded_message);
    let hash_data = HASH_SM3.hash(&input_message);
    std::mem::forget(input_message);
    set_c_pointer(&hash_data, hash_result);
    SUCCESS
}

// ripemd160 implementation.

#[cfg(feature = "wedpr_f_hash_ripemd160")]
#[no_mangle]
/// C interface for 'wedpr_ripemd160_hash'.
pub unsafe extern "C" fn wedpr_ripemd160_hash(
    encoded_message: &CPointInput,
    hash_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(hash_result, HASH_256_DATA_SIZE);
    // Note: Since encode_message is an object passed in by C/CPP, it should
    // not be released
    let input_message = c_pointer_to_rust_bytes(encoded_message);
    let hash_data = HASH_RIPEMD160.hash(&input_message);
    std::mem::forget(input_message);
    set_c_pointer(&hash_data, hash_result);
    SUCCESS
}

// SHA3 implementation.

#[cfg(feature = "wedpr_f_hash_sha3")]
#[no_mangle]
/// C interface for 'wedpr_sha3_hash'.
pub unsafe extern "C" fn wedpr_sha3_hash(
    encoded_message: &CPointInput,
    hash_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(hash_result, HASH_256_DATA_SIZE);
    // Note: Since encode_message is an object passed in by C/CPP, it should
    // not be released
    let input_message = c_pointer_to_rust_bytes(encoded_message);
    let hash_data = HASH_SHA3.hash(&input_message);
    std::mem::forget(input_message);
    set_c_pointer(&hash_data, hash_result);
    SUCCESS
}

// BLAKE2B implementation.

#[cfg(feature = "wedpr_f_hash_blake2b")]
#[no_mangle]
/// C interface for 'wedpr_blake2b_hash'.
pub unsafe extern "C" fn wedpr_blake2b_hash(
    encoded_message: &CPointInput,
    hash_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(hash_result, HASH_256_DATA_SIZE);
    // Note: Since encode_message is an object passed in by C/CPP, it should
    // not be released
    let input_message = c_pointer_to_rust_bytes(encoded_message);
    let hash_data = HASH_BLAKE2B.hash(&input_message);
    std::mem::forget(input_message);
    set_c_pointer(&hash_data, hash_result);
    SUCCESS
}
