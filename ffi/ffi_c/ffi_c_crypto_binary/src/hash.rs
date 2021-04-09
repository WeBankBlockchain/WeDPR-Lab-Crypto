// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Hash function wrappers.

#![cfg(all(
    feature = "wedpr_f_hash_keccak256",
    feature = "wedpr_f_hash_sm3",
    feature = "wedpr_f_hash_sha3",
    feature = "wedpr_f_hash_ripemd160",
    feature = "wedpr_f_hash_blake2b"
))]

use wedpr_l_utils::traits::Hash;

#[cfg(feature = "wedpr_f_hash_keccak256")]
use crate::config::HASH_KECCAK256;

#[cfg(feature = "wedpr_f_hash_sm3")]
use crate::config::HASH_SM3;

#[cfg(feature = "wedpr_f_hash_sha3")]
use crate::config::HASH_SHA3_256;

#[cfg(feature = "wedpr_f_hash_ripemd160")]
use crate::config::HASH_RIPEMD160;

#[cfg(feature = "wedpr_f_hash_blake2b")]
use crate::config::HASH_BLAKE2B;

use wedpr_ffi_common::utils::{
    c_read_raw_pointer, c_write_raw_pointer, CInputBuffer, COutputBuffer,
    FAILURE, SUCCESS,
};

const HASH_256_DATA_SIZE: usize = 32;

// Keccak256 implementation.
#[cfg(feature = "wedpr_f_hash_keccak256")]
#[no_mangle]
/// C interface for 'wedpr_keccak256_hash'.
pub unsafe extern "C" fn wedpr_keccak256_hash(
    raw_message: &CInputBuffer,
    output_hash: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(output_hash, HASH_256_DATA_SIZE);

    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let message = c_read_raw_pointer(raw_message);

    let hash_data = HASH_KECCAK256.hash(&message);
    std::mem::forget(message);
    c_write_raw_pointer(&hash_data, output_hash);
    SUCCESS
}

// SM3 implementation.

#[cfg(feature = "wedpr_f_hash_sm3")]
#[no_mangle]
/// C interface for 'wedpr_sm3_hash'.
pub unsafe extern "C" fn wedpr_sm3_hash(
    raw_message: &CInputBuffer,
    output_hash: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(output_hash, HASH_256_DATA_SIZE);
    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let message = c_read_raw_pointer(raw_message);

    let hash_data = HASH_SM3.hash(&message);
    std::mem::forget(message);
    c_write_raw_pointer(&hash_data, output_hash);
    SUCCESS
}

// RIPEMD160 implementation.

#[cfg(feature = "wedpr_f_hash_ripemd160")]
#[no_mangle]
/// C interface for 'wedpr_ripemd160_hash'.
pub unsafe extern "C" fn wedpr_ripemd160_hash(
    raw_message: &CInputBuffer,
    output_hash: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(output_hash, HASH_256_DATA_SIZE);
    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let message = c_read_raw_pointer(raw_message);

    let hash_data = HASH_RIPEMD160.hash(&message);
    std::mem::forget(message);
    c_write_raw_pointer(&hash_data, output_hash);
    SUCCESS
}

// SHA3 implementation.

#[cfg(feature = "wedpr_f_hash_sha3")]
#[no_mangle]
/// C interface for 'wedpr_sha3_hash'.
pub unsafe extern "C" fn wedpr_sha3_hash(
    raw_message: &CInputBuffer,
    output_hash: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(output_hash, HASH_256_DATA_SIZE);
    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let message = c_read_raw_pointer(raw_message);

    let hash_data = HASH_SHA3_256.hash(&message);
    std::mem::forget(message);
    c_write_raw_pointer(&hash_data, output_hash);
    SUCCESS
}

// BLAKE2B implementation.

#[cfg(feature = "wedpr_f_hash_blake2b")]
#[no_mangle]
/// C interface for 'wedpr_blake2b_hash'.
pub unsafe extern "C" fn wedpr_blake2b_hash(
    message_input: &CInputBuffer,
    output_hash: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(output_hash, HASH_256_DATA_SIZE);
    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let message = c_read_raw_pointer(message_input);

    let hash_data = HASH_BLAKE2B.hash(&message);
    std::mem::forget(message);
    c_write_raw_pointer(&hash_data, output_hash);
    SUCCESS
}
