//! Library of FFI of wedpr_crypto wrapper functions, targeting C/C++
//! compatible architectures (including iOS), with fast binary interfaces.
// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use ecc_edwards25519::{hash_to_curve, point_scalar_multi, random_scalar};

use wedpr_ffi_common::utils::{c_read_raw_pointer, c_write_raw_pointer, CInputBuffer, COutputBuffer, FAILURE, SUCCESS};

#[no_mangle]
/// C interface for 'wedpr_random_scalar'.
pub unsafe extern "C" fn wedpr_random_scalar(
    output_ciphertext: &mut COutputBuffer,
) -> i8 {
    let random_scalar = random_scalar();
    c_write_raw_pointer(&random_scalar, output_ciphertext);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_hash_to_curve'.
pub unsafe extern "C" fn wedpr_hash_to_curve(
    raw_message: &CInputBuffer,
    output_ciphertext: &mut COutputBuffer,
) -> i8 {
    let plaintext = c_read_raw_pointer(raw_message);
    let message = hash_to_curve(&plaintext);
    std::mem::forget(plaintext);
    c_write_raw_pointer(&message, output_ciphertext);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_point_scalar_multi'.
pub unsafe extern "C" fn wedpr_point_scalar_multi(
    raw_point: &CInputBuffer,
    raw_scalar: &CInputBuffer,
    output_ciphertext: &mut COutputBuffer,
) -> i8 {
    let num_point = c_read_raw_pointer(raw_point);
    let num_scalar = c_read_raw_pointer(raw_scalar);
    let result = point_scalar_multi(&num_point, &num_scalar);
    std::mem::forget(num_point);
    std::mem::forget(num_scalar);
    if result.is_empty() {
        return FAILURE;
    }
    c_write_raw_pointer(&result, output_ciphertext);
    SUCCESS
}
