// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Bn128 precompile function wrappers.

use wedpr_ffi_common::utils::{
    c_pointer_to_rust_bytes, set_c_pointer, CPointInput, CPointOutput, FAILURE,
    SUCCESS,
};
use wedpr_third_party_fisco_bcos;

// Bn128 implementation.
#[no_mangle]
/// C interface for 'wedpr_alt_bn128_g1_add'.
pub unsafe extern "C" fn wedpr_alt_bn128_g1_add(
    points_input: &CPointInput,
    point_result: &mut CPointOutput,
) -> i8 {
    // Note: Since encode_message is an object passed in by C/CPP, it should
    // not be released
    let input = c_pointer_to_rust_bytes(points_input);
    let result = wedpr_third_party_fisco_bcos::alt_bn128_g1_add(&input);
    std::mem::forget(input);
    let output = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&output, point_result);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_alt_bn128_g1_mul'.
pub unsafe extern "C" fn wedpr_alt_bn128_g1_mul(
    points_input: &CPointInput,
    point_result: &mut CPointOutput,
) -> i8 {
    // Note: Since encode_message is an object passed in by C/CPP, it should
    // not be released
    let input = c_pointer_to_rust_bytes(points_input);
    let result = wedpr_third_party_fisco_bcos::alt_bn128_g1_mul(&input);
    std::mem::forget(input);
    let output = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&output, point_result);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_alt_bn128_pairing_product'.
pub unsafe extern "C" fn wedpr_alt_bn128_pairing_product(
    points_input: &CPointInput,
    point_result: &mut CPointOutput,
) -> i8 {
    // Note: Since encode_message is an object passed in by C/CPP, it should
    // not be released
    let input = c_pointer_to_rust_bytes(points_input);
    let result =
        wedpr_third_party_fisco_bcos::alt_bn128_pairing_product(&input);
    std::mem::forget(input);
    let output = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&output, point_result);
    SUCCESS
}
