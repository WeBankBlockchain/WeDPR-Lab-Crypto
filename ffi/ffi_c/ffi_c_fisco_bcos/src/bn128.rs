// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! BN128 curve function wrappers.

use wedpr_ffi_common::utils::{
    c_read_raw_pointer, c_write_raw_pointer, CInputBuffer, COutputBuffer,
    FAILURE, SUCCESS,
};
use wedpr_third_party_fisco_bcos;

// Bn128 implementation.
#[no_mangle]
/// C interface for 'wedpr_fb_alt_bn128_g1_add'.
pub unsafe extern "C" fn wedpr_fb_alt_bn128_g1_add(
    raw_pairing_data: &CInputBuffer,
    output_point: &mut COutputBuffer,
) -> i8 {
    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let pairing = c_read_raw_pointer(raw_pairing_data);

    let result = wedpr_third_party_fisco_bcos::alt_bn128_g1_add(&pairing);
    std::mem::forget(pairing);
    let point = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&point, output_point);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_fb_alt_bn128_g1_mul'.
pub unsafe extern "C" fn wedpr_fb_alt_bn128_g1_mul(
    raw_pairing_data: &CInputBuffer,
    output_point: &mut COutputBuffer,
) -> i8 {
    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let pairing = c_read_raw_pointer(raw_pairing_data);

    let result = wedpr_third_party_fisco_bcos::alt_bn128_g1_mul(&pairing);
    std::mem::forget(pairing);
    let point = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&point, output_point);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_fb_alt_bn128_pairing_product'.
pub unsafe extern "C" fn wedpr_fb_alt_bn128_pairing_product(
    raw_pairing_data: &CInputBuffer,
    output_point: &mut COutputBuffer,
) -> i8 {
    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let pairing = c_read_raw_pointer(raw_pairing_data);

    let result =
        wedpr_third_party_fisco_bcos::alt_bn128_pairing_product(&pairing);
    std::mem::forget(pairing);
    let point = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&point, output_point);
    SUCCESS
}
