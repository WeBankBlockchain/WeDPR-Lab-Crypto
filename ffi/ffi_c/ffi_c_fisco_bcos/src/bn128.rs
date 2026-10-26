// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! BN128 curve function wrappers.

#![cfg(not(tarpaulin_include))]

use wedpr_ffi_common::utils::{
    c_read_raw_pointer, c_write_raw_pointer, CInputBuffer, COutputBuffer,
    FAILURE, SUCCESS,
};
use wedpr_third_party_fisco_bcos;

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn native_bn128_checks_buffers_and_preserves_outputs_on_failure() {
        type Operation =
            unsafe extern "C" fn(*const CInputBuffer, *mut COutputBuffer) -> i8;
        for (operation, required) in [
            (wedpr_fb_alt_bn128_g1_add as Operation, 64),
            (wedpr_fb_alt_bn128_g1_mul as Operation, 64),
            (wedpr_fb_alt_bn128_pairing_product as Operation, 32),
        ] {
            let data = [0u8; 192];
            let input = CInputBuffer {
                data: data.as_ptr().cast(),
                len: data.len(),
            };
            let mut bytes = [99u8; 64];
            let mut output = COutputBuffer {
                data: bytes.as_mut_ptr().cast(),
                len: required - 1,
            };
            unsafe {
                assert_eq!(operation(&input, &mut output), FAILURE);
                assert_eq!(output.len, required);
                assert_eq!(bytes, [99u8; 64]);
                assert_eq!(operation(std::ptr::null(), &mut output), FAILURE);
                assert_eq!(operation(&input, std::ptr::null_mut()), FAILURE);
                let invalid_data = [1u8; 192];
                let invalid = CInputBuffer {
                    data: invalid_data.as_ptr().cast(),
                    len: invalid_data.len(),
                };
                assert_eq!(operation(&invalid, &mut output), FAILURE);
                assert_eq!(bytes, [99u8; 64]);
                assert_eq!(operation(&input, &mut output), SUCCESS);
                assert_eq!(output.len, required);
                assert!(bytes[..required - 1].iter().all(|byte| *byte == 0));
                assert_eq!(
                    bytes[required - 1],
                    if required == 32 { 1 } else { 0 }
                );
                assert_eq!(data, [0u8; 192]);
            }
        }
    }
}

// Bn128 implementation.
#[no_mangle]
/// C interface for 'wedpr_fb_alt_bn128_g1_add'.
pub unsafe extern "C" fn wedpr_fb_alt_bn128_g1_add(
    raw_pairing_data: *const CInputBuffer,
    output_point: *mut COutputBuffer,
) -> i8 {
    let raw_pairing_data =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_pairing_data) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_pairing_data = &raw_pairing_data;
    let output_point =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_point) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let pairing = match c_read_raw_pointer(raw_pairing_data) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = wedpr_third_party_fisco_bcos::alt_bn128_g1_add(&pairing);

    let point = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&point, output_point).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_fb_alt_bn128_g1_mul'.
pub unsafe extern "C" fn wedpr_fb_alt_bn128_g1_mul(
    raw_pairing_data: *const CInputBuffer,
    output_point: *mut COutputBuffer,
) -> i8 {
    let raw_pairing_data =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_pairing_data) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_pairing_data = &raw_pairing_data;
    let output_point =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_point) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let pairing = match c_read_raw_pointer(raw_pairing_data) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = wedpr_third_party_fisco_bcos::alt_bn128_g1_mul(&pairing);

    let point = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&point, output_point).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_fb_alt_bn128_pairing_product'.
pub unsafe extern "C" fn wedpr_fb_alt_bn128_pairing_product(
    raw_pairing_data: *const CInputBuffer,
    output_point: *mut COutputBuffer,
) -> i8 {
    let raw_pairing_data =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_pairing_data) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_pairing_data = &raw_pairing_data;
    let output_point =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_point) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    // Note: Since encode_message is an object passed in by C/C++, it should
    // not be released
    let pairing = match c_read_raw_pointer(raw_pairing_data) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result =
        wedpr_third_party_fisco_bcos::alt_bn128_pairing_product(&pairing);

    let point = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&point, output_point).is_err() {
        return FAILURE;
    }
    SUCCESS
}
