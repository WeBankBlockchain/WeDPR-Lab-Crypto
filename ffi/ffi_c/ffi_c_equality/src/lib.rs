//! Library of FFI of wedpr_crypto wrapper functions, targeting C/C++
//! compatible architectures (including iOS), with fast binary interfaces.
// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

// C/C++ FFI: C-style interfaces will be generated.
#[macro_use]
extern crate wedpr_ffi_macros;

use wedpr_bls12_381;

use wedpr_ffi_common::utils::{
    c_read_raw_pointer, c_write_raw_pointer, CInputBuffer, COutputBuffer,
    FAILURE, SUCCESS,
};

#[no_mangle]
/// C interface for 'encrypt_message'.
pub unsafe extern "C" fn wedpr_pairing_bls128_encrypt_message(
    raw_plaintext: &CInputBuffer,
    output_ciphertext: &mut COutputBuffer,
) -> i8 {
    let plaintext = c_read_raw_pointer(raw_plaintext);

    let result = wedpr_bls12_381::encrypt_message(&plaintext);
    std::mem::forget(plaintext);
    c_write_raw_pointer(&result.to_bytes(), output_ciphertext);
    SUCCESS
}

#[no_mangle]
/// C interface for 'equality_test'.
pub unsafe extern "C" fn wedpr_pairing_bls128_equality_test(
    raw_cipher1: &CInputBuffer,
    raw_cipher2: &CInputBuffer,
) -> i8 {
    let cipher1 = c_read_raw_pointer(raw_cipher1);
    let cipher2 = c_read_raw_pointer(raw_cipher2);
    let cipher1_struct =
        match wedpr_bls12_381::WedprBls128Cipher::from_bytes(&cipher1) {
            Ok(v) => v,
            Err(_) => return FAILURE,
        };
    let cipher2_struct =
        match wedpr_bls12_381::WedprBls128Cipher::from_bytes(&cipher2) {
            Ok(v) => v,
            Err(_) => return FAILURE,
        };
    std::mem::forget(cipher1);
    std::mem::forget(cipher2);
    if wedpr_bls12_381::equality_test(&cipher1_struct, &cipher2_struct) {
        return SUCCESS;
    };
    FAILURE
}
