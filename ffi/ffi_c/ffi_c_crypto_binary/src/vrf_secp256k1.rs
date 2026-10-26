// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! VRF function wrappers.

#![cfg(not(tarpaulin_include))]
#![cfg(feature = "wedpr_f_vrf_secp256k1")]

use wedpr_ffi_common::utils::{
    c_read_raw_pointer, c_write_raw_pointer, CInputBuffer, COutputBuffer,
    FAILURE, SUCCESS,
};

#[cfg(feature = "wedpr_f_vrf_secp256k1")]
use wedpr_l_crypto_vrf_secp256k1::WedprSecp256k1Vrf;
use wedpr_l_utils::traits::Vrf;

// secp256k1 implementation.

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_derive_public_key'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_derive_public_key(
    raw_private_key: *const CInputBuffer,
    output_public_key: *mut COutputBuffer,
) -> i8 {
    let raw_private_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_private_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_private_key = &raw_private_key;
    let output_public_key =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_public_key)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    let private_key = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let public_key = WedprSecp256k1Vrf::derive_public_key(&private_key);

    if c_write_raw_pointer(&public_key, output_public_key).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_prove_utf8'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_prove_utf8(
    raw_private_key: *const CInputBuffer,
    raw_utf8_message: *const CInputBuffer,
    output_proof: *mut COutputBuffer,
) -> i8 {
    let raw_private_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_private_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_private_key = &raw_private_key;
    let raw_utf8_message =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_utf8_message) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_utf8_message = &raw_utf8_message;
    let output_proof =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_proof) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    let private_key = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message = match c_read_raw_pointer(raw_utf8_message) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = WedprSecp256k1Vrf::prove(&private_key, &message);

    let proof = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&proof.encode_proof(), output_proof).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_prove_fast_utf8'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_prove_fast_utf8(
    raw_private_key: *const CInputBuffer,
    raw_public_key: *const CInputBuffer,
    raw_utf8_message: *const CInputBuffer,
    output_proof: *mut COutputBuffer,
) -> i8 {
    let raw_private_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_private_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_private_key = &raw_private_key;
    let raw_public_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_public_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_public_key = &raw_public_key;
    let raw_utf8_message =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_utf8_message) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_utf8_message = &raw_utf8_message;
    let output_proof =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_proof) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    let private_key = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let public_key = match c_read_raw_pointer(raw_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message = match c_read_raw_pointer(raw_utf8_message) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result =
        WedprSecp256k1Vrf::prove_fast(&private_key, &public_key, &message);

    let proof = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&proof.encode_proof(), output_proof).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_verify_utf8'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_verify_utf8(
    raw_public_key: *const CInputBuffer,
    raw_utf8_message: *const CInputBuffer,
    raw_proof: *const CInputBuffer,
) -> i8 {
    let raw_public_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_public_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_public_key = &raw_public_key;
    let raw_utf8_message =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_utf8_message) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_utf8_message = &raw_utf8_message;
    let raw_proof =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_proof) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_proof = &raw_proof;

    let proof_bytes = match c_read_raw_pointer(raw_proof) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let public_key = match c_read_raw_pointer(raw_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message = match c_read_raw_pointer(raw_utf8_message) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let proof = match WedprSecp256k1Vrf::decode_proof(&proof_bytes) {
        Ok(v) => v,
        Err(_) => {
            return FAILURE;
        },
    };

    let result = proof.verify(&public_key, &message);

    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_proof_to_hash'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_proof_to_hash(
    raw_proof: *const CInputBuffer,
    output_hash: *mut COutputBuffer,
) -> i8 {
    let raw_proof =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_proof) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_proof = &raw_proof;
    let output_hash =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_hash) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    let proof_bytes = match c_read_raw_pointer(raw_proof) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let proof = match WedprSecp256k1Vrf::decode_proof(&proof_bytes) {
        Ok(v) => v,
        Err(_) => {
            return FAILURE;
        },
    };

    let result = proof.proof_to_hash();

    let hash = match result {
        Ok(v) => v,
        Err(_) => {
            return FAILURE;
        },
    };
    if c_write_raw_pointer(&hash, output_hash).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_is_valid_public_key'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_is_valid_public_key(
    raw_public_key: *const CInputBuffer,
) -> i8 {
    let raw_public_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_public_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_public_key = &raw_public_key;

    let public_key = match c_read_raw_pointer(raw_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = WedprSecp256k1Vrf::is_valid_public_key(&public_key);

    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}
