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
    raw_private_key: &CInputBuffer,
    output_public_key: &mut COutputBuffer,
) -> i8 {
    let private_key = c_read_raw_pointer(raw_private_key);

    let public_key = WedprSecp256k1Vrf::derive_public_key(&private_key);
    std::mem::forget(private_key);
    c_write_raw_pointer(&public_key, output_public_key);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_prove_utf8'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_prove_utf8(
    raw_private_key: &CInputBuffer,
    raw_utf8_message: &CInputBuffer,
    output_proof: &mut COutputBuffer,
) -> i8 {
    let private_key = c_read_raw_pointer(raw_private_key);
    let message = c_read_raw_pointer(raw_utf8_message);

    let result = WedprSecp256k1Vrf::prove(&private_key, &message);
    std::mem::forget(private_key);
    std::mem::forget(message);
    let proof = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&proof.encode_proof(), output_proof);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_prove_fast_utf8'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_prove_fast_utf8(
    raw_private_key: &CInputBuffer,
    raw_public_key: &CInputBuffer,
    raw_utf8_message: &CInputBuffer,
    output_proof: &mut COutputBuffer,
) -> i8 {
    let private_key = c_read_raw_pointer(raw_private_key);
    let public_key = c_read_raw_pointer(raw_public_key);
    let message = c_read_raw_pointer(raw_utf8_message);

    let result =
        WedprSecp256k1Vrf::prove_fast(&private_key, &public_key, &message);
    std::mem::forget(private_key);
    std::mem::forget(public_key);
    std::mem::forget(message);
    let proof = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&proof.encode_proof(), output_proof);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_verify_utf8'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_verify_utf8(
    raw_public_key: &CInputBuffer,
    raw_utf8_message: &CInputBuffer,
    raw_proof: &CInputBuffer,
) -> i8 {
    let proof_bytes = c_read_raw_pointer(raw_proof);
    let public_key = c_read_raw_pointer(raw_public_key);
    let message = c_read_raw_pointer(raw_utf8_message);

    let proof = match WedprSecp256k1Vrf::decode_proof(&proof_bytes) {
        Ok(v) => v,
        Err(_) => {
            std::mem::forget(proof_bytes);
            std::mem::forget(public_key);
            std::mem::forget(message);
            return FAILURE;
        },
    };

    let result = proof.verify(&public_key, &message);
    std::mem::forget(proof_bytes);
    std::mem::forget(public_key);
    std::mem::forget(message);
    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_proof_to_hash'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_proof_to_hash(
    raw_proof: &CInputBuffer,
    output_hash: &mut COutputBuffer,
) -> i8 {
    let proof_bytes = c_read_raw_pointer(raw_proof);
    let proof = match WedprSecp256k1Vrf::decode_proof(&proof_bytes) {
        Ok(v) => v,
        Err(_) => {
            std::mem::forget(proof_bytes);
            return FAILURE;
        },
    };

    let result = proof.proof_to_hash();
    std::mem::forget(proof_bytes);
    let hash = match result {
        Ok(v) => v,
        Err(_) => {
            return FAILURE;
        },
    };
    c_write_raw_pointer(&hash, output_hash);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_secp256k1_vrf_is_valid_public_key'.
pub unsafe extern "C" fn wedpr_secp256k1_vrf_is_valid_public_key(
    raw_public_key: &CInputBuffer,
) -> i8 {
    let public_key = c_read_raw_pointer(raw_public_key);

    let result = WedprSecp256k1Vrf::is_valid_public_key(&public_key);
    std::mem::forget(public_key);
    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}
