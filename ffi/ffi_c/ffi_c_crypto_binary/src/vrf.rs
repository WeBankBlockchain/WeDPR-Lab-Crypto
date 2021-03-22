// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! VRF function wrappers.

#![cfg(feature = "wedpr_f_vrf_curve25519")]

use wedpr_ffi_common::utils::{
    c_pointer_to_rust_bytes, set_c_pointer, CPointInput, CPointOutput, FAILURE,
    SUCCESS,
};

#[cfg(feature = "wedpr_f_vrf_curve25519")]
use wedpr_l_crypto_vrf_curve25519::WedprCurve25519Vrf;
use wedpr_l_utils::traits::Vrf;

// Curve25519 implementation.

#[no_mangle]
/// C interface for 'wedpr_curve25519_vrf_derive_public_key'.
pub unsafe extern "C" fn wedpr_curve25519_vrf_derive_public_key(
    private_key_input: &CPointInput,
    public_key_result: &mut CPointOutput,
) -> i8 {
    let private_key = c_pointer_to_rust_bytes(private_key_input);

    let public_key = WedprCurve25519Vrf::derive_public_key(&private_key);
    std::mem::forget(private_key);
    set_c_pointer(&public_key, public_key_result);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_curve25519_vrf_prove_utf8'.
pub unsafe extern "C" fn wedpr_curve25519_vrf_prove_utf8(
    private_key_input: &CPointInput,
    utf8_message_input: &CPointInput,
    proof_result: &mut CPointOutput,
) -> i8 {
    let private_key = c_pointer_to_rust_bytes(private_key_input);
    let message = c_pointer_to_rust_bytes(utf8_message_input);

    let result = WedprCurve25519Vrf::prove(&private_key, &message);
    std::mem::forget(private_key);
    std::mem::forget(message);
    let proof = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&proof.encode_proof(), proof_result);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_curve25519_vrf_prove_fast_utf8'.
pub unsafe extern "C" fn wedpr_curve25519_vrf_prove_fast_utf8(
    private_key_input: &CPointInput,
    public_key_input: &CPointInput,
    utf8_message_input: &CPointInput,
    proof_result: &mut CPointOutput,
) -> i8 {
    let private_key = c_pointer_to_rust_bytes(private_key_input);
    let public_key = c_pointer_to_rust_bytes(public_key_input);
    let message = c_pointer_to_rust_bytes(utf8_message_input);

    let result =
        WedprCurve25519Vrf::prove_fast(&private_key, &public_key, &message);
    std::mem::forget(private_key);
    std::mem::forget(public_key);
    std::mem::forget(message);
    let proof = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&proof.encode_proof(), proof_result);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_curve25519_vrf_verify_utf8'.
pub unsafe extern "C" fn wedpr_curve25519_vrf_verify_utf8(
    public_key_input: &CPointInput,
    utf8_message_input: &CPointInput,
    proof_input: &CPointInput,
) -> i8 {
    let proof_bytes = c_pointer_to_rust_bytes(proof_input);
    let public_key = c_pointer_to_rust_bytes(public_key_input);
    let message = c_pointer_to_rust_bytes(utf8_message_input);

    let proof = match WedprCurve25519Vrf::decode_proof(&proof_bytes) {
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
/// C interface for 'wedpr_curve25519_vrf_proof_to_hash'.
pub unsafe extern "C" fn wedpr_curve25519_vrf_proof_to_hash(
    proof_input: &CPointInput,
    hash_result: &mut CPointOutput,
) -> i8 {
    let proof_bytes = c_pointer_to_rust_bytes(proof_input);
    let proof = match WedprCurve25519Vrf::decode_proof(&proof_bytes) {
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
    set_c_pointer(&hash, hash_result);
    SUCCESS
}

#[no_mangle]
/// C interface for 'wedpr_curve25519_vrf_is_valid_public_key'.
pub unsafe extern "C" fn wedpr_curve25519_vrf_is_valid_public_key(
    public_key_input: &CPointInput,
) -> i8 {
    let public_key = c_pointer_to_rust_bytes(public_key_input);

    let result = WedprCurve25519Vrf::is_valid_public_key(&public_key);
    std::mem::forget(public_key);
    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}
