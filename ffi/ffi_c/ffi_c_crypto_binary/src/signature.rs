// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Signature function wrappers.

#![cfg(all(
    feature = "wedpr_f_signature_secp256k1",
    feature = "wedpr_f_signature_sm2"
))]

use wedpr_l_utils::traits::Signature;

#[cfg(feature = "wedpr_f_signature_secp256k1")]
use crate::config::SIGNATURE_SECP256K1;

#[cfg(feature = "wedpr_f_signature_sm2")]
use crate::config::SIGNATURE_SM2;

#[cfg(feature = "wedpr_f_signature_ed25519")]
use crate::config::SIGNATURE_ED25519;

use wedpr_ffi_common::utils::{
    c_pointer_to_rust_bytes, set_c_pointer, CPointInput, CPointOutput, FAILURE,
    SUCCESS,
};

const PUBLIC_KEY_SIZE_WITHOUT_PREFIX: usize = 64;
const PUBLIC_KEY_SIZE_WITH_PREFIX: usize = 65;
const SECP256K1_SIGNATURE_DATA_LENGTH: usize = 65;
const SM2_SIGNATURE_DATA_LENGTH: usize = 64;
const PRIVATE_KEY_SIZE: usize = 32;

// Secp256k1 implementation.

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_gen_key_pair'.
pub unsafe extern "C" fn wedpr_secp256k1_gen_key_pair(
    public_key_result: &mut CPointOutput,
    private_key_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(public_key_result, PUBLIC_KEY_SIZE_WITHOUT_PREFIX);
    check_c_pointer_length!(private_key_result, PRIVATE_KEY_SIZE);

    let (pk, sk) = SIGNATURE_SECP256K1.generate_keypair();
    if public_key_result.len == PUBLIC_KEY_SIZE_WITH_PREFIX {
        set_c_pointer(&pk, public_key_result);
    } else {
        set_c_pointer(&pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX], public_key_result);
    }
    set_c_pointer(&sk, private_key_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_derive_public_key'.
pub unsafe extern "C" fn wedpr_secp256k1_derive_public_key(
    private_key_input: &CPointInput,
    public_key_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(public_key_result, PUBLIC_KEY_SIZE_WITHOUT_PREFIX);

    let sk = c_pointer_to_rust_bytes(private_key_input);
    let result = SIGNATURE_SECP256K1.derive_public_key(&sk);
    std::mem::forget(sk);
    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&pk, public_key_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_sign'.
pub unsafe extern "C" fn wedpr_secp256k1_sign(
    private_key_input: &CPointInput,
    message_hash_input: &CPointInput,
    signature_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(signature_result, SECP256K1_SIGNATURE_DATA_LENGTH);
    let private_key = c_pointer_to_rust_bytes(private_key_input);
    let message_hash = c_pointer_to_rust_bytes(&message_hash_input);
    let result = SIGNATURE_SECP256K1.sign(&private_key, &message_hash);
    std::mem::forget(private_key);
    std::mem::forget(message_hash);
    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&signature, signature_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_verify'.
pub unsafe extern "C" fn wedpr_secp256k1_verify(
    public_key_input: &CPointInput,
    message_hash_input: &CPointInput,
    signature_input: &CPointInput,
) -> i8 {
    let public_key = c_pointer_to_rust_bytes(public_key_input);
    let message_hash = c_pointer_to_rust_bytes(&message_hash_input);
    let signature = c_pointer_to_rust_bytes(&signature_input);

    let result =
        SIGNATURE_SECP256K1.verify(&public_key, &message_hash, &signature);
    std::mem::forget(public_key);
    std::mem::forget(message_hash);
    std::mem::forget(signature);
    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_recover_public_key'.
pub unsafe extern "C" fn wedpr_secp256k1_recover_public_key(
    message_hash_input: &CPointInput,
    signature_input: &CPointInput,
    public_key_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(public_key_result, PUBLIC_KEY_SIZE_WITHOUT_PREFIX);
    let message_hash = c_pointer_to_rust_bytes(&message_hash_input);
    let signature = c_pointer_to_rust_bytes(&signature_input);
    let result =
        SIGNATURE_SECP256K1.recover_public_key(&message_hash, &signature);
    std::mem::forget(message_hash);
    std::mem::forget(signature);
    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if public_key_result.len == PUBLIC_KEY_SIZE_WITH_PREFIX {
        set_c_pointer(&pk, public_key_result);
    } else {
        set_c_pointer(&pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX], public_key_result);
    }
    SUCCESS
}

// SM2 implementation.

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_gen_key_pair'.
pub unsafe extern "C" fn wedpr_sm2_gen_key_pair(
    public_key_result: &mut CPointOutput,
    private_key_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(public_key_result, PUBLIC_KEY_SIZE_WITHOUT_PREFIX);
    check_c_pointer_length!(private_key_result, PRIVATE_KEY_SIZE);

    let (pk, sk) = SIGNATURE_SM2.generate_keypair();
    if public_key_result.len == PUBLIC_KEY_SIZE_WITH_PREFIX {
        set_c_pointer(&pk, public_key_result);
    } else {
        set_c_pointer(&pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX], public_key_result);
    }
    set_c_pointer(&sk, private_key_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_derive_public_key'.
pub unsafe extern "C" fn wedpr_sm2_derive_public_key(
    private_key_input: &CPointInput,
    public_key_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(public_key_result, PUBLIC_KEY_SIZE_WITHOUT_PREFIX);

    let sk = c_pointer_to_rust_bytes(private_key_input);
    let result = SIGNATURE_SM2.derive_public_key(&sk);
    std::mem::forget(sk);
    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&pk, public_key_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign'.
pub unsafe extern "C" fn wedpr_sm2_sign(
    private_key_input: &CPointInput,
    message_hash_input: &CPointInput,
    signature_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(signature_result, SM2_SIGNATURE_DATA_LENGTH);
    let private_key = c_pointer_to_rust_bytes(private_key_input);
    let message_hash = c_pointer_to_rust_bytes(&message_hash_input);
    let result = SIGNATURE_SM2.sign(&private_key, &message_hash);
    std::mem::forget(private_key);
    std::mem::forget(message_hash);
    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&signature, signature_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign_fast'.
pub unsafe extern "C" fn wedpr_sm2_sign_fast(
    private_key_input: &CPointInput,
    public_key_input: &CPointInput,
    message_hash_input: &CPointInput,
    signature_result: &mut CPointOutput,
) -> i8 {
    check_c_pointer_length!(signature_result, SM2_SIGNATURE_DATA_LENGTH);
    let private_key = c_pointer_to_rust_bytes(private_key_input);
    let public_key = c_pointer_to_rust_bytes(public_key_input);
    let message_hash = c_pointer_to_rust_bytes(&message_hash_input);
    let result =
        SIGNATURE_SM2.sign_fast(&private_key, &public_key, &message_hash);
    std::mem::forget(private_key);
    std::mem::forget(public_key);
    std::mem::forget(message_hash);
    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&signature, signature_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_verify'.
pub unsafe extern "C" fn wedpr_sm2_verify(
    public_key_input: &CPointInput,
    message_hash_input: &CPointInput,
    signature_input: &CPointInput,
) -> i8 {
    let public_key = c_pointer_to_rust_bytes(public_key_input);
    let message_hash = c_pointer_to_rust_bytes(&message_hash_input);
    let signature = c_pointer_to_rust_bytes(&signature_input);

    let result = SIGNATURE_SM2.verify(&public_key, &message_hash, &signature);
    std::mem::forget(public_key);
    std::mem::forget(message_hash);
    std::mem::forget(signature);
    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}

// Ed25519 implementation.

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_gen_key_pair'.
pub unsafe extern "C" fn wedpr_ed25519_gen_key_pair(
    public_key_result: &mut CPointOutput,
    private_key_result: &mut CPointOutput,
) -> i8 {
    let (pk, sk) = SIGNATURE_ED25519.generate_keypair();
    if public_key_result.len == PUBLIC_KEY_SIZE_WITH_PREFIX {
        set_c_pointer(&pk, public_key_result);
    } else {
        set_c_pointer(&pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX], public_key_result);
    }
    set_c_pointer(&sk, private_key_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_derive_public_key'.
pub unsafe extern "C" fn wedpr_ed25519_derive_public_key(
    private_key_input: &CPointInput,
    public_key_result: &mut CPointOutput,
) -> i8 {
    let sk = c_pointer_to_rust_bytes(private_key_input);
    let result = SIGNATURE_ED25519.derive_public_key(&sk);
    std::mem::forget(sk);
    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&pk, public_key_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_sign'.
pub unsafe extern "C" fn wedpr_ed25519_sign(
    private_key_input: &CPointInput,
    message_hash_input: &CPointInput,
    signature_result: &mut CPointOutput,
) -> i8 {
    let private_key = c_pointer_to_rust_bytes(private_key_input);
    let message_hash = c_pointer_to_rust_bytes(&message_hash_input);
    let result = SIGNATURE_ED25519.sign(&private_key, &message_hash);
    std::mem::forget(private_key);
    std::mem::forget(message_hash);
    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    set_c_pointer(&signature, signature_result);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_verify'.
pub unsafe extern "C" fn wedpr_ed25519_verify(
    public_key_input: &CPointInput,
    message_hash_input: &CPointInput,
    signature_input: &CPointInput,
) -> i8 {
    let public_key = c_pointer_to_rust_bytes(public_key_input);
    let message_hash = c_pointer_to_rust_bytes(&message_hash_input);
    let signature = c_pointer_to_rust_bytes(&signature_input);

    let result =
        SIGNATURE_ED25519.verify(&public_key, &message_hash, &signature);
    std::mem::forget(public_key);
    std::mem::forget(message_hash);
    std::mem::forget(signature);
    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}
