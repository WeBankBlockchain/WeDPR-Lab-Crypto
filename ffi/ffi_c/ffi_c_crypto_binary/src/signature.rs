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
    c_read_raw_pointer, c_write_raw_pointer, CInputBuffer, COutputBuffer,
    FAILURE, SUCCESS,
};

const PUBLIC_KEY_SIZE_WITHOUT_PREFIX: usize = 64;
const PUBLIC_KEY_SIZE_WITH_PREFIX: usize = 65;
const PRIVATE_KEY_SIZE: usize = 32;

const SECP256K1_SIGNATURE_DATA_LENGTH: usize = 65;
const SM2_SIGNATURE_DATA_LENGTH: usize = 64;

// Secp256k1 implementation.

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_gen_key_pair'.
pub unsafe extern "C" fn wedpr_secp256k1_gen_key_pair(
    output_public_key: &mut COutputBuffer,
    output_private_key: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    c_check_exact_buffer_size!(output_private_key, PRIVATE_KEY_SIZE);

    let (pk, sk) = SIGNATURE_SECP256K1.generate_keypair();
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        c_write_raw_pointer(&pk, output_public_key);
    } else {
        c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        );
    }
    c_write_raw_pointer(&sk, output_private_key);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_derive_public_key'.
pub unsafe extern "C" fn wedpr_secp256k1_derive_public_key(
    raw_private_key: &CInputBuffer,
    output_public_key: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    let sk = c_read_raw_pointer(raw_private_key);

    let result = SIGNATURE_SECP256K1.derive_public_key(&sk);
    std::mem::forget(sk);
    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        c_write_raw_pointer(&pk, output_public_key);
    } else {
        c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        );
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_sign'.
pub unsafe extern "C" fn wedpr_secp256k1_sign(
    raw_private_key: &CInputBuffer,
    raw_message_hash: &CInputBuffer,
    output_signature: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(
        output_signature,
        SECP256K1_SIGNATURE_DATA_LENGTH
    );
    let private_key = c_read_raw_pointer(raw_private_key);
    let message_hash = c_read_raw_pointer(&raw_message_hash);

    let result = SIGNATURE_SECP256K1.sign(&private_key, &message_hash);
    std::mem::forget(private_key);
    std::mem::forget(message_hash);
    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&signature, output_signature);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_verify'.
pub unsafe extern "C" fn wedpr_secp256k1_verify(
    raw_public_key: &CInputBuffer,
    raw_message_hash: &CInputBuffer,
    raw_signature: &CInputBuffer,
) -> i8 {
    let public_key = c_read_raw_pointer(raw_public_key);
    let message_hash = c_read_raw_pointer(&raw_message_hash);
    let signature = c_read_raw_pointer(&raw_signature);

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
    raw_message_hash: &CInputBuffer,
    raw_signature: &CInputBuffer,
    output_public_key: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    let message_hash = c_read_raw_pointer(&raw_message_hash);
    let signature = c_read_raw_pointer(&raw_signature);

    let result =
        SIGNATURE_SECP256K1.recover_public_key(&message_hash, &signature);
    std::mem::forget(message_hash);
    std::mem::forget(signature);
    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        c_write_raw_pointer(&pk, output_public_key);
    } else {
        c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        );
    }
    SUCCESS
}

// SM2 implementation.

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_gen_key_pair'.
pub unsafe extern "C" fn wedpr_sm2_gen_key_pair(
    output_public_key: &mut COutputBuffer,
    output_private_key: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    c_check_exact_buffer_size!(output_private_key, PRIVATE_KEY_SIZE);

    let (pk, sk) = SIGNATURE_SM2.generate_keypair();
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        c_write_raw_pointer(&pk, output_public_key);
    } else {
        c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        );
    }
    c_write_raw_pointer(&sk, output_private_key);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_derive_public_key'.
pub unsafe extern "C" fn wedpr_sm2_derive_public_key(
    raw_private_key: &CInputBuffer,
    output_public_key: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    let sk = c_read_raw_pointer(raw_private_key);

    let result = SIGNATURE_SM2.derive_public_key(&sk);
    std::mem::forget(sk);
    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        c_write_raw_pointer(&pk, output_public_key);
    } else {
        c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        );
    }

    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign'.
pub unsafe extern "C" fn wedpr_sm2_sign(
    raw_private_key: &CInputBuffer,
    raw_message_hash: &CInputBuffer,
    output_signature: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(output_signature, SM2_SIGNATURE_DATA_LENGTH);
    let private_key = c_read_raw_pointer(raw_private_key);
    let message_hash = c_read_raw_pointer(&raw_message_hash);

    let result = SIGNATURE_SM2.sign(&private_key, &message_hash);
    std::mem::forget(private_key);
    std::mem::forget(message_hash);
    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&signature, output_signature);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign_fast'.
pub unsafe extern "C" fn wedpr_sm2_sign_fast(
    raw_private_key: &CInputBuffer,
    raw_public_key: &CInputBuffer,
    raw_message_hash: &CInputBuffer,
    output_signature: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(output_signature, SM2_SIGNATURE_DATA_LENGTH);
    let private_key = c_read_raw_pointer(raw_private_key);
    let public_key = c_read_raw_pointer(raw_public_key);
    let message_hash = c_read_raw_pointer(&raw_message_hash);

    let result =
        SIGNATURE_SM2.sign_fast(&private_key, &public_key, &message_hash);
    std::mem::forget(private_key);
    std::mem::forget(public_key);
    std::mem::forget(message_hash);
    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&signature, output_signature);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_verify'.
pub unsafe extern "C" fn wedpr_sm2_verify(
    raw_public_key: &CInputBuffer,
    raw_message_hash: &CInputBuffer,
    raw_signature: &CInputBuffer,
) -> i8 {
    let public_key = c_read_raw_pointer(raw_public_key);
    let message_hash = c_read_raw_pointer(&raw_message_hash);
    let signature = c_read_raw_pointer(&raw_signature);

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
    output_public_key: &mut COutputBuffer,
    output_private_key: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    c_check_exact_buffer_size!(output_private_key, PRIVATE_KEY_SIZE);
    let (pk, sk) = SIGNATURE_ED25519.generate_keypair();
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        c_write_raw_pointer(&pk, output_public_key);
    } else {
        c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        );
    }
    c_write_raw_pointer(&sk, output_private_key);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_derive_public_key'.
pub unsafe extern "C" fn wedpr_ed25519_derive_public_key(
    raw_private_key: &CInputBuffer,
    output_public_key: &mut COutputBuffer,
) -> i8 {
    c_check_exact_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    let sk = c_read_raw_pointer(raw_private_key);

    let result = SIGNATURE_ED25519.derive_public_key(&sk);
    std::mem::forget(sk);
    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        c_write_raw_pointer(&pk, output_public_key);
    } else {
        c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        );
    }

    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_sign'.
pub unsafe extern "C" fn wedpr_ed25519_sign(
    raw_private_key: &CInputBuffer,
    raw_message_hash: &CInputBuffer,
    output_signature: &mut COutputBuffer,
) -> i8 {
    let private_key = c_read_raw_pointer(raw_private_key);
    let message_hash = c_read_raw_pointer(&raw_message_hash);

    let result = SIGNATURE_ED25519.sign(&private_key, &message_hash);
    std::mem::forget(private_key);
    std::mem::forget(message_hash);
    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    c_write_raw_pointer(&signature, output_signature);
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_verify'.
pub unsafe extern "C" fn wedpr_ed25519_verify(
    raw_public_key: &CInputBuffer,
    raw_message_hash: &CInputBuffer,
    raw_signature: &CInputBuffer,
) -> i8 {
    let public_key = c_read_raw_pointer(raw_public_key);
    let message_hash = c_read_raw_pointer(&raw_message_hash);
    let signature = c_read_raw_pointer(&raw_signature);

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
