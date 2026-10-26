// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Signature function wrappers.

#![cfg(not(tarpaulin_include))]
#![cfg(any(
    feature = "wedpr_f_signature_secp256k1",
    feature = "wedpr_f_signature_sm2",
    feature = "wedpr_f_signature_ed25519"
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

const ED25519_PUBLIC_KEY_SIZE_WITHOUT_PREFIX: usize = 32;

const SECP256K1_SIGNATURE_DATA_LENGTH: usize = 65;
const SM2_SIGNATURE_DATA_LENGTH: usize = 64;

// Secp256k1 implementation.

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_gen_key_pair'.
pub unsafe extern "C" fn wedpr_secp256k1_gen_key_pair(
    output_public_key: *mut COutputBuffer,
    output_private_key: *mut COutputBuffer,
) -> i8 {
    if output_public_key == output_private_key {
        return FAILURE;
    }
    let output_public_key =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_public_key)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let output_private_key =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(
            output_private_key,
        ) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    c_check_enough_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    c_check_exact_buffer_size!(output_private_key, PRIVATE_KEY_SIZE);

    let (pk, sk) = SIGNATURE_SECP256K1.generate_keypair();
    // FISCO BCOS public key length is either 64 or 65 bytes.
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        if c_write_raw_pointer(&pk, output_public_key).is_err() {
            return FAILURE;
        }
    } else {
        if c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        )
        .is_err()
        {
            return FAILURE;
        }
    }
    if c_write_raw_pointer(&sk, output_private_key).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_derive_public_key'.
pub unsafe extern "C" fn wedpr_secp256k1_derive_public_key(
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

    c_check_enough_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    let sk = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = SIGNATURE_SECP256K1.derive_public_key(&sk);

    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // FISCO BCOS public key length is either 64 or 65 bytes.
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        if c_write_raw_pointer(&pk, output_public_key).is_err() {
            return FAILURE;
        }
    } else {
        if c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        )
        .is_err()
        {
            return FAILURE;
        }
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_sign'.
pub unsafe extern "C" fn wedpr_secp256k1_sign(
    raw_private_key: *const CInputBuffer,
    raw_message_hash: *const CInputBuffer,
    output_signature: *mut COutputBuffer,
) -> i8 {
    let raw_private_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_private_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_private_key = &raw_private_key;
    let raw_message_hash =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_message_hash) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_message_hash = &raw_message_hash;
    let output_signature =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_signature)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    c_check_enough_buffer_size!(
        output_signature,
        SECP256K1_SIGNATURE_DATA_LENGTH
    );
    let private_key = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message_hash = match c_read_raw_pointer(&raw_message_hash) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = SIGNATURE_SECP256K1.sign(&private_key, &message_hash);

    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&signature, output_signature).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_verify'.
pub unsafe extern "C" fn wedpr_secp256k1_verify(
    raw_public_key: *const CInputBuffer,
    raw_message_hash: *const CInputBuffer,
    raw_signature: *const CInputBuffer,
) -> i8 {
    let raw_public_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_public_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_public_key = &raw_public_key;
    let raw_message_hash =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_message_hash) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_message_hash = &raw_message_hash;
    let raw_signature =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_signature) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_signature = &raw_signature;

    let public_key = match c_read_raw_pointer(raw_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message_hash = match c_read_raw_pointer(&raw_message_hash) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let signature = match c_read_raw_pointer(&raw_signature) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result =
        SIGNATURE_SECP256K1.verify(&public_key, &message_hash, &signature);

    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_recover_public_key'.
pub unsafe extern "C" fn wedpr_secp256k1_recover_public_key(
    raw_message_hash: *const CInputBuffer,
    raw_signature: *const CInputBuffer,
    output_public_key: *mut COutputBuffer,
) -> i8 {
    let raw_message_hash =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_message_hash) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_message_hash = &raw_message_hash;
    let raw_signature =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_signature) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_signature = &raw_signature;
    let output_public_key =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_public_key)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    c_check_enough_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    let message_hash = match c_read_raw_pointer(&raw_message_hash) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let signature = match c_read_raw_pointer(&raw_signature) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result =
        SIGNATURE_SECP256K1.recover_public_key(&message_hash, &signature);

    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    // FISCO BCOS public key length is either 64 or 65 bytes.
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        if c_write_raw_pointer(&pk, output_public_key).is_err() {
            return FAILURE;
        }
    } else {
        if c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        )
        .is_err()
        {
            return FAILURE;
        }
    }
    SUCCESS
}

// SM2 implementation.

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_gen_key_pair'.
pub unsafe extern "C" fn wedpr_sm2_gen_key_pair(
    output_public_key: *mut COutputBuffer,
    output_private_key: *mut COutputBuffer,
) -> i8 {
    if output_public_key == output_private_key {
        return FAILURE;
    }
    let output_public_key =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_public_key)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let output_private_key =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(
            output_private_key,
        ) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    c_check_enough_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    c_check_exact_buffer_size!(output_private_key, PRIVATE_KEY_SIZE);

    let (pk, sk) = SIGNATURE_SM2.generate_keypair();
    // FISCO BCOS public key length is either 64 or 65 bytes.
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        if c_write_raw_pointer(&pk, output_public_key).is_err() {
            return FAILURE;
        }
    } else {
        if c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        )
        .is_err()
        {
            return FAILURE;
        }
    }
    if c_write_raw_pointer(&sk, output_private_key).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_derive_public_key'.
pub unsafe extern "C" fn wedpr_sm2_derive_public_key(
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

    c_check_enough_buffer_size!(
        output_public_key,
        PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    let sk = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = SIGNATURE_SM2.derive_public_key(&sk);

    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if output_public_key.len >= PUBLIC_KEY_SIZE_WITH_PREFIX {
        if c_write_raw_pointer(&pk, output_public_key).is_err() {
            return FAILURE;
        }
    } else {
        if c_write_raw_pointer(
            &pk[1..PUBLIC_KEY_SIZE_WITH_PREFIX],
            output_public_key,
        )
        .is_err()
        {
            return FAILURE;
        }
    }

    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign'.
pub unsafe extern "C" fn wedpr_sm2_sign(
    raw_private_key: *const CInputBuffer,
    raw_message_hash: *const CInputBuffer,
    output_signature: *mut COutputBuffer,
) -> i8 {
    let raw_private_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_private_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_private_key = &raw_private_key;
    let raw_message_hash =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_message_hash) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_message_hash = &raw_message_hash;
    let output_signature =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_signature)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    c_check_exact_buffer_size!(output_signature, SM2_SIGNATURE_DATA_LENGTH);
    let private_key = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message_hash = match c_read_raw_pointer(&raw_message_hash) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = SIGNATURE_SM2.sign(&private_key, &message_hash);

    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&signature, output_signature).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign_fast'.
pub unsafe extern "C" fn wedpr_sm2_sign_fast(
    raw_private_key: *const CInputBuffer,
    raw_public_key: *const CInputBuffer,
    raw_message_hash: *const CInputBuffer,
    output_signature: *mut COutputBuffer,
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
    let raw_message_hash =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_message_hash) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_message_hash = &raw_message_hash;
    let output_signature =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_signature)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    c_check_exact_buffer_size!(output_signature, SM2_SIGNATURE_DATA_LENGTH);
    let private_key = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let public_key = match c_read_raw_pointer(raw_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message_hash = match c_read_raw_pointer(&raw_message_hash) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result =
        SIGNATURE_SM2.sign_fast(&private_key, &public_key, &message_hash);

    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&signature, output_signature).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_verify'.
pub unsafe extern "C" fn wedpr_sm2_verify(
    raw_public_key: *const CInputBuffer,
    raw_message_hash: *const CInputBuffer,
    raw_signature: *const CInputBuffer,
) -> i8 {
    let raw_public_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_public_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_public_key = &raw_public_key;
    let raw_message_hash =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_message_hash) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_message_hash = &raw_message_hash;
    let raw_signature =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_signature) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_signature = &raw_signature;

    let public_key = match c_read_raw_pointer(raw_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message_hash = match c_read_raw_pointer(&raw_message_hash) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let signature = match c_read_raw_pointer(&raw_signature) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = SIGNATURE_SM2.verify(&public_key, &message_hash, &signature);

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
    output_public_key: *mut COutputBuffer,
    output_private_key: *mut COutputBuffer,
) -> i8 {
    if output_public_key == output_private_key {
        return FAILURE;
    }
    let output_public_key =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_public_key)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let output_private_key =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(
            output_private_key,
        ) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    c_check_enough_buffer_size!(
        output_public_key,
        ED25519_PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    c_check_exact_buffer_size!(output_private_key, PRIVATE_KEY_SIZE);
    let (pk, sk) = SIGNATURE_ED25519.generate_keypair();
    if c_write_raw_pointer(&pk, output_public_key).is_err() {
        return FAILURE;
    }
    if c_write_raw_pointer(&sk, output_private_key).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_derive_public_key'.
pub unsafe extern "C" fn wedpr_ed25519_derive_public_key(
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

    c_check_enough_buffer_size!(
        output_public_key,
        ED25519_PUBLIC_KEY_SIZE_WITHOUT_PREFIX
    );
    let sk = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = SIGNATURE_ED25519.derive_public_key(&sk);

    let pk = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&pk, output_public_key).is_err() {
        return FAILURE;
    }

    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_sign'.
pub unsafe extern "C" fn wedpr_ed25519_sign(
    raw_private_key: *const CInputBuffer,
    raw_message_hash: *const CInputBuffer,
    output_signature: *mut COutputBuffer,
) -> i8 {
    let raw_private_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_private_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_private_key = &raw_private_key;
    let raw_message_hash =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_message_hash) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_message_hash = &raw_message_hash;
    let output_signature =
        match wedpr_ffi_common::utils::c_borrow_output_buffer(output_signature)
        {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };

    let private_key = match c_read_raw_pointer(raw_private_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message_hash = match c_read_raw_pointer(&raw_message_hash) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result = SIGNATURE_ED25519.sign(&private_key, &message_hash);

    let signature = match result {
        Ok(v) => v,
        Err(_) => return FAILURE,
    };
    if c_write_raw_pointer(&signature, output_signature).is_err() {
        return FAILURE;
    }
    SUCCESS
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_verify'.
pub unsafe extern "C" fn wedpr_ed25519_verify(
    raw_public_key: *const CInputBuffer,
    raw_message_hash: *const CInputBuffer,
    raw_signature: *const CInputBuffer,
) -> i8 {
    let raw_public_key =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_public_key) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_public_key = &raw_public_key;
    let raw_message_hash =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_message_hash) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_message_hash = &raw_message_hash;
    let raw_signature =
        match wedpr_ffi_common::utils::c_copy_input_buffer(raw_signature) {
            Ok(buffer) => buffer,
            Err(_) => return FAILURE,
        };
    let raw_signature = &raw_signature;

    let public_key = match c_read_raw_pointer(raw_public_key) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let message_hash = match c_read_raw_pointer(&raw_message_hash) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    let signature = match c_read_raw_pointer(&raw_signature) {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };

    let result =
        SIGNATURE_ED25519.verify(&public_key, &message_hash, &signature);

    match result {
        true => SUCCESS,
        false => FAILURE,
    }
}
