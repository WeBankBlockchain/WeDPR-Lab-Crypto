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

use libc::c_char;
use std::{ffi::CString, panic, ptr};
use wedpr_l_protos::generated::common;

use protobuf::{self, Message};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE,
    SUCCESS,
};

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::{
    bytes_to_string, c_char_pointer_to_string, string_to_bytes, FAILURE,
    SUCCESS,
};

// Secp256k1 implementation.

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_gen_key_pair'.
pub extern "C" fn wedpr_secp256k1_gen_key_pair() -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let (pk, sk) = SIGNATURE_SECP256K1.generate_keypair();
        let mut keypair = common::Keypair::new();
        keypair.set_private_key(sk);
        keypair.set_public_key(pk);
        let c_keypair = bytes_to_string(
            &keypair
                .write_to_bytes()
                .expect("proto to bytes should not fail"),
        );
        c_safe_string_to_c_char_pointer!(c_keypair)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_derive_public_key'.
pub extern "C" fn wedpr_secp256k1_derive_public_key(
    encoded_private_key: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let sk = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let pk = match SIGNATURE_SECP256K1.derive_public_key(&sk) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            },
        };
        let mut keypair = common::Keypair::new();
        keypair.set_private_key(sk);
        keypair.set_public_key(pk);
        let c_keypair = bytes_to_string(
            &keypair
                .write_to_bytes()
                .expect("proto to bytes should not fail"),
        );
        c_safe_string_to_c_char_pointer!(c_keypair)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_sign'.
pub extern "C" fn wedpr_secp256k1_sign(
    encoded_private_key: *const c_char,
    encoded_message_hash: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let message_hash =
            c_safe_c_char_pointer_to_bytes!(encoded_message_hash);

        let signature =
            match SIGNATURE_SECP256K1.sign(&private_key, &message_hash) {
                Ok(v) => v,
                Err(_) => {
                    return ptr::null_mut();
                },
            };
        c_safe_bytes_to_c_char_pointer!(&signature)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_verify'.
pub extern "C" fn wedpr_secp256k1_verify(
    encoded_public_key: *const c_char,
    encoded_message_hash: *const c_char,
    encoded_signature: *const c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_public_key,
            FAILURE
        );
        let message_hash = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_message_hash,
            FAILURE
        );
        let signature = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_signature,
            FAILURE
        );

        match SIGNATURE_SECP256K1.verify(&public_key, &message_hash, &signature)
        {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
#[no_mangle]
/// C interface for 'wedpr_secp256k1_recover_public_key'.
pub extern "C" fn wedpr_secp256k1_recover_public_key(
    encoded_message_hash: *const c_char,
    encoded_signature: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let message_hash =
            c_safe_c_char_pointer_to_bytes!(encoded_message_hash);
        let signature = c_safe_c_char_pointer_to_bytes!(encoded_signature);

        let result = match SIGNATURE_SECP256K1
            .recover_public_key(&message_hash, &signature)
        {
            Ok(v) => v,
            Err(_) => return ptr::null_mut(),
        };
        c_safe_bytes_to_c_char_pointer!(&result)
    });
    c_safe_return!(result)
}

// SM2 implementation.

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_gen_key_pair'.
pub extern "C" fn wedpr_sm2_gen_key_pair() -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let (pk, sk) = SIGNATURE_SM2.generate_keypair();
        let mut keypair = common::Keypair::new();
        keypair.set_private_key(sk);
        keypair.set_public_key(pk);
        let c_keypair = bytes_to_string(
            &keypair
                .write_to_bytes()
                .expect("proto to bytes should not fail"),
        );
        c_safe_string_to_c_char_pointer!(c_keypair)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_derive_public_key'.
pub extern "C" fn wedpr_sm2_derive_public_key(
    encoded_private_key: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let sk = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let pk = match SIGNATURE_SM2.derive_public_key(&sk) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            },
        };
        let mut keypair = common::Keypair::new();
        keypair.set_private_key(sk);
        keypair.set_public_key(pk);
        let c_keypair = bytes_to_string(
            &keypair
                .write_to_bytes()
                .expect("proto to bytes should not fail"),
        );
        c_safe_string_to_c_char_pointer!(c_keypair)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign'.
pub extern "C" fn wedpr_sm2_sign(
    encoded_private_key: *const c_char,
    encoded_message_hash: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let message_hash =
            c_safe_c_char_pointer_to_bytes!(encoded_message_hash);

        let signature = match SIGNATURE_SM2.sign(&private_key, &message_hash) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&signature)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_sign_fast'.
pub extern "C" fn wedpr_sm2_sign_fast(
    encoded_private_key: *const c_char,
    encoded_public_key: *const c_char,
    encoded_message_hash: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let public_key = c_safe_c_char_pointer_to_bytes!(encoded_public_key);
        let message_hash =
            c_safe_c_char_pointer_to_bytes!(encoded_message_hash);

        let signature = match SIGNATURE_SM2.sign_fast(
            &private_key,
            &public_key,
            &message_hash,
        ) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            },
        };
        c_safe_bytes_to_c_char_pointer!(&signature)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_sm2")]
#[no_mangle]
/// C interface for 'wedpr_sm2_verify'.
pub extern "C" fn wedpr_sm2_verify(
    encoded_public_key: *const c_char,
    encoded_message_hash: *const c_char,
    encoded_signature: *const c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_public_key,
            FAILURE
        );
        let message_hash = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_message_hash,
            FAILURE
        );
        let signature = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_signature,
            FAILURE
        );

        match SIGNATURE_SM2.verify(&public_key, &message_hash, &signature) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}

// Ed25519 implementation.

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_gen_key_pair'.
pub extern "C" fn wedpr_ed25519_gen_key_pair() -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let (pk, sk) = SIGNATURE_ED25519.generate_keypair();
        let mut keypair = common::Keypair::new();
        keypair.set_private_key(sk);
        keypair.set_public_key(pk);
        let c_keypair = bytes_to_string(
            &keypair
                .write_to_bytes()
                .expect("proto to bytes should not fail"),
        );
        c_safe_string_to_c_char_pointer!(c_keypair)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_derive_public_key'.
pub extern "C" fn wedpr_ed25519_derive_public_key(
    encoded_private_key: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let sk = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let pk = match SIGNATURE_ED25519.derive_public_key(&sk) {
            Ok(v) => v,
            Err(_) => {
                return ptr::null_mut();
            },
        };
        let mut keypair = common::Keypair::new();
        keypair.set_private_key(sk);
        keypair.set_public_key(pk);
        let c_keypair = bytes_to_string(
            &keypair
                .write_to_bytes()
                .expect("proto to bytes should not fail"),
        );
        c_safe_string_to_c_char_pointer!(c_keypair)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_sign'.
pub extern "C" fn wedpr_ed25519_sign(
    encoded_private_key: *const c_char,
    encoded_message_hash: *const c_char,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        let private_key = c_safe_c_char_pointer_to_bytes!(encoded_private_key);
        let message_hash =
            c_safe_c_char_pointer_to_bytes!(encoded_message_hash);

        let signature =
            match SIGNATURE_ED25519.sign(&private_key, &message_hash) {
                Ok(v) => v,
                Err(_) => {
                    return ptr::null_mut();
                },
            };
        c_safe_bytes_to_c_char_pointer!(&signature)
    });
    c_safe_return!(result)
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
#[no_mangle]
/// C interface for 'wedpr_ed25519_verify'.
pub extern "C" fn wedpr_ed25519_verify(
    encoded_public_key: *const c_char,
    encoded_message_hash: *const c_char,
    encoded_signature: *const c_char,
) -> i8 {
    let result = panic::catch_unwind(|| {
        let public_key = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_public_key,
            FAILURE
        );
        let message_hash = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_message_hash,
            FAILURE
        );
        let signature = c_safe_c_char_pointer_to_bytes_with_error_value!(
            encoded_signature,
            FAILURE
        );

        match SIGNATURE_ED25519.verify(&public_key, &message_hash, &signature) {
            true => SUCCESS,
            false => FAILURE,
        }
    });
    c_safe_return_with_error_value!(result, FAILURE)
}
