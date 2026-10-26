// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Block Cipher function wrappers.

#![cfg(not(tarpaulin_include))]
#![cfg(any(
    feature = "wedpr_f_crypto_block_cipher_aes",
    feature = "wedpr_f_crypto_block_cipher_sm4"
))]

use wedpr_l_utils::traits::BlockCipher;

#[cfg(feature = "wedpr_f_crypto_block_cipher_aes")]
use crate::config::BLOCK_CIPHER_AES256;

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
use crate::config::BLOCK_CIPHER_SM4;

use wedpr_ffi_common::utils::{
    c_write_raw_pointer, CInputBuffer, COutputBuffer, FAILURE, SUCCESS,
};

// Borrow input memory; ownership always remains with the C caller.
unsafe fn input_bytes(input: &CInputBuffer) -> Result<&[u8], ()> {
    if input.len == 0 {
        return Ok(&[]);
    }
    if input.data.is_null() || input.len > isize::MAX as usize {
        return Err(());
    }
    Ok(std::slice::from_raw_parts(
        input.data as *const u8,
        input.len,
    ))
}

unsafe fn transform<C: BlockCipher>(
    cipher: &C,
    input: &CInputBuffer,
    key: &CInputBuffer,
    iv: &CInputBuffer,
    output: &mut COutputBuffer,
    decrypt: bool,
) -> i8 {
    let (input, key, iv) =
        match (input_bytes(input), input_bytes(key), input_bytes(iv)) {
            (Ok(input), Ok(key), Ok(iv)) => (input, key, iv),
            _ => return FAILURE,
        };
    let result = if decrypt {
        cipher.decrypt(input, key, iv)
    } else {
        cipher.encrypt(input, key, iv)
    };
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(_) => return FAILURE,
    };
    if bytes.is_empty() {
        output.len = 0;
        return SUCCESS;
    }
    if output.data.is_null()
        || output.len < bytes.len()
        || output.len > isize::MAX as usize
    {
        output.len = bytes.len();
        return FAILURE;
    }
    c_write_raw_pointer(&bytes, output);
    SUCCESS
}

// AES256 implementation.

#[cfg(feature = "wedpr_f_crypto_block_cipher_aes")]
#[no_mangle]
/// C interface for 'wedpr_aes256_encrypt'.
pub unsafe extern "C" fn wedpr_aes256_encrypt(
    raw_plaintext: &CInputBuffer,
    raw_key: &CInputBuffer,
    raw_iv: &CInputBuffer,
    output_ciphertext: &mut COutputBuffer,
) -> i8 {
    transform(
        &*BLOCK_CIPHER_AES256,
        raw_plaintext,
        raw_key,
        raw_iv,
        output_ciphertext,
        false,
    )
}

#[cfg(feature = "wedpr_f_crypto_block_cipher_aes")]
#[no_mangle]
/// C interface for 'wedpr_aes256_decrypt'.
pub unsafe extern "C" fn wedpr_aes256_decrypt(
    raw_ciphertext: &CInputBuffer,
    raw_key: &CInputBuffer,
    raw_iv: &CInputBuffer,
    output_plaintext: &mut COutputBuffer,
) -> i8 {
    transform(
        &*BLOCK_CIPHER_AES256,
        raw_ciphertext,
        raw_key,
        raw_iv,
        output_plaintext,
        true,
    )
}

// SM4 implementation.

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
#[no_mangle]
/// C interface for 'wedpr_sm4_encrypt'.
pub unsafe extern "C" fn wedpr_sm4_encrypt(
    raw_plaintext: &CInputBuffer,
    raw_key: &CInputBuffer,
    raw_iv: &CInputBuffer,
    output_ciphertext: &mut COutputBuffer,
) -> i8 {
    transform(
        &*BLOCK_CIPHER_SM4,
        raw_plaintext,
        raw_key,
        raw_iv,
        output_ciphertext,
        false,
    )
}

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
#[no_mangle]
/// C interface for 'wedpr_sm4_decrypt'.
pub unsafe extern "C" fn wedpr_sm4_decrypt(
    raw_ciphertext: &CInputBuffer,
    raw_key: &CInputBuffer,
    raw_iv: &CInputBuffer,
    output_plaintext: &mut COutputBuffer,
) -> i8 {
    transform(
        &*BLOCK_CIPHER_SM4,
        raw_ciphertext,
        raw_key,
        raw_iv,
        output_plaintext,
        true,
    )
}

#[cfg(all(
    test,
    feature = "wedpr_f_crypto_block_cipher_aes",
    feature = "wedpr_f_crypto_block_cipher_sm4"
))]
mod security_tests {
    use super::*;
    type Operation = unsafe extern "C" fn(
        &CInputBuffer,
        &CInputBuffer,
        &CInputBuffer,
        &mut COutputBuffer,
    ) -> i8;

    fn input(bytes: &[u8]) -> CInputBuffer {
        CInputBuffer {
            data: bytes.as_ptr().cast(),
            len: bytes.len(),
        }
    }

    #[test]
    fn both_ciphers_report_capacity_and_leave_outputs_untouched_on_failure() {
        let operations: [(Operation, Operation, usize); 2] = [
            (wedpr_aes256_encrypt, wedpr_aes256_decrypt, 32),
            (wedpr_sm4_encrypt, wedpr_sm4_decrypt, 16),
        ];
        for (encrypt, decrypt, key_len) in operations.iter().copied() {
            let message = b"amount=00000100".to_vec();
            let key = vec![42u8; key_len];
            let iv = vec![17u8; 16];
            let mut output = [99u8; 1];
            let mut small = COutputBuffer {
                data: output.as_mut_ptr().cast(),
                len: 1,
            };
            assert_eq!(
                unsafe {
                    encrypt(
                        &input(&message),
                        &input(&key),
                        &input(&iv),
                        &mut small,
                    )
                },
                FAILURE
            );
            assert_eq!(small.len, 56);
            assert_eq!(output, [99u8]);
            let mut ciphertext = vec![0u8; small.len];
            let mut encoded = COutputBuffer {
                data: ciphertext.as_mut_ptr().cast(),
                len: ciphertext.len(),
            };
            assert_eq!(
                unsafe {
                    encrypt(
                        &input(&message),
                        &input(&key),
                        &input(&iv),
                        &mut encoded,
                    )
                },
                SUCCESS
            );
            ciphertext[8] ^= 1;
            let mut plaintext = vec![99u8; message.len()];
            let mut decoded = COutputBuffer {
                data: plaintext.as_mut_ptr().cast(),
                len: plaintext.len(),
            };
            assert_eq!(
                unsafe {
                    decrypt(
                        &input(&ciphertext),
                        &input(&key),
                        &input(&iv),
                        &mut decoded,
                    )
                },
                FAILURE
            );
            assert_eq!(plaintext, vec![99u8; message.len()]);
            let null_input = CInputBuffer {
                data: std::ptr::null(),
                len: 1,
            };
            assert_eq!(
                unsafe {
                    encrypt(
                        &null_input,
                        &input(&key),
                        &input(&iv),
                        &mut decoded,
                    )
                },
                FAILURE
            );
            let mut null_output = COutputBuffer {
                data: std::ptr::null_mut(),
                len: 0,
            };
            assert_eq!(
                unsafe {
                    encrypt(
                        &input(&message),
                        &input(&key),
                        &input(&iv),
                        &mut null_output,
                    )
                },
                FAILURE
            );
            assert_eq!(null_output.len, 56);
        }
    }
}
