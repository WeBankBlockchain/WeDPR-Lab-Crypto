// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! AES block cipher functions.

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};

use rand::RngCore;
use std::borrow::BorrowMut;
use wedpr_l_utils::{error::WedprError, traits::BlockCipher};

/// Implements AES256 as a BlockCipher instance.
#[derive(Default, Debug, Clone)]
pub struct WedprBlockCipherAes256 {}

// TODO: Add configurable implementation.
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

impl BlockCipher for WedprBlockCipherAes256 {
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        message: &T,
        key: &T,
        iv: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let cipher = match Aes256Cbc::new_var(key.as_ref(), iv.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(WedprError::FormatError),
        };
        // TODO: Find a better way to prepare the aligned buffer.
        let input_length = message.as_ref().len();
        let padding_length =
            (input_length / BLOCK_SIZE + 1) * BLOCK_SIZE - input_length;
        let mut buffer_vec = message.as_ref().to_vec();
        buffer_vec.append([0u8].repeat(padding_length).borrow_mut());

        return match cipher.encrypt(buffer_vec.as_mut_slice(), input_length) {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => Err(WedprError::FormatError),
        };
    }

    fn decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        ciphertext: &T,
        key: &T,
        iv: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let cipher = match Aes256Cbc::new_var(key.as_ref(), iv.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(WedprError::FormatError),
        };

        return match cipher.decrypt(ciphertext.as_ref().to_vec().as_mut_slice())
        {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => Err(WedprError::FormatError),
        };
    }

    fn generate_key(&self) -> Vec<u8> {
        let mut rng = rand::rngs::OsRng::default();
        let mut key = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut key);
        key.to_vec()
    }

    fn generate_iv(&self) -> Vec<u8> {
        let mut rng = rand::rngs::OsRng::default();
        let mut iv = [0u8; BLOCK_SIZE];
        rng.fill_bytes(&mut iv);
        iv.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_long_message() {
        let aes256 = WedprBlockCipherAes256::default();
        let key = aes256.generate_key();
        let iv = aes256.generate_iv();
        let msg = b"helloworld1 helloworld2 helloworld3 helloworld4";

        let ciphertext = aes256.encrypt(&msg.to_vec(), &key, &iv).unwrap();
        let decrypted_msg = aes256.decrypt(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted_msg, msg);
    }

    #[test]
    fn test_aes256_short_message() {
        let aes256 = WedprBlockCipherAes256::default();
        let key = aes256.generate_key();
        let iv = aes256.generate_iv();
        let msg = b"hello";

        let ciphertext = aes256.encrypt(&msg.to_vec(), &key, &iv).unwrap();
        let decrypted_msg = aes256.decrypt(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted_msg, msg);
    }
}
