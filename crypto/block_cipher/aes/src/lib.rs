// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! AES Block cipher functions.

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};

use rand::RngCore;
use wedpr_l_utils::{error::WedprError, traits::BlockCipher};
// #[macro_use]
// extern crate wedpr_l_macros;

/// Implements a block cipher instance with AES algorithm.
#[derive(Default, Debug, Clone)]
pub struct WedprBlockCipherAES {}

impl BlockCipher for WedprBlockCipherAES {
    /// Encrypts a block with a symmetric key and a initialization vector(iv).
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        block_text: &T,
        key: &T,
        iv: &T,
    ) -> Result<Vec<u8>, WedprError> {
        type Aes256Cbc = Cbc<Aes256, Pkcs7>;
        let cipher = match Aes256Cbc::new_var(key.as_ref(), iv.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(WedprError::FormatError),
        };
        let mut buffer = [0u8; 32];
        buffer[..block_text.as_ref().len()]
            .copy_from_slice(block_text.as_ref());
        return match cipher.encrypt(&mut buffer, block_text.as_ref().len()) {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => Err(WedprError::FormatError),
        };
    }

    /// Decrypts a cipher with a symmetric key and a initialization vector(iv).
    fn decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        cipher_text: &T,
        key: &T,
        iv: &T,
    ) -> Result<Vec<u8>, WedprError> {
        type Aes128Cbc = Cbc<Aes256, Pkcs7>;
        let cipher = match Aes128Cbc::new_var(key.as_ref(), iv.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(WedprError::FormatError),
        };
        let mut buf = cipher_text.as_ref().to_vec();
        return match cipher.decrypt(&mut buf) {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => Err(WedprError::VerificationError),
        };
    }

    /// Generates a new key for block cipher,
    fn generate_key(&self) -> Vec<u8> {
        let mut rng = rand::rngs::OsRng::default();
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256() {
        let wedpr_aes = WedprBlockCipherAES::default();
        let key = wedpr_aes.generate_key();
        let mut rng = rand::rngs::OsRng::default();
        let mut iv_tmp = [0u8; 16];
        rng.fill_bytes(&mut iv_tmp);
        let iv = iv_tmp.to_vec();
        // let iv = wedpr_aes.generate_key();
        let block = b"helloworld";

        let ciphertext = wedpr_aes.encrypt(&block.to_vec(), &key, &iv).unwrap();
        let decrypted_msg = wedpr_aes.decrypt(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted_msg, block.to_vec());
    }
}
