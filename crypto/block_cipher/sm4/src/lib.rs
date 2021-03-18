// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! AES Block cipher functions.

use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use sm4::Sm4;

use rand::RngCore;
use wedpr_l_utils::{error::WedprError, traits::BlockCipher};

/// Implements a block cipher instance with AES algorithm.
#[derive(Default, Debug, Clone)]
pub struct WedprBlockCipherSm4 {}

impl BlockCipher for WedprBlockCipherSm4 {
    /// Encrypts a block with a symmetric key and a initialization vector(iv).
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        block_text: &T,
        key: &T,
        iv: &T,
    ) -> Result<Vec<u8>, WedprError> {
        type Sm4128Cbc = Cbc<Sm4, Pkcs7>;
        let cipher = match Sm4128Cbc::new_var(key.as_ref(), iv.as_ref()) {
            Ok(v) => v,
            Err(_) => return Err(WedprError::FormatError),
        };
        let mut buffer = [0u8; 16];
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
        type Sm4128Cbc = Cbc<Sm4, Pkcs7>;
        let cipher = match Sm4128Cbc::new_var(key.as_ref(), iv.as_ref()) {
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
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);
        key.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256() {
        let wedpr_sm4 = WedprBlockCipherSm4::default();
        let key = wedpr_sm4.generate_key();
        let iv = wedpr_sm4.generate_key();
        // let iv = wedpr_aes.generate_key();
        let block = b"helloworld";

        let ciphertext = wedpr_sm4.encrypt(&block.to_vec(), &key, &iv).unwrap();
        let decrypted_msg = wedpr_sm4.decrypt(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted_msg, block.to_vec());
    }
}
