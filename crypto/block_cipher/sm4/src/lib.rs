// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! SM4 Block cipher functions.

use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use sm4::Sm4;

use rand::RngCore;
use std::borrow::BorrowMut;
use wedpr_l_utils::{error::WedprError, traits::BlockCipher};

/// Implements SM4 as a BlockCipher instance.
#[derive(Default, Debug, Clone)]
pub struct WedprBlockCipherSm4 {}

// TODO: Add configurable implementation.
type Sm4Cbc = Cbc<Sm4, Pkcs7>;
const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 16;

impl BlockCipher for WedprBlockCipherSm4 {
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        message: &T,
        key: &T,
        iv: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let cipher = match Sm4Cbc::new_var(key.as_ref(), iv.as_ref()) {
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
        let cipher = match Sm4Cbc::new_var(key.as_ref(), iv.as_ref()) {
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
    fn test_sm4_long_message() {
        let sm4 = WedprBlockCipherSm4::default();
        let key = sm4.generate_key();
        let iv = sm4.generate_iv();
        let msg = b"helloworld1 helloworld2 helloworld3 helloworld4";

        let ciphertext = sm4.encrypt(&msg.to_vec(), &key, &iv).unwrap();
        let decrypted_msg = sm4.decrypt(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted_msg, msg);
    }

    #[test]
    fn test_sm4_short_message() {
        let sm4 = WedprBlockCipherSm4::default();
        let key = sm4.generate_key();
        let iv = sm4.generate_iv();
        let msg = b"hello";

        let ciphertext = sm4.encrypt(&msg.to_vec(), &key, &iv).unwrap();
        let decrypted_msg = sm4.decrypt(&ciphertext, &key, &iv).unwrap();
        assert_eq!(decrypted_msg, msg);
    }
}
