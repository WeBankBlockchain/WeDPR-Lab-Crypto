// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! AES block cipher functions.

use aes::Aes256;

use rand::RngCore;
use wedpr_l_utils::{error::WedprError, traits::BlockCipher};

/// Implements AES256 as a BlockCipher instance.
#[derive(Default, Debug, Clone)]
pub struct WedprBlockCipherAes256 {}

const SUITE: &[u8] = b"WeDPR/AES256-CBC-HMAC-SHA256/v1";
const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;

impl BlockCipher for WedprBlockCipherAes256 {
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        message: &T,
        key: &T,
        iv: &T,
    ) -> Result<Vec<u8>, WedprError> {
        wedpr_l_crypto_authenticated_cbc::encrypt::<Aes256>(
            message.as_ref(),
            key.as_ref(),
            iv.as_ref(),
            SUITE,
        )
    }

    fn decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        ciphertext: &T,
        key: &T,
        iv: &T,
    ) -> Result<Vec<u8>, WedprError> {
        wedpr_l_crypto_authenticated_cbc::decrypt::<Aes256>(
            ciphertext.as_ref(),
            key.as_ref(),
            iv.as_ref(),
            SUITE,
        )
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

impl WedprBlockCipherAes256 {
    /// Required output size for the authenticated v1 ciphertext envelope.
    pub fn ciphertext_len(plaintext_len: usize) -> Option<usize> {
        wedpr_l_crypto_authenticated_cbc::ciphertext_len(plaintext_len)
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

        let empty_key = vec![0u8; KEY_SIZE];
        let empty_iv = vec![0u8; BLOCK_SIZE];
        let empty_ciphertext = aes256
            .encrypt(&msg.to_vec(), &empty_key, &empty_iv)
            .unwrap();
        let decrypted_msg_empty = aes256
            .decrypt(&empty_ciphertext, &empty_key, &empty_iv)
            .unwrap();
        assert_eq!(decrypted_msg_empty, msg);
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};

    #[test]
    fn authenticated_roundtrips_include_empty_and_block_boundaries() {
        let cipher = WedprBlockCipherAes256::default();
        let key = vec![42u8; 32];
        let iv = vec![17u8; 16];
        for size in &[0, 1, 15, 16, 17, 32, 1024] {
            let plaintext = vec![3u8; *size];
            let ciphertext = cipher.encrypt(&plaintext, &key, &iv).unwrap();
            assert_eq!(
                ciphertext.len(),
                WedprBlockCipherAes256::ciphertext_len(*size).unwrap()
            );
            assert_eq!(
                cipher.decrypt(&ciphertext, &key, &iv).unwrap(),
                plaintext
            );
        }
        assert!(WedprBlockCipherAes256::ciphertext_len(usize::MAX).is_none());
    }

    #[test]
    fn rejects_iv_bitflip_every_ciphertext_byte_wrong_key_and_truncation() {
        let cipher = WedprBlockCipherAes256::default();
        let key = vec![42u8; 32];
        let iv = vec![17u8; 16];
        let plaintext = b"amount=00000100".to_vec();
        let ciphertext = cipher.encrypt(&plaintext, &key, &iv).unwrap();
        // Previously this changed the first plaintext digit from 0 to 9.
        let mut altered_iv = iv.clone();
        altered_iv[7] ^= b'0' ^ b'9';
        assert!(cipher.decrypt(&ciphertext, &key, &altered_iv).is_err());
        for index in 0..iv.len() {
            let mut altered = iv.clone();
            altered[index] ^= 1;
            assert!(cipher.decrypt(&ciphertext, &key, &altered).is_err());
        }
        for index in 0..ciphertext.len() {
            let mut altered = ciphertext.clone();
            altered[index] ^= 1;
            assert!(cipher.decrypt(&altered, &key, &iv).is_err());
            assert!(cipher
                .decrypt(&ciphertext[..index].to_vec(), &key, &iv)
                .is_err());
        }
        let mut extended = ciphertext.clone();
        extended.push(0);
        assert!(cipher.decrypt(&extended, &key, &iv).is_err());
        assert!(cipher.decrypt(&ciphertext, &vec![43u8; 32], &iv).is_err());
        assert!(cipher.encrypt(&plaintext, &vec![], &iv).is_err());
        assert!(cipher.decrypt(&ciphertext, &key, &vec![17u8; 15]).is_err());
    }

    #[test]
    fn rejects_legacy_unauthenticated_cbc_instead_of_falling_back() {
        let key = vec![42u8; 32];
        let iv = vec![17u8; 16];
        let old = Cbc::<aes::Aes256, Pkcs7>::new_var(&key, &iv)
            .unwrap()
            .encrypt_vec(b"amount=00000100");
        assert!(WedprBlockCipherAes256::default()
            .decrypt(&old, &key, &iv)
            .is_err());
    }
    #[test]
    fn matches_independent_python_hkdf_hmac_and_openssl_vector() {
        // Generated independently with Python hashlib/hmac HKDF expansion and
        // OpenSSL CBC encryption; key = 0x2a repeated, IV = 0x11 repeated.
        let expected = [
            0x57, 0x44, 0x50, 0x52, 0x45, 0x54, 0x4d, 0x01, 0x92, 0x25, 0x65,
            0x7d, 0xc7, 0xfe, 0xca, 0x98, 0x6f, 0xb7, 0xe7, 0xce, 0xde, 0x74,
            0x3f, 0xd3, 0xd7, 0xc5, 0x5e, 0x97, 0x1d, 0x4e, 0x0b, 0x1a, 0xca,
            0x08, 0x20, 0x72, 0x2b, 0x8d, 0x96, 0xb1, 0xd9, 0x10, 0x51, 0x8c,
            0x23, 0xfb, 0x70, 0x4d, 0x47, 0xc2, 0x75, 0xcf, 0x14, 0xf8, 0xde,
            0x37,
        ];
        let cipher = WedprBlockCipherAes256::default();
        let ciphertext = cipher
            .encrypt(
                &b"amount=00000100".to_vec(),
                &vec![42u8; 32],
                &vec![17u8; 16],
            )
            .unwrap();
        assert_eq!(ciphertext, expected);
    }
}
