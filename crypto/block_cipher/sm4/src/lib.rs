// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! SM4 Block cipher functions.

use sm4::Sm4;

use rand::RngCore;
use wedpr_l_utils::{error::WedprError, traits::BlockCipher};

/// Implements SM4 as a BlockCipher instance.
#[derive(Default, Debug, Clone)]
pub struct WedprBlockCipherSm4 {}

const SUITE: &[u8] = b"WeDPR/SM4-CBC-HMAC-SHA256/v1";
const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 16;

impl BlockCipher for WedprBlockCipherSm4 {
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        message: &T,
        key: &T,
        iv: &T,
    ) -> Result<Vec<u8>, WedprError> {
        wedpr_l_crypto_authenticated_cbc::encrypt::<Sm4>(
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
        wedpr_l_crypto_authenticated_cbc::decrypt::<Sm4>(
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

impl WedprBlockCipherSm4 {
    /// Required output size for the authenticated v1 ciphertext envelope.
    pub fn ciphertext_len(plaintext_len: usize) -> Option<usize> {
        wedpr_l_crypto_authenticated_cbc::ciphertext_len(plaintext_len)
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

#[cfg(test)]
mod security_tests {
    use super::*;
    use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};

    #[test]
    fn authenticated_roundtrips_include_empty_and_block_boundaries() {
        let cipher = WedprBlockCipherSm4::default();
        let key = vec![42u8; 16];
        let iv = vec![17u8; 16];
        for size in &[0, 1, 15, 16, 17, 32, 1024] {
            let plaintext = vec![3u8; *size];
            let ciphertext = cipher.encrypt(&plaintext, &key, &iv).unwrap();
            assert_eq!(
                ciphertext.len(),
                WedprBlockCipherSm4::ciphertext_len(*size).unwrap()
            );
            assert_eq!(
                cipher.decrypt(&ciphertext, &key, &iv).unwrap(),
                plaintext
            );
        }
        assert!(WedprBlockCipherSm4::ciphertext_len(usize::MAX).is_none());
    }

    #[test]
    fn rejects_iv_bitflip_every_ciphertext_byte_wrong_key_and_truncation() {
        let cipher = WedprBlockCipherSm4::default();
        let key = vec![42u8; 16];
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
        assert!(cipher.decrypt(&ciphertext, &vec![43u8; 16], &iv).is_err());
        assert!(cipher.encrypt(&plaintext, &vec![], &iv).is_err());
        assert!(cipher.decrypt(&ciphertext, &key, &vec![17u8; 15]).is_err());
    }

    #[test]
    fn rejects_legacy_unauthenticated_cbc_instead_of_falling_back() {
        let key = vec![42u8; 16];
        let iv = vec![17u8; 16];
        let old = Cbc::<sm4::Sm4, Pkcs7>::new_var(&key, &iv)
            .unwrap()
            .encrypt_vec(b"amount=00000100");
        assert!(WedprBlockCipherSm4::default()
            .decrypt(&old, &key, &iv)
            .is_err());
    }
    #[test]
    fn matches_independent_python_hkdf_hmac_and_openssl_vector() {
        // Generated independently with Python hashlib/hmac HKDF expansion and
        // OpenSSL CBC encryption; key = 0x2a repeated, IV = 0x11 repeated.
        let expected = [
            0x57, 0x44, 0x50, 0x52, 0x45, 0x54, 0x4d, 0x01, 0x58, 0xc0, 0x03,
            0xf9, 0xec, 0x0f, 0x3c, 0xe4, 0x7e, 0x4f, 0x28, 0xc5, 0xdc, 0x43,
            0x48, 0x6d, 0x38, 0x12, 0xc3, 0xe6, 0xcb, 0xaf, 0x8a, 0xa1, 0xe1,
            0x8f, 0x21, 0x76, 0xf8, 0x22, 0x82, 0x1e, 0x3e, 0x2e, 0x00, 0x79,
            0xc3, 0xa0, 0xfb, 0xed, 0xc3, 0x6d, 0x04, 0xdf, 0x23, 0x51, 0xa8,
            0x97,
        ];
        let cipher = WedprBlockCipherSm4::default();
        let ciphertext = cipher
            .encrypt(
                &b"amount=00000100".to_vec(),
                &vec![42u8; 16],
                &vec![17u8; 16],
            )
            .unwrap();
        assert_eq!(ciphertext, expected);
    }
}
