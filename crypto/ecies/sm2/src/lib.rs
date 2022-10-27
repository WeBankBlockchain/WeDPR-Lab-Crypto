// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Sm2 ECIES functions.

use libsm::sm2::{
    encrypt::{DecryptCtx, EncryptCtx},
    signature::SigCtx,
};
use wedpr_l_utils::{error::WedprError, traits::Ecies};
#[macro_use]
extern crate wedpr_l_macros;
#[macro_use]
extern crate lazy_static;

lazy_static! {
    // Shared sm2 instance initialized for all functions.
    pub static ref SM2_CTX: SigCtx = SigCtx::new();
}

/// Implements a ECIES instance on sm2 curve.
#[derive(Default, Debug, Clone)]
pub struct WedprSm2Ecies {}

impl WedprSm2Ecies {
    pub fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
        message_len: usize,
    ) -> Result<Vec<u8>, WedprError> {
        let public_key_point = match SM2_CTX.load_pubkey(&public_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            },
        };
        let encrypt_ctx = EncryptCtx::new(message_len, public_key_point);
        match encrypt_ctx.encrypt(message.as_ref()) {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => {
                wedpr_println!("sm2 ECIES encrypt failed");
                return Err(WedprError::FormatError);
            },
        }
    }

    pub fn decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        ciphertext: &T,
        message_len: usize,
    ) -> Result<Vec<u8>, WedprError> {
        let secret_key = match SM2_CTX.load_seckey(&private_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            },
        };
        let decrypt_ctx = DecryptCtx::new(message_len, secret_key);
        match decrypt_ctx.decrypt(ciphertext.as_ref()) {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => {
                wedpr_println!("sm2 ECIES decrypt failed");
                return Err(WedprError::FormatError);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;

    #[test]
    fn test_sm2_ecies() {
        let sm2_ecies = WedprSm2Ecies::default();
        let (pk_b, sk_b) = SM2_CTX.new_keypair().unwrap();
        let public_key = SM2_CTX.serialize_pubkey(&pk_b, false).unwrap();
        let secret_key = SM2_CTX.serialize_seckey(&sk_b).unwrap();
        let message: Vec<u8> =
            (0..1024).map(|_| rand::random::<u8>()).collect();
        let message_size = 1024;

        let ciphertext = sm2_ecies
            .encrypt(&public_key, &message, message_size)
            .unwrap();
        wedpr_println!("ciphertext = :{:?}", ciphertext.len());
        let decrypted_msg = sm2_ecies
            .decrypt(&secret_key, &ciphertext, message_size)
            .unwrap();
        assert_eq!(decrypted_msg, message);
    }
}
