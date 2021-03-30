// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Secp256k1 ECIES functions.

use wedpr_l_utils::{error::WedprError, traits::Ecies};

#[macro_use]
extern crate wedpr_l_macros;

/// Implements a ECIES instance on Secp256k1 curve.
#[derive(Default, Debug, Clone)]
pub struct WedprSecp256k1Ecies {}

impl Ecies for WedprSecp256k1Ecies {
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
    ) -> Result<Vec<u8>, WedprError>
    {
        match ecies::encrypt(public_key.as_ref(), message.as_ref()) {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => {
                wedpr_println!("secp256k1 ECIES encrypt failed");
                return Err(WedprError::FormatError);
            },
        }
    }

    fn decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        ciphertext: &T,
    ) -> Result<Vec<u8>, WedprError>
    {
        match ecies::decrypt(private_key.as_ref(), ciphertext.as_ref()) {
            Ok(v) => Ok(v.to_vec()),
            Err(_) => {
                wedpr_println!("secp256k1 ECIES decrypt failed");
                return Err(WedprError::FormatError);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::{
        BASE64_ENCODED_TEST_MESSAGE, SECP256K1_TEST_PUBLIC_KEY,
        SECP256K1_TEST_SECRET_KEY,
    };

    #[test]
    fn test_secp256k1_ecies() {
        let secp256k1_ecies = WedprSecp256k1Ecies::default();

        let ciphertext = secp256k1_ecies
            .encrypt(
                &SECP256K1_TEST_PUBLIC_KEY.to_vec(),
                &BASE64_ENCODED_TEST_MESSAGE.to_vec(),
            )
            .unwrap();
        let decrypted_msg = secp256k1_ecies
            .decrypt(&SECP256K1_TEST_SECRET_KEY.to_vec(), &ciphertext)
            .unwrap();
        assert_eq!(decrypted_msg, BASE64_ENCODED_TEST_MESSAGE);
    }
}
