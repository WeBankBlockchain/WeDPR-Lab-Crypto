// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! SM2 signature functions.

#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_l_macros;
#[macro_use]
extern crate lazy_static;

use wedpr_l_utils::{error::WedprError, traits::Signature};

use wedpr_l_libsm::sm2::signature::{SigCtx, Signature as sm2Signature};

lazy_static! {
    // Shared sm2 instance initialized for all functions.
    static ref SM2_CTX: SigCtx = SigCtx::new();
}

/// Implements FISCO-BCOS-compatible SM2 as a Signature instance.
#[derive(Default, Debug, Clone)]
pub struct WeDPRSm2p256v1 {}

impl Signature for WeDPRSm2p256v1 {
    fn sign<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError>
    {
        let secret_key = match SM2_CTX.load_seckey(&private_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            },
        };
        let derived_public_key = SM2_CTX.pk_from_sk(&secret_key);
        let signature =
            SM2_CTX.sign(&msg_hash.as_ref(), &secret_key, &derived_public_key);
        Ok(signature.bytes_encode().to_vec())
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        msg_hash: &T,
        signature: &T,
    ) -> bool
    {
        let public_key_point = match SM2_CTX.load_pubkey(&public_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return false;
            },
        };

        let parsed_sig = match sm2Signature::bytes_decode(signature.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return false;
            },
        };
        SM2_CTX.verify(&msg_hash.as_ref(), &public_key_point, &parsed_sig)
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = SM2_CTX.new_keypair();
        (
            SM2_CTX.serialize_pubkey(&public_key, false),
            SM2_CTX.serialize_seckey(&secret_key),
        )
    }
}

impl WeDPRSm2p256v1 {
    /// Signes a message hash faster with both the private and public keys.
    pub fn sign_fast<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        public_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError>
    {
        let secret_key = match SM2_CTX.load_seckey(&private_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            },
        };
        let public_key_point = match SM2_CTX.load_pubkey(&public_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            },
        };
        let signature =
            SM2_CTX.sign(&msg_hash.as_ref(), &secret_key, &public_key_point);
        Ok(signature.bytes_encode().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::BASE64_ENCODED_TEST_MESSAGE;

    #[test]
    fn test_sm2() {
        let sm2_sign = WeDPRSm2p256v1::default();

        // The message hash (NOT the original message) is required for
        // generating a valid signature.
        let msg_hash = BASE64_ENCODED_TEST_MESSAGE;

        let (public_key, private_key) = sm2_sign.generate_keypair();

        let signature_normal =
            sm2_sign.sign(&private_key, &msg_hash.to_vec()).unwrap();
        assert_eq!(
            true,
            sm2_sign.verify(&public_key, &msg_hash.to_vec(), &signature_normal)
        );

        let signature_fast = sm2_sign
            .sign_fast(&private_key, &public_key, &msg_hash.to_vec())
            .unwrap();
        assert_eq!(
            true,
            sm2_sign.verify(&public_key, &msg_hash.to_vec(), &signature_fast)
        );
    }
}
