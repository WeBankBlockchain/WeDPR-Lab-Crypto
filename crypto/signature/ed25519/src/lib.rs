// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Ed25519 signature functions.

// #[macro_use]
// extern crate wedpr_l_macros;
// #[macro_use]
// extern crate lazy_static;

use ed25519_dalek::{
    ed25519::signature::Signature as ed25519_signature_try, Keypair, PublicKey,
    SecretKey, Signature as ed25519_signature, Signer, Verifier,
};
use rand::rngs::OsRng;
use wedpr_l_utils::{error::WedprError, traits::Signature};

/// Implements Ed25519 as a Signature instance.
#[derive(Default, Debug, Clone, Copy)]
pub struct WedprEd25519 {}

impl Signature for WedprEd25519 {
    fn sign<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let secret_key: SecretKey =
            match SecretKey::from_bytes(&private_key.as_ref()) {
                Ok(v) => v,
                Err(_) => return Err(WedprError::DecodeError),
            };
        let public_key: PublicKey = (&secret_key).into();
        let key_pair = Keypair {
            secret: secret_key,
            public: public_key,
        };
        Ok(key_pair.sign(msg_hash.as_ref()).to_bytes().to_vec())
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        msg_hash: &T,
        signature: &T,
    ) -> bool {
        let public_key_parser: PublicKey =
            match PublicKey::from_bytes(&public_key.as_ref()) {
                Ok(v) => v,
                Err(_) => return false,
            };

        let signature_parser: ed25519_signature =
            match ed25519_signature::from_bytes(signature.as_ref()) {
                Ok(v) => v,
                Err(_) => return false,
            };
        return match public_key_parser
            .verify(msg_hash.as_ref(), &signature_parser)
        {
            Ok(_) => true,
            Err(_) => false,
        };
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let mut cs_prng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut cs_prng);
        (
            keypair.public.to_bytes().to_vec(),
            keypair.secret.to_bytes().to_vec(),
        )
    }
}

impl WedprEd25519 {
    /// Derives public key from private key.
    pub fn derive_public_key<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let secret_key: SecretKey =
            match SecretKey::from_bytes(&private_key.as_ref()) {
                Ok(v) => v,
                Err(_) => return Err(WedprError::DecodeError),
            };
        let public_key: PublicKey = (&secret_key).into();

        Ok(public_key.to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::BASE64_ENCODED_TEST_MESSAGE;

    #[test]
    fn test_ed25519() {
        let ed25519 = WedprEd25519::default();
        let (public_key, secret_key) = ed25519.generate_keypair();

        // The message hash (NOT the original message) is required for
        // generating a valid signature.
        let msg_hash = BASE64_ENCODED_TEST_MESSAGE;

        let signature = ed25519.sign(&secret_key, &msg_hash.to_vec()).unwrap();
        assert_eq!(
            true,
            ed25519.verify(
                &public_key.to_vec(),
                &msg_hash.to_vec(),
                &signature
            )
        );
    }
}
