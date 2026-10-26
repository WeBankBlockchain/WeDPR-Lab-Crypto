// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Ed25519 signature functions.

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use std::convert::{TryFrom, TryInto};
use wedpr_l_utils::{error::WedprError, traits::Signature};

/// Implements FISCO-BCOS-compatible Ed25519 as a Signature instance.
#[derive(Default, Debug, Clone, Copy)]
pub struct WedprEd25519 {}

impl Signature for WedprEd25519 {
    fn sign<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let secret: &[u8; 32] = private_key
            .as_ref()
            .try_into()
            .map_err(|_| WedprError::DecodeError)?;
        let signing_key = SigningKey::from_bytes(secret);
        Ok(signing_key.sign(msg_hash.as_ref()).to_bytes().to_vec())
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        msg_hash: &T,
        signature: &T,
    ) -> bool {
        let public: &[u8; 32] = match public_key.as_ref().try_into() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let public_key_parser = match VerifyingKey::from_bytes(public) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let signature_parser =
            match Ed25519Signature::try_from(signature.as_ref()) {
                Ok(v) => v,
                Err(_) => return false,
            };
        return match public_key_parser
            .verify_strict(msg_hash.as_ref(), &signature_parser)
        {
            Ok(_) => true,
            Err(_) => false,
        };
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let signing_key = SigningKey::generate(&mut OsRng);
        (
            signing_key.verifying_key().to_bytes().to_vec(),
            signing_key.to_bytes().to_vec(),
        )
    }
}

impl WedprEd25519 {
    /// Derives public key from private key.
    pub fn derive_public_key<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let secret: &[u8; 32] = private_key
            .as_ref()
            .try_into()
            .map_err(|_| WedprError::DecodeError)?;
        Ok(SigningKey::from_bytes(secret)
            .verifying_key()
            .to_bytes()
            .to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::BASE64_ENCODED_TEST_MESSAGE;

    #[test]
    fn rfc8032_empty_message_vector_preserves_key_and_signature_formats() {
        fn decode(value: &str) -> Vec<u8> {
            (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
                .collect()
        }
        // RFC 8032 section 7.1, TEST 1. These are public test fixtures.
        let secret = decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        );
        let public = decode(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        );
        let signature = decode(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        let ed25519 = WedprEd25519::default();
        assert_eq!(ed25519.derive_public_key(&secret).unwrap(), public);
        assert_eq!(ed25519.sign(&secret, &Vec::new()).unwrap(), signature);
        assert!(ed25519.verify(&public, &Vec::new(), &signature));
        for len in [0, 31, 33, 64] {
            assert!(ed25519.sign(&vec![1u8; len], &Vec::new()).is_err());
            assert!(ed25519.derive_public_key(&vec![1u8; len]).is_err());
        }
    }

    #[test]
    fn rejects_identity_public_key_and_universal_identity_signature() {
        let ed25519 = WedprEd25519::default();
        let mut identity = vec![0u8; 32];
        identity[0] = 1;
        let mut forged_signature = vec![0u8; 64];
        forged_signature[..32].copy_from_slice(&identity);
        for message in &[b"first message".to_vec(), b"second message".to_vec()]
        {
            assert!(!ed25519.verify(&identity, message, &forged_signature));
        }
    }

    #[test]
    fn rejects_noncanonical_scalars_and_malformed_encodings() {
        let ed25519 = WedprEd25519::default();
        let (public, secret) = ed25519.generate_keypair();
        let message = b"signature validation".to_vec();
        let signature = ed25519.sign(&secret, &message).unwrap();
        assert!(ed25519.verify(&public, &message, &signature));
        let mut malformed = signature.clone();
        malformed[32..].fill(0xff);
        assert!(!ed25519.verify(&public, &message, &malformed));
        for length in 0..64 {
            assert!(!ed25519.verify(
                &public,
                &message,
                &signature[..length].to_vec()
            ));
        }
        assert!(!ed25519.verify(&vec![0u8; 31], &message, &signature));
    }

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
