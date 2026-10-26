// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! SM2 signature functions.

#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_l_macros;
#[macro_use]
extern crate lazy_static;

use wedpr_l_utils::{error::WedprError, traits::Signature};

use rand::rngs::SysRng;
use sm2::{
    dsa::{
        signature::{RandomizedSigner, Verifier},
        Signature as Sm2Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{sec1::ToSec1Point, subtle::ConstantTimeEq, Generate},
    SecretKey,
};
use wedpr_l_libsm::sm2::signature::SigCtx;

lazy_static! {
    // Legacy context is retained only for hashing public protocol parameters.
    // Production private-key operations use the RustCrypto backend below.
    static ref SM2_CTX: SigCtx = SigCtx::new();
}

const SM2_STANDARD_ID: &str = "1234567812345678";

// SM2 signing requires 1 <= d <= n-2: d=n-1 makes (1+d)^-1 undefined.
const ORDER_MINUS_ONE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
    0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x22,
];

fn checked_signing_key(bytes: &[u8]) -> Result<SigningKey, WedprError> {
    if bytes.len() != 32 || bool::from(bytes.ct_eq(ORDER_MINUS_ONE.as_ref())) {
        return Err(WedprError::FormatError);
    }
    // NonZeroScalar parsing checks 1 <= d < n without variable-time BigUint
    // operations. The additional constant-time check above excludes d=n-1.
    SigningKey::from_slice(SM2_STANDARD_ID, bytes)
        .map_err(|_| WedprError::FormatError)
}

fn sign_with_key(
    key: &SigningKey,
    message: &[u8],
) -> Result<Vec<u8>, WedprError> {
    // Mix fresh OS randomness into RFC6979. This also avoids deterministic
    // nonce reuse with another protocol if a caller incorrectly reuses a key.
    let signature: Sm2Signature = key
        .try_sign_with_rng(&mut SysRng, message)
        .map_err(|_| WedprError::FormatError)?;
    Ok(signature.to_bytes().to_vec())
}

/// Implements FISCO-BCOS-compatible SM2 as a Signature instance.
#[derive(Default, Debug, Clone)]
pub struct WedprSm2p256v1 {}

impl Signature for WedprSm2p256v1 {
    fn sign<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let key = checked_signing_key(private_key.as_ref())?;
        sign_with_key(&key, msg_hash.as_ref())
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        msg_hash: &T,
        signature: &T,
    ) -> bool {
        let key = match VerifyingKey::from_sec1_bytes(
            SM2_STANDARD_ID,
            public_key.as_ref(),
        ) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let signature = match Sm2Signature::from_slice(signature.as_ref()) {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        key.verify(msg_hash.as_ref(), &signature).is_ok()
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        loop {
            let secret = SecretKey::generate_from_rng(&mut rand::rng());
            if let Ok(key) = checked_signing_key(&secret.to_bytes()) {
                return (
                    key.verifying_key()
                        .to_sec1_point(false)
                        .as_bytes()
                        .to_vec(),
                    key.to_bytes().to_vec(),
                );
            }
        }
    }
}

impl WedprSm2p256v1 {
    /// Signs a message hash faster with both the private and public keys.
    pub fn sign_fast<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        public_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let key = checked_signing_key(private_key.as_ref())?;
        let provided =
            VerifyingKey::from_sec1_bytes(SM2_STANDARD_ID, public_key.as_ref())
                .map_err(|_| WedprError::FormatError)?;
        if key.verifying_key().to_sec1_point(false)
            != provided.to_sec1_point(false)
        {
            return Err(WedprError::FormatError);
        }
        sign_with_key(&key, msg_hash.as_ref())
    }

    /// Derives public key from private key.
    pub fn derive_public_key<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let key = checked_signing_key(private_key.as_ref())?;
        Ok(key.verifying_key().to_sec1_point(false).as_bytes().to_vec())
    }

    /// Computes GM standard e value, which is the hash of message and ID, EC
    /// parameters and public key.
    pub fn compute_hash_e<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let public_key_point = match SM2_CTX.load_pubkey(&public_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            },
        };
        if public_key_point.is_zero() {
            return Err(WedprError::FormatError);
        }
        Ok(SM2_CTX
            .hash(SM2_STANDARD_ID, &public_key_point, message.as_ref())
            .to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::BASE64_ENCODED_TEST_MESSAGE;

    #[test]
    fn interoperates_with_legacy_keys_signatures_and_message_hashing() {
        use wedpr_l_libsm::sm2::signature::Signature as LegacySignature;
        let signer = WedprSm2p256v1::default();
        let mut largest = ORDER_MINUS_ONE.to_vec();
        largest[31] -= 1;
        let mut one = vec![0u8; 32];
        one[31] = 1;
        for secret in [one, vec![1u8; 32], largest] {
            // The legacy private arithmetic is used only as an independent
            // test oracle with public synthetic fixtures, not in production.
            let old_secret = SM2_CTX.load_seckey(&secret).unwrap();
            let old_public = SM2_CTX.pk_from_sk(&old_secret);
            let public = signer.derive_public_key(&secret).unwrap();
            assert_eq!(public, SM2_CTX.serialize_pubkey(&old_public, false));
            for message in [
                vec![],
                vec![42u8; 32],
                b"SM2 compatibility message".to_vec(),
            ] {
                let signature = signer.sign(&secret, &message).unwrap();
                let parsed = LegacySignature::bytes_decode(&signature).unwrap();
                assert!(SM2_CTX.verify(&message, &old_public, &parsed));
                let old_signature = SM2_CTX
                    .sign(&message, &old_secret, &old_public)
                    .bytes_encode()
                    .to_vec();
                assert!(signer.verify(&public, &message, &old_signature));
                let compressed = SM2_CTX.serialize_pubkey(&old_public, true);
                let fast =
                    signer.sign_fast(&secret, &compressed, &message).unwrap();
                assert!(signer.verify(&compressed, &message, &fast));
                assert_eq!(
                    signer.compute_hash_e(&public, &message).unwrap(),
                    SM2_CTX.hash(SM2_STANDARD_ID, &old_public, &message)
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_public_keys_and_signature_scalars() {
        let signer = WedprSm2p256v1::default();
        let secret = vec![1u8; 32];
        let message = b"SM2 invalid input".to_vec();
        let public = signer.derive_public_key(&secret).unwrap();
        let signature = signer.sign(&secret, &message).unwrap();
        for length in 0..64 {
            assert!(!signer.verify(
                &public,
                &message,
                &signature[..length].to_vec()
            ));
        }
        for scalar in [vec![0u8; 32], vec![0xffu8; 32]] {
            for offset in [0, 32] {
                let mut changed = signature.clone();
                changed[offset..offset + 32].copy_from_slice(&scalar);
                assert!(!signer.verify(&public, &message, &changed));
            }
        }
        for key in [
            vec![],
            vec![0u8],
            vec![0u8; 33],
            vec![0u8; 65],
            vec![0xffu8; 65],
        ] {
            assert!(!signer.verify(&key, &message, &signature));
            assert!(signer.sign_fast(&secret, &key, &message).is_err());
            assert!(signer.compute_hash_e(&key, &message).is_err());
        }
    }

    #[test]
    fn rejects_invalid_private_key_boundaries_before_curve_operations() {
        let sm2 = WedprSm2p256v1::default();
        let (public, _) = sm2.generate_keypair();
        let message = b"key boundary test".to_vec();
        let mut order = ORDER_MINUS_ONE.to_vec();
        order[31] += 1;
        for key in &[
            vec![],
            vec![0u8; 31],
            vec![0u8; 32],
            ORDER_MINUS_ONE.to_vec(),
            order,
            vec![0xffu8; 32],
        ] {
            assert!(sm2.sign(key, &message).is_err());
            assert!(sm2.sign_fast(key, &public, &message).is_err());
            assert!(sm2.derive_public_key(key).is_err());
        }
        let mut largest = ORDER_MINUS_ONE.to_vec();
        largest[31] -= 1;
        let public = sm2.derive_public_key(&largest).unwrap();
        let signature = sm2.sign(&largest, &message).unwrap();
        assert!(sm2.verify(&public, &message, &signature));
    }

    #[test]
    fn fast_signing_rejects_a_public_key_from_another_private_key() {
        let sm2 = WedprSm2p256v1::default();
        let (_, secret) = sm2.generate_keypair();
        let (other_public, _) = sm2.generate_keypair();
        assert!(sm2
            .sign_fast(&secret, &other_public, &b"key mismatch".to_vec())
            .is_err());
    }

    #[test]
    fn test_sm2() {
        let sm2_sign = WedprSm2p256v1::default();

        // The message hash (NOT the original message) is required for
        // generating a valid signature.
        let msg_hash = BASE64_ENCODED_TEST_MESSAGE;

        let (public_key, private_key) = sm2_sign.generate_keypair();

        let public_key_derive =
            sm2_sign.derive_public_key(&private_key).unwrap();
        assert_eq!(public_key, public_key_derive);

        let signature_normal =
            sm2_sign.sign(&private_key, &msg_hash.to_vec()).unwrap();
        assert_eq!(
            true,
            sm2_sign.verify(
                &public_key_derive,
                &msg_hash.to_vec(),
                &signature_normal
            )
        );

        let signature_fast = sm2_sign
            .sign_fast(&private_key, &public_key, &msg_hash.to_vec())
            .unwrap();
        assert_eq!(
            true,
            sm2_sign.verify(&public_key, &msg_hash.to_vec(), &signature_fast)
        );
        let empty_sk = vec![0u8; 32];
        let derive_pk = sm2_sign.derive_public_key(&empty_sk).unwrap_err();
        assert_eq!(derive_pk, WedprError::FormatError);
    }
}
