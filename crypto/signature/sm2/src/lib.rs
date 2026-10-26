// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! SM2 signature functions.

#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_l_macros;
#[macro_use]
extern crate lazy_static;

use wedpr_l_utils::{error::WedprError, traits::Signature};

use wedpr_l_libsm::sm2::signature::{
    Seckey, SigCtx, Signature as sm2Signature,
};

lazy_static! {
    // Shared sm2 instance initialized for all functions.
    static ref SM2_CTX: SigCtx = SigCtx::new();
}

const SM2_STANDARD_ID: &str = "1234567812345678";

// SM2 signing requires 1 <= d <= n-2: d=n-1 makes (1+d)^-1 undefined.
const ORDER_MINUS_ONE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
    0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x22,
];

fn checked_secret_key(bytes: &[u8]) -> Result<Seckey, WedprError> {
    if bytes.len() != 32
        || bytes.iter().all(|byte| *byte == 0)
        || bytes >= ORDER_MINUS_ONE.as_ref()
    {
        return Err(WedprError::FormatError);
    }
    SM2_CTX
        .load_seckey(bytes)
        .map_err(|_| WedprError::FormatError)
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
        let secret_key = match checked_secret_key(private_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            },
        };
        let derived_public_key = SM2_CTX.pk_from_sk(&secret_key);
        let signature =
            SM2_CTX.sign(&msg_hash.as_ref(), &secret_key, &derived_public_key);
        if signature == sm2Signature::default() {
            return Err(WedprError::FormatError);
        }
        Ok(signature.bytes_encode().to_vec())
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        msg_hash: &T,
        signature: &T,
    ) -> bool {
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
        if public_key_point.is_zero() {
            return false;
        }
        SM2_CTX.verify(&msg_hash.as_ref(), &public_key_point, &parsed_sig)
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        loop {
            let (public_key, secret_key) = SM2_CTX.new_keypair();
            let bytes = SM2_CTX.serialize_seckey(&secret_key);
            if checked_secret_key(&bytes).is_ok() {
                return (SM2_CTX.serialize_pubkey(&public_key, false), bytes);
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
        let secret_key = match checked_secret_key(private_key.as_ref()) {
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
        let derived_public_key = SM2_CTX.pk_from_sk(&secret_key);
        if public_key_point.is_zero()
            || SM2_CTX.serialize_pubkey(&public_key_point, false)
                != SM2_CTX.serialize_pubkey(&derived_public_key, false)
        {
            return Err(WedprError::FormatError);
        }
        let signature =
            SM2_CTX.sign(&msg_hash.as_ref(), &secret_key, &public_key_point);
        if signature == sm2Signature::default() {
            return Err(WedprError::FormatError);
        }
        Ok(signature.bytes_encode().to_vec())
    }

    /// Derives public key from private key.
    pub fn derive_public_key<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
    ) -> Result<Vec<u8>, WedprError> {
        let secret_key = match checked_secret_key(private_key.as_ref()) {
            Ok(v) => v,
            Err(_) => {
                return Err(WedprError::FormatError);
            },
        };
        let public_key = SM2_CTX.pk_from_sk(&secret_key);
        if public_key.is_zero() {
            return Err(WedprError::FormatError);
        }
        Ok(SM2_CTX.serialize_pubkey(&public_key, false))
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
