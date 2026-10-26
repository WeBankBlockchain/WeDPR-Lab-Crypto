// Copyright 2024 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! The legacy secp256k1 VRF is disabled: it leaks keys across messages and its
//! output is publicly predictable. Updating the nonce alone is insufficient.
//!
//! All legacy proof operations fail closed. Key parsing/derivation remains
//! available. See the repository README for migration requirements. No
//! experimental replacement protocol is enabled by this crate.

#![forbid(unsafe_code)]

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use wedpr_l_utils::{error::WedprError, traits::Vrf};

/// Disabled legacy VRF. Public fields are retained for source compatibility;
/// constructing this struct manually does not enable legacy verification.
#[derive(PartialEq, Debug, Clone, Default)]
pub struct WedprSecp256k1Vrf {
    pub gamma_param: Vec<u8>,
    pub c_param: Vec<u8>,
    pub s_param: Vec<u8>,
}

// Only canonical, compressed, nonidentity secp256k1 points are accepted.
fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, WedprError> {
    if bytes.len() != 33 || !matches!(bytes[0], 2 | 3) {
        return Err(WedprError::FormatError);
    }
    PublicKey::from_slice(bytes).map_err(|_| WedprError::FormatError)
}

fn parse_secret_key(bytes: &[u8]) -> Result<SecretKey, WedprError> {
    if bytes.len() != 32 {
        return Err(WedprError::FormatError);
    }
    SecretKey::from_slice(bytes).map_err(|_| WedprError::FormatError)
}

impl Vrf for WedprSecp256k1Vrf {
    /// Disabled. Empty bytes are an invalid proof, never a legacy encoding.
    fn encode_proof(&self) -> Vec<u8> {
        Vec::new()
    }

    fn decode_proof<T: ?Sized + AsRef<[u8]>>(
        _: &T,
    ) -> Result<Self, WedprError> {
        Err(WedprError::VerificationError)
    }

    fn prove<T: ?Sized + AsRef<[u8]>>(
        _: &T,
        _: &T,
    ) -> Result<Self, WedprError> {
        Err(WedprError::VerificationError)
    }

    fn prove_fast<T: ?Sized + AsRef<[u8]>>(
        _: &T,
        _: &T,
        _: &T,
    ) -> Result<Self, WedprError> {
        Err(WedprError::VerificationError)
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(&self, _: &T, _: &T) -> bool {
        false
    }

    fn derive_public_key<T: ?Sized + AsRef<[u8]>>(private_key: &T) -> Vec<u8> {
        match parse_secret_key(private_key.as_ref()) {
            Ok(key) => {
                PublicKey::from_secret_key(&Secp256k1::signing_only(), &key)
                    .serialize()
                    .to_vec()
            },
            Err(_) => Vec::new(),
        }
    }

    fn is_valid_public_key<T: ?Sized + AsRef<[u8]>>(public_key: &T) -> bool {
        parse_public_key(public_key.as_ref()).is_ok()
    }

    fn proof_to_hash(&self) -> Result<Vec<u8>, WedprError> {
        Err(WedprError::VerificationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_legacy_proof_operations_fail_closed() {
        let secret = vec![1u8; 32];
        let public = WedprSecp256k1Vrf::derive_public_key(&secret);
        let message = b"quarantine regression".to_vec();
        assert_eq!(public.len(), 33);
        assert!(WedprSecp256k1Vrf::is_valid_public_key(&public));
        assert!(WedprSecp256k1Vrf::prove(&secret, &message).is_err());
        assert!(
            WedprSecp256k1Vrf::prove_fast(&secret, &public, &message).is_err()
        );
        for length in [0, 96, 97, 98] {
            assert!(
                WedprSecp256k1Vrf::decode_proof(&vec![0u8; length]).is_err()
            );
        }
        // Public fields and Default must not bypass the quarantine.
        for proof in [
            WedprSecp256k1Vrf::default(),
            WedprSecp256k1Vrf {
                gamma_param: public.clone(),
                c_param: vec![0u8; 32],
                s_param: vec![1u8; 32],
            },
        ] {
            assert!(!proof.verify(&public, &message));
            assert!(proof.proof_to_hash().is_err());
            assert!(proof.encode_proof().is_empty());
        }
    }

    #[test]
    fn key_tools_reject_invalid_and_noncanonical_inputs() {
        for invalid in [
            vec![],
            vec![1u8; 31],
            vec![0u8; 32],
            vec![0xffu8; 32],
            vec![1u8; 33],
        ] {
            assert!(WedprSecp256k1Vrf::derive_public_key(&invalid).is_empty());
        }
        for invalid in [
            vec![],
            vec![0u8],
            vec![0u8; 33],
            vec![4u8; 65],
            vec![0xffu8; 33],
        ] {
            assert!(!WedprSecp256k1Vrf::is_valid_public_key(&invalid));
        }
    }
}
