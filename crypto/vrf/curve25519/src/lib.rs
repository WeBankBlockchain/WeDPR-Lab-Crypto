// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Curve25519 VRF functions.

extern crate curve25519_dalek;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use wedpr_l_utils::traits::{Hash, Vrf};

#[macro_use]
extern crate wedpr_l_macros;

use rand::thread_rng;
use sha3::Sha3_512;
use wedpr_l_crypto_hash_keccak256::WedprKeccak256;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, point_to_bytes, point_to_slice,
    scalar_to_slice, BASEPOINT_G1,
};
use wedpr_l_utils::error::WedprError;

extern crate rand;

/// Implements Curve25519 as a VRF instance.
#[derive(PartialEq, Debug, Clone, Default)]
pub struct WedprCurve25519Vrf {
    pub gamma_param: [u8; 32],
    pub c_param: [u8; 32],
    pub s_param: [u8; 32],
}

impl Vrf for WedprCurve25519Vrf {
    fn encode_proof(&self) -> Vec<u8> {
        let mut proof = Vec::new();
        proof.append(&mut self.gamma_param.to_vec());
        proof.append(&mut self.c_param.to_vec());
        proof.append(&mut self.s_param.to_vec());
        proof
    }

    fn decode_proof<T: ?Sized + AsRef<[u8]>>(
        proof: &T,
    ) -> Result<Self, WedprError> {
        if proof.as_ref().len() != 96 {
            return Err(WedprError::FormatError);
        }
        let mut gamma = [0u8; 32];
        gamma.copy_from_slice(&proof.as_ref()[0..32]);

        let mut c = [0u8; 32];
        c.copy_from_slice(&proof.as_ref()[32..64]);

        let mut s = [0u8; 32];
        s.copy_from_slice(&proof.as_ref()[64..96]);
        Ok(WedprCurve25519Vrf {
            gamma_param: gamma,
            c_param: c,
            s_param: s,
        })
    }

    fn prove<T: ?Sized + AsRef<[u8]>>(
        private_key: &T,
        message: &T,
    ) -> Result<Self, WedprError> {
        let public_key_bytes = Self::derive_public_key(private_key);
        // TODO: Merge the following logic with prove_fast.
        let private_key_hash =
            Scalar::hash_from_bytes::<Sha3_512>(private_key.as_ref());
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut public_key_bytes.clone());
        hash_vec.append(&mut message.as_ref().to_vec());

        let h_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&hash_vec);
        let gamma = h_point * private_key_hash;
        let blinding_k = Scalar::random(&mut thread_rng());
        let base_k = *BASEPOINT_G1 * blinding_k;
        let point_k = h_point * blinding_k;

        let mut c_vec = Vec::new();
        c_vec.append(&mut hash_vec.clone());
        c_vec.append(&mut public_key_bytes.clone());
        c_vec.append(&mut point_to_bytes(&gamma));
        c_vec.append(&mut point_to_bytes(&base_k));
        c_vec.append(&mut point_to_bytes(&point_k));

        let c_scalar = Scalar::hash_from_bytes::<Sha3_512>(&c_vec);
        let s = blinding_k - (c_scalar * private_key_hash);
        let proof = WedprCurve25519Vrf {
            gamma_param: point_to_slice(&gamma),
            c_param: scalar_to_slice(&c_scalar),
            s_param: scalar_to_slice(&s),
        };
        Ok(proof)
    }

    fn prove_fast<T: ?Sized + AsRef<[u8]>>(
        private_key: &T,
        public_key: &T,
        message: &T,
    ) -> Result<Self, WedprError> {
        let public_key_bytes = public_key.as_ref().to_vec();
        let private_key_hash =
            Scalar::hash_from_bytes::<Sha3_512>(private_key.as_ref());
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut public_key_bytes.clone());
        hash_vec.append(&mut message.as_ref().to_vec());

        let h_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&hash_vec);
        let gamma = h_point * private_key_hash;
        let blinding_k = Scalar::random(&mut thread_rng());
        let base_k = *BASEPOINT_G1 * blinding_k;
        let point_k = h_point * blinding_k;

        let mut c_vec = Vec::new();
        c_vec.append(&mut hash_vec.clone());
        c_vec.append(&mut public_key_bytes.clone());
        c_vec.append(&mut point_to_bytes(&gamma));
        c_vec.append(&mut point_to_bytes(&base_k));
        c_vec.append(&mut point_to_bytes(&point_k));

        let c_scalar = Scalar::hash_from_bytes::<Sha3_512>(&c_vec);
        let s = blinding_k - (c_scalar * private_key_hash);
        let proof = WedprCurve25519Vrf {
            gamma_param: point_to_slice(&gamma),
            c_param: scalar_to_slice(&c_scalar),
            s_param: scalar_to_slice(&s),
        };
        Ok(proof)
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
    ) -> bool {
        let gamma_point = bytes_to_point!(self.gamma_param.as_ref());
        let public_key_point = bytes_to_point!(public_key.as_ref());
        let c_scalar = bytes_to_scalar!(&self.c_param);
        let s_scalar = bytes_to_scalar!(&self.s_param);
        let u = (public_key_point * c_scalar) + (*BASEPOINT_G1 * s_scalar);
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut public_key.as_ref().to_vec());
        hash_vec.append(&mut message.as_ref().to_vec());

        let h_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&hash_vec);
        let v = (gamma_point * c_scalar) + (h_point * s_scalar);

        let mut c_vec = Vec::new();
        c_vec.append(&mut hash_vec.clone());
        c_vec.append(&mut public_key.as_ref().to_vec());
        c_vec.append(&mut self.gamma_param.clone().to_vec());
        c_vec.append(&mut point_to_bytes(&u));
        c_vec.append(&mut point_to_bytes(&v));

        let expect_c_scalar = Scalar::hash_from_bytes::<Sha3_512>(&c_vec);

        c_scalar == expect_c_scalar
    }

    fn derive_public_key<T: ?Sized + AsRef<[u8]>>(private_key: &T) -> Vec<u8> {
        let private_key_hash =
            Scalar::hash_from_bytes::<Sha3_512>(private_key.as_ref());
        let pubkey = *BASEPOINT_G1 * private_key_hash;
        point_to_bytes(&pubkey)
    }

    fn proof_to_hash(&self) -> Result<Vec<u8>, WedprError> {
        let gamma = bytes_to_point(&self.gamma_param)?;
        // Order 8 is used as recommended by IETF
        // draft-sullivan-hash-to-curve-00.
        let base = gamma * Scalar::from(8u8);
        let hash = WedprKeccak256::default();
        Ok(hash.hash(&point_to_bytes(&base)))
    }

    fn is_valid_public_key<T: ?Sized + AsRef<[u8]>>(public_key: &T) -> bool {
        return match bytes_to_point(&public_key.as_ref()) {
            Ok(_) => true,
            Err(_) => false,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::tool::string_to_bytes_utf8;

    #[test]
    fn test_vrf() {
        let private_key = string_to_bytes_utf8("random key");
        let public_key = WedprCurve25519Vrf::derive_public_key(&private_key);
        let message = string_to_bytes_utf8("test message");
        assert_eq!(WedprCurve25519Vrf::is_valid_public_key(&public_key), true);
        // Private key is not a public key.
        assert_eq!(
            WedprCurve25519Vrf::is_valid_public_key(&private_key),
            false
        );

        let proof = WedprCurve25519Vrf::prove(&private_key, &message).unwrap();
        assert_eq!(proof.verify(&public_key, &message), true);

        let proof_hash = proof.proof_to_hash().unwrap();
        // TODO: Add the expected value here.
        println!("hash_proof = {:?}", proof_hash);

        let invalid_private_key = string_to_bytes_utf8("invalid key");
        assert_eq!(
            WedprCurve25519Vrf::prove(&invalid_private_key, &message)
                .unwrap()
                .verify(&public_key, &message),
            false
        );

        let recovered_proof =
            WedprCurve25519Vrf::decode_proof(&proof.encode_proof()).unwrap();
        assert_eq!(recovered_proof.verify(&public_key, &message), true);
    }
}
