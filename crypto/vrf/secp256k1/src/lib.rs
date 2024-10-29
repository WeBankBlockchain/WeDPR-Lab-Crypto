// Copyright 2024 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! secp256k1 VRF functions.

extern crate k256;

use k256::{
    elliptic_curve::{
        generic_array::GenericArray, rand_core::OsRng, sec1::FromEncodedPoint,
        PrimeField,
    },
    AffinePoint, EncodedPoint, Scalar,
};
use wedpr_l_utils::traits::Vrf;

use crate::k256::elliptic_curve::{
    group::{prime::PrimeCurveAffine, GroupEncoding},
    Field,
};
use sha2::{Digest, Sha256};
use wedpr_l_utils::error::WedprError;

const SECP256K1_POINT_LENGTH: usize = 33;
const SECP256K1_SCALAR_LENGTH: usize = 32;

/// Implements secp256k1 as a VRF instance.
#[derive(PartialEq, Debug, Clone, Default)]
pub struct WedprSecp256k1Vrf {
    // 33 bytes
    pub gamma_param: Vec<u8>,
    // 32 bytes
    pub c_param: Vec<u8>,
    // 32 bytes
    pub s_param: Vec<u8>,
}

fn hash_to_scalar(hash_vec: &Vec<u8>) -> Result<Scalar, WedprError> {
    let mut hasher = Sha256::new();
    hasher.update(hash_vec);
    let hash_vec = hasher.finalize().to_vec();

    let array: GenericArray<u8, _> =
        GenericArray::clone_from_slice(hash_vec.as_slice());

    let scalar_option = k256::Scalar::from_repr(array);

    if scalar_option.is_some().into() {
        return Ok(scalar_option.unwrap());
    } else {
        return Err(WedprError::FormatError);
    };
}

fn bytes_to_affine(bytes: &[u8]) -> Result<AffinePoint, WedprError> {
    let encoded_point = EncodedPoint::from_bytes(bytes);
    match encoded_point {
        Ok(encoded_point) => {
            let affine_point = AffinePoint::from_encoded_point(&encoded_point);
            if affine_point.is_some().into() {
                return Ok(affine_point.unwrap());
            } else {
                return Err(WedprError::FormatError);
            }
        },
        Err(_) => Err(WedprError::FormatError),
    }
}

fn bytes_to_scalar(bytes: &[u8]) -> Result<Scalar, WedprError> {
    let scalar_option =
        k256::Scalar::from_repr(GenericArray::clone_from_slice(bytes));
    if scalar_option.is_some().into() {
        return Ok(scalar_option.unwrap());
    } else {
        return Err(WedprError::FormatError);
    }
}

impl Vrf for WedprSecp256k1Vrf {
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
        if proof.as_ref().len()
            != (SECP256K1_POINT_LENGTH
                + SECP256K1_SCALAR_LENGTH
                + SECP256K1_SCALAR_LENGTH)
        {
            return Err(WedprError::FormatError);
        }
        let mut gamma = [0u8; SECP256K1_POINT_LENGTH];
        gamma.copy_from_slice(&proof.as_ref()[0..SECP256K1_POINT_LENGTH]);

        let mut c = [0u8; SECP256K1_SCALAR_LENGTH];
        c.copy_from_slice(
            &proof.as_ref()[SECP256K1_POINT_LENGTH
                ..SECP256K1_POINT_LENGTH + SECP256K1_SCALAR_LENGTH],
        );

        let mut s = [0u8; SECP256K1_SCALAR_LENGTH];
        s.copy_from_slice(
            &proof.as_ref()[SECP256K1_POINT_LENGTH + SECP256K1_SCALAR_LENGTH
                ..SECP256K1_POINT_LENGTH
                    + SECP256K1_SCALAR_LENGTH
                    + SECP256K1_SCALAR_LENGTH],
        );
        Ok(WedprSecp256k1Vrf {
            gamma_param: gamma.to_vec(),
            c_param: c.to_vec(),
            s_param: s.to_vec(),
        })
    }

    fn prove<T: ?Sized + AsRef<[u8]>>(
        private_key: &T,
        message: &T,
    ) -> Result<Self, WedprError>
    where
        Self: Sized,
    {
        let private_key_result =
            k256::SecretKey::from_slice(private_key.as_ref());

        let private_key = match private_key_result {
            Ok(private_key) => private_key,
            Err(_) => return Err(WedprError::FormatError),
        };

        let private_key_scalar: Scalar =
            private_key.as_scalar_primitive().into();

        let public_key = private_key.public_key();

        let public_key_bytes = public_key.as_affine().to_bytes().to_vec();

        let message = message.as_ref();

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut public_key_bytes.clone());
        hash_vec.append(&mut message.to_vec());

        let h_scalar_result = hash_to_scalar(&hash_vec);
        let h_scalar = match h_scalar_result {
            Ok(h_scalar_result) => h_scalar_result,
            Err(_) => return Err(WedprError::FormatError),
        };

        let base_point = k256::AffinePoint::generator();
        let h_point = base_point * h_scalar;

        let gamma = h_point * private_key_scalar;

        let blinding_k = k256::Scalar::random(&mut OsRng);

        let scalar_k = private_key_scalar * blinding_k;

        let point_k = base_point * scalar_k;

        let point_kh = h_point * scalar_k;

        let mut c_vec = Vec::new();
        c_vec.append(&mut h_point.to_bytes().to_vec());
        c_vec.append(&mut gamma.to_bytes().to_vec());
        c_vec.append(&mut point_k.to_bytes().to_vec());
        c_vec.append(&mut point_kh.to_bytes().to_vec());

        let c_scalar_result = hash_to_scalar(&c_vec);
        let c_scalar = match c_scalar_result {
            Ok(c_scalar_result) => c_scalar_result,
            Err(_) => return Err(WedprError::FormatError),
        };

        let s = scalar_k + (c_scalar * private_key_scalar);

        // println!("gamma : {:?}", gamma.to_bytes().to_vec());
        // println!("c : {:?}", c_scalar.to_bytes().to_vec());
        // println!("s : {:?}", s.to_bytes().to_vec());

        return Ok(WedprSecp256k1Vrf {
            gamma_param: gamma.to_bytes().to_vec(),
            c_param: c_scalar.to_bytes().to_vec(),
            s_param: s.to_bytes().to_vec(),
        });
    }

    fn prove_fast<T: ?Sized + AsRef<[u8]>>(
        private_key: &T,
        public_key: &T,
        message: &T,
    ) -> Result<Self, WedprError>
    where
        Self: Sized,
    {
        // TODO: We found use input public key directly is slower than derive
        // public key from private key
        Self::prove(private_key, message)
    }

    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
    ) -> bool {
        let public_key_bytes = public_key.as_ref().to_vec();

        let public_key_point = match bytes_to_affine(&public_key_bytes) {
            Ok(public_key_point) => public_key_point,
            Err(_) => return false,
        };

        let message = message.as_ref();

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut public_key_bytes.clone());
        hash_vec.append(&mut message.to_vec());

        let base_point = k256::AffinePoint::generator();

        let h_scalar = hash_to_scalar(&hash_vec).unwrap();
        let h_point = base_point * h_scalar;

        let gamma = match bytes_to_affine(&self.gamma_param) {
            Ok(gamma) => gamma,
            Err(_) => return false,
        };

        let c = match bytes_to_scalar(&self.c_param) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let s = match bytes_to_scalar(&self.s_param) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let u = (base_point * s) - (public_key_point * c);
        let v = (h_point * s) - (gamma * c);

        let mut c_vec = Vec::new();
        c_vec.append(&mut h_point.to_bytes().to_vec());
        c_vec.append(&mut self.gamma_param.clone());
        c_vec.append(&mut u.to_bytes().to_vec());
        c_vec.append(&mut v.to_bytes().to_vec());

        let c_scalar_result = hash_to_scalar(&c_vec);
        let c_scalar = match c_scalar_result {
            Ok(c_scalar_result) => c_scalar_result,
            Err(_) => return false,
        };

        return c_scalar.to_bytes().to_vec().eq(self.c_param.as_slice());
    }

    fn derive_public_key<T: ?Sized + AsRef<[u8]>>(private_key: &T) -> Vec<u8> {
        let private_key_result =
            k256::SecretKey::from_slice(private_key.as_ref());

        let private_key = match private_key_result {
            Ok(private_key) => private_key,
            Err(_) => return Vec::new(),
        };

        let public_key = private_key.public_key();

        public_key.as_affine().to_bytes().to_vec()
    }

    fn is_valid_public_key<T: ?Sized + AsRef<[u8]>>(public_key: &T) -> bool {
        let public_key_bytes = public_key.as_ref().to_vec();
        match bytes_to_affine(&public_key_bytes) {
            Ok(_) => return true,
            Err(_) => return false,
        };
    }

    fn proof_to_hash(&self) -> Result<Vec<u8>, WedprError> {
        let gamma = match bytes_to_affine(&self.gamma_param) {
            Ok(gamma) => gamma,
            Err(_) => return Err(WedprError::FormatError),
        };

        let base_order = Scalar::from_u128(8);
        let base = gamma * base_order;

        let mut hasher = Sha256::new();
        hasher.update(base.to_bytes().as_slice());
        let hash_vec = hasher.finalize().to_vec();

        Ok(hash_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_vrf() {
        let private_key = k256::SecretKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let message = "hello world".as_bytes().to_vec();

        let proof = WedprSecp256k1Vrf::prove(
            &private_key.to_bytes().to_vec(),
            &message,
        )
        .unwrap();

        assert_eq!(
            proof.verify(&public_key.as_affine().to_bytes().to_vec(), &message),
            true
        );
        // println!("proof hash : {:?}", proof.proof_to_hash().unwrap());
    }

    #[test]
    fn test_encode_proof() {
        let private_key = k256::SecretKey::random(&mut OsRng);
        // let public_key = private_key.public_key();
        let message = "hello world".as_bytes().to_vec();

        let proof = WedprSecp256k1Vrf::prove(
            &private_key.to_bytes().to_vec(),
            &message,
        )
        .unwrap();
        let encoded_proof = proof.encode_proof();
        // println!("encoded_proof : {:?}, length: {}", encoded_proof,
        // encoded_proof.len());
        let decoded_proof =
            WedprSecp256k1Vrf::decode_proof(&encoded_proof).unwrap();
        assert_eq!(decoded_proof, proof);

        assert_eq!(
            proof.verify(
                &private_key.public_key().as_affine().to_bytes().to_vec(),
                &message
            ),
            true
        );
    }

    #[test]
    fn test_utils() {
        let private_key = k256::SecretKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        let expected_pk = WedprSecp256k1Vrf::derive_public_key(
            &private_key.to_bytes().to_vec(),
        );
        assert_eq!(public_key.as_affine().to_bytes().to_vec(), expected_pk);

        assert_eq!(WedprSecp256k1Vrf::is_valid_public_key(&expected_pk), true);
    }
}
