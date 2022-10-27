//! This module provides bls12_381 equality test

extern crate bls12_381;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use ff::Field;
use rand;
use sha2;
use wedpr_l_utils::error::WedprError;

#[macro_use]
extern crate wedpr_l_macros;

pub struct WedprBls128Cipher {
    u_point: G1Projective,
    v_point: G2Projective,
}

impl WedprBls128Cipher {
    pub fn to_bytes(&self) -> Vec<u8> {
        let u_point_bytes = G1Affine::from(self.u_point).to_compressed();

        let v_point_bytes = G2Affine::from(self.v_point).to_compressed();
        let result: Vec<u8> =
            [u_point_bytes.as_slice(), v_point_bytes.as_slice()].concat();
        return result;
    }

    pub fn from_bytes(message: &[u8]) -> Result<WedprBls128Cipher, WedprError> {
        if message.len() != 144 {
            return Err(WedprError::FormatError);
        }

        let mut u_point_bytes: [u8; 48] = [0; 48];
        u_point_bytes.copy_from_slice(&message[0..48]);

        if G1Affine::from_compressed(&u_point_bytes)
            .is_some()
            .unwrap_u8()
            != 1
        {
            return Err(WedprError::FormatError);
        }
        let u_point: G1Affine =
            G1Affine::from_compressed(&u_point_bytes).unwrap();
        let mut v_point_bytes: [u8; 96] = [0; 96];
        v_point_bytes.copy_from_slice(&message[48..144]);
        println!(
            "v1:{}",
            G2Affine::from_compressed(&v_point_bytes)
                .is_some()
                .unwrap_u8()
        );
        if G2Affine::from_compressed(&v_point_bytes)
            .is_some()
            .unwrap_u8()
            != 1
        {
            return Err(WedprError::FormatError);
        }
        let v_point: G2Affine =
            G2Affine::from_compressed(&v_point_bytes).unwrap();

        Ok(WedprBls128Cipher {
            u_point: G1Projective::from(u_point),
            v_point: G2Projective::from(v_point),
        })
    }
}

fn message_to_g1_point(message: &[u8]) -> G1Projective {
    let domain: &[u8] = b"wedpr-BLS12381G1:SHA-256_";
    let g1_point = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
        &message, domain,
    );
    return g1_point;
}

pub fn encrypt_message(message: &[u8]) -> WedprBls128Cipher {
    let message_g1 = message_to_g1_point(message);
    let rng = rand::rngs::OsRng::default();
    let blinding = Scalar::random(rng);
    let base_g2 = G2Projective::generator();
    let u_point = message_g1 * blinding;
    let v_point = base_g2 * blinding;
    return WedprBls128Cipher { u_point, v_point };
}

pub fn equality_test(
    cipher1: &WedprBls128Cipher,
    cipher2: &WedprBls128Cipher,
) -> bool {
    let pairing1 = pairing(
        &G1Affine::from(cipher1.u_point),
        &G2Affine::from(cipher2.v_point),
    );
    let pairing2 = pairing(
        &G1Affine::from(cipher2.u_point),
        &G2Affine::from(cipher1.v_point),
    );
    return pairing1.eq(&pairing2);
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_equality() {
        let message1: &[u8] = b"hello world";
        let message2: &[u8] = b"hello wedpr";
        let cipher1_m1 = encrypt_message(message1);
        let cipher1_m1_bytes = cipher1_m1.to_bytes();
        let cipher1_m1_recover =
            WedprBls128Cipher::from_bytes(&cipher1_m1_bytes).unwrap();
        let cipher2_m1 = encrypt_message(message1);

        let cipher1_m2 = encrypt_message(message2);
        let cipher2_m2 = encrypt_message(message2);

        assert_eq!(equality_test(&cipher1_m1, &cipher2_m1), true);
        assert_eq!(equality_test(&cipher2_m1, &cipher1_m1), true);
        assert_eq!(equality_test(&cipher1_m1_recover, &cipher2_m1), true);

        assert_eq!(equality_test(&cipher1_m2, &cipher2_m2), true);
        assert_eq!(equality_test(&cipher2_m2, &cipher1_m2), true);

        assert_eq!(equality_test(&cipher1_m1, &cipher2_m2), false);
        assert_eq!(equality_test(&cipher2_m2, &cipher1_m1), false);
        assert_eq!(equality_test(&cipher2_m2, &cipher1_m1_recover), false);

        assert_eq!(equality_test(&cipher1_m2, &cipher1_m1), false);
        assert_eq!(equality_test(&cipher1_m1, &cipher1_m2), false);
    }
}
