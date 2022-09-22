//! This module provides bls12_381 equality test

extern crate bls12_381;
use bls12_381::{G1Projective, G2Projective, hash_to_curve::{HashToCurve, ExpandMsgXmd}, G1Affine, G2Affine};
use bls12_381::Scalar;
use rand;
use sha2;
use bls12_381::pairing;
use ff::Field;

pub struct WedprBls128Cipher {
    u_point: G1Projective,
    v_point: G2Projective
}

pub fn message_to_g1_point(message: &[u8]) -> G1Projective {
    let DOMAIN: &[u8] = b"wedpr-BLS12381G1:SHA-256_";
    let g1_point = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
        &message, DOMAIN,
    );
    return g1_point;
}

pub fn encrypt_message(message: &[u8]) -> WedprBls128Cipher {
    let message_g1 = message_to_g1_point(message);
    // let mut rng = rand_core::OsRng::default();
    let mut rng = rand::rngs::OsRng::default();
    let blinding = Scalar::random(rng);
    let base_g2 = G2Projective::generator();
    let u_point = message_g1* blinding;
    let v_point = base_g2 * blinding;
    return WedprBls128Cipher {
        u_point,
        v_point
    }
}

pub fn equality_test(cipher1: &WedprBls128Cipher, cipher2: &WedprBls128Cipher) -> bool {
    G1Affine::from(cipher1.u_point);
    let pairing1 = pairing(&G1Affine::from(cipher1.u_point), &G2Affine::from(cipher2.v_point));
    let pairing2 = pairing(&G1Affine::from(cipher2.u_point), &G2Affine::from(cipher1.v_point));
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
        let cipher2_m1 = encrypt_message(message1);

        let cipher1_m2 = encrypt_message(message2);
        let cipher2_m2 = encrypt_message(message2);

        assert_eq!(equality_test(&cipher1_m1, &cipher2_m1), true);
        assert_eq!(equality_test(&cipher2_m1, &cipher1_m1), true);

        assert_eq!(equality_test(&cipher1_m2, &cipher2_m2), true);
        assert_eq!(equality_test(&cipher2_m2, &cipher1_m2), true);

        assert_eq!(equality_test(&cipher1_m1, &cipher2_m2), false);
        assert_eq!(equality_test(&cipher2_m2, &cipher1_m1), false);

        assert_eq!(equality_test(&cipher1_m2, &cipher1_m1), false);
        assert_eq!(equality_test(&cipher1_m1, &cipher1_m2), false);
    }
}
