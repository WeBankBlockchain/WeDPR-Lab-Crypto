// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Zero-knowledge proof (ZKP) functions based on DLP construction.

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use wedpr_l_crypto_zkp_utils::{
    bytes_to_scalar, get_random_scalar, hash_to_scalar, point_to_bytes,
    scalar_to_bytes,
};
use wedpr_l_protos::generated::zkp::BalanceProof;
use wedpr_l_utils::error::WedprError;

/// Proves three commitments satisfying a sum relationship, i.e.
/// the values embedded in them satisfying c1_value + c2_value = c3_value.
/// c3_value is not in the argument list, and will be directly computed from
/// c1_value + c2_value.
/// c?_blinding are random blinding values used in the commitments.
/// The commitments (c?_value*value_basepoint+c?_blinding*blinding_basepoint)
/// are not in the argument list, as they are not directly used by the proof
/// generation.
/// It returns a proof for the above sum relationship.
pub fn prove_sum_relationship(
    c1_value: u64,
    c2_value: u64,
    c1_blinding: &Scalar,
    c2_blinding: &Scalar,
    c3_blinding: &Scalar,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> BalanceProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let blinding_c = get_random_scalar();
    let blinding_d = get_random_scalar();
    let blinding_e = get_random_scalar();
    let c1_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c1_value), *c1_blinding],
        &[*value_basepoint, *blinding_basepoint],
    );
    let c2_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c2_value), *c2_blinding],
        &[*value_basepoint, *blinding_basepoint],
    );
    let c3_point = RistrettoPoint::multiscalar_mul(
        &[
            Scalar::from(c1_value) + Scalar::from(c2_value),
            *c3_blinding,
        ],
        &[*value_basepoint, *blinding_basepoint],
    );
    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t2_p = RistrettoPoint::multiscalar_mul(&[blinding_c, blinding_d], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t3_p = RistrettoPoint::multiscalar_mul(
        &[(blinding_a + blinding_c), blinding_e],
        &[*value_basepoint, *blinding_basepoint],
    );
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&t3_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));

    let check = hash_to_scalar(&hash_vec);
    let m1 = blinding_a - (check * (Scalar::from(c1_value)));
    let m2 = blinding_b - (check * c1_blinding);
    let m3 = blinding_c - (check * (Scalar::from(c2_value)));
    let m4 = blinding_d - (check * (c2_blinding));
    let m5 = blinding_e - (check * (c3_blinding));

    let mut proof = BalanceProof::new();
    proof.set_c(scalar_to_bytes(&check));
    proof.set_m1(scalar_to_bytes(&m1));
    proof.set_m2(scalar_to_bytes(&m2));
    proof.set_m3(scalar_to_bytes(&m3));
    proof.set_m4(scalar_to_bytes(&m4));
    proof.set_m5(scalar_to_bytes(&m5));
    proof
}

/// Verifies three commitments satisfying a sum relationship, i.e.
/// the values embedded in c1_point, c2_point, c3_point satisfying
/// c1_value + c2_value = c3_value.
pub fn verify_sum_relationship(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &BalanceProof,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let check = bytes_to_scalar(proof.get_c())?;
    let m1 = bytes_to_scalar(proof.get_m1())?;
    let m2 = bytes_to_scalar(proof.get_m2())?;
    let m3 = bytes_to_scalar(proof.get_m3())?;
    let m4 = bytes_to_scalar(proof.get_m4())?;
    let m5 = bytes_to_scalar(proof.get_m5())?;
    let t1_v = RistrettoPoint::multiscalar_mul(&[m1, m2, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c1_point,
    ]);
    let t2_v = RistrettoPoint::multiscalar_mul(&[m3, m4, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c2_point,
    ]);
    let t3_v = RistrettoPoint::multiscalar_mul(&[m1 + (m3), m5, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c3_point,
    ]);
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_v));
    hash_vec.append(&mut point_to_bytes(&t2_v));
    hash_vec.append(&mut point_to_bytes(&t3_v));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));

    let computed = hash_to_scalar(&hash_vec);
    Ok(computed.eq(&check))
}

/// Proves three commitments satisfying a product relationship, i.e.
/// the values embedded in them satisfying c1_value * c2_value = c3_value.
/// c3_value is not in the argument list, and will be directly computed from
/// c1_value * c2_value.
/// c?_blinding are random blinding values used in the commitments.
/// The commitments (c?_value*value_basepoint+c?_blinding*blinding_basepoint)
/// are not in the argument list, as they are not directly used by the proof
/// generation.
/// It returns a proof for the above product relationship.
pub fn prove_product_relationship(
    c1_value: u64,
    c2_value: u64,
    c1_blinding: &Scalar,
    c2_blinding: &Scalar,
    c3_blinding: &Scalar,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> BalanceProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let blinding_c = get_random_scalar();
    let blinding_d = get_random_scalar();
    let blinding_e = get_random_scalar();
    let c1_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c1_value), *c1_blinding],
        &[*value_basepoint, *blinding_basepoint],
    );
    let c2_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c2_value), *c2_blinding],
        &[*value_basepoint, *blinding_basepoint],
    );
    let c3_point = RistrettoPoint::multiscalar_mul(
        &[
            Scalar::from(c1_value) * Scalar::from(c2_value),
            *c3_blinding,
        ],
        &[*value_basepoint, *blinding_basepoint],
    );

    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t2_p = RistrettoPoint::multiscalar_mul(&[blinding_c, blinding_d], &[
        *value_basepoint,
        *blinding_basepoint,
    ]);
    let t3_p = RistrettoPoint::multiscalar_mul(
        &[blinding_a * (blinding_c), blinding_e],
        &[*value_basepoint, *blinding_basepoint],
    );
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&t3_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));

    let check = hash_to_scalar(&hash_vec);
    let value1 = Scalar::from(c1_value);
    let value2 = Scalar::from(c2_value);
    let m1 = blinding_a - (check * (value1));
    let m2 = blinding_b - (check * c1_blinding);
    let m3 = blinding_c - (check * (value2));
    let m4 = blinding_d - (check * c2_blinding);
    let c_index2 = check * check;
    let m5 = blinding_e
        + c_index2
            * ((value1 * c2_blinding) - c3_blinding + (value2 * c1_blinding))
        - check * ((blinding_a * c2_blinding) + (blinding_c * c1_blinding));

    let mut proof = BalanceProof::new();
    proof.set_c(scalar_to_bytes(&check));
    proof.set_m1(scalar_to_bytes(&m1));
    proof.set_m2(scalar_to_bytes(&m2));
    proof.set_m3(scalar_to_bytes(&m3));
    proof.set_m4(scalar_to_bytes(&m4));
    proof.set_m5(scalar_to_bytes(&m5));
    proof
}

/// Verifies three commitments satisfying a product relationship, i.e.
/// the values embedded in c1_point, c2_point, c3_point satisfying
/// c1_value * c2_value = c3_value.
pub fn verify_product_relationship(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &BalanceProof,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let check = bytes_to_scalar(proof.get_c())?;
    let m1 = bytes_to_scalar(proof.get_m1())?;
    let m2 = bytes_to_scalar(proof.get_m2())?;
    let m3 = bytes_to_scalar(proof.get_m3())?;
    let m4 = bytes_to_scalar(proof.get_m4())?;
    let m5 = bytes_to_scalar(proof.get_m5())?;

    let t1_v = RistrettoPoint::multiscalar_mul(&[m1, m2, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c1_point,
    ]);
    let t2_v = RistrettoPoint::multiscalar_mul(&[m3, m4, check], &[
        *value_basepoint,
        *blinding_basepoint,
        *c2_point,
    ]);
    let t3_v = RistrettoPoint::multiscalar_mul(
        &[m1 * m3, m5, check * check, check * m3, check * m1],
        &[
            *value_basepoint,
            *blinding_basepoint,
            *c3_point,
            *c1_point,
            *c2_point,
        ],
    );
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_v));
    hash_vec.append(&mut point_to_bytes(&t2_v));
    hash_vec.append(&mut point_to_bytes(&t3_v));
    hash_vec.append(&mut point_to_bytes(c1_point));
    hash_vec.append(&mut point_to_bytes(c2_point));
    hash_vec.append(&mut point_to_bytes(c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));

    let computed = hash_to_scalar(&hash_vec);
    Ok(computed.eq(&check))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_crypto_zkp_utils::{BASEPOINT_G1, BASEPOINT_G2};

    #[test]
    fn test_sum_relationship_proof() {
        let c1_value = 30u64;
        let c2_value = 10u64;
        let c1_blinding = get_random_scalar();
        let c2_blinding = get_random_scalar();
        let c3_blinding = get_random_scalar();
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;

        let proof = prove_sum_relationship(
            c1_value,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        let c1_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value), c1_blinding],
            &[value_basepoint, blinding_basepoint],
        );
        let c2_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c2_value), c2_blinding],
            &[value_basepoint, blinding_basepoint],
        );
        // c3 = c1 + c2
        let c3_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value + c2_value), c3_blinding],
            &[value_basepoint, blinding_basepoint],
        );

        assert_eq!(
            true,
            verify_sum_relationship(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_product_relationship_proof() {
        let c1_value = 30u64;
        let c2_value = 10u64;
        let c1_blinding = get_random_scalar();
        let c2_blinding = get_random_scalar();
        let c3_blinding = get_random_scalar();
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;

        let proof = prove_product_relationship(
            c1_value,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &value_basepoint,
            &blinding_basepoint,
        );
        let c1_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value), c1_blinding],
            &[value_basepoint, blinding_basepoint],
        );
        let c2_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c2_value), c2_blinding],
            &[value_basepoint, blinding_basepoint],
        );
        // c3 = c1 * c2
        let c3_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value * c2_value), c3_blinding],
            &[value_basepoint, blinding_basepoint],
        );

        assert_eq!(
            true,
            verify_product_relationship(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }
}
