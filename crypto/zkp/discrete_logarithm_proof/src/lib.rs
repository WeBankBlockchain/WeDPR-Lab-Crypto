// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Zero-knowledge proof (ZKP) functions based on DLP construction.

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, get_random_scalar, get_random_u32,
    hash_to_scalar, point_to_bytes, scalar_to_bytes,
};
use wedpr_l_protos::generated::zkp::{BalanceProof, EqualityProof};
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
    proof.set_t1(point_to_bytes(&t1_p));
    proof.set_t2(point_to_bytes(&t2_p));
    proof.set_t3(point_to_bytes(&t3_p));
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
    let m1 = bytes_to_scalar(proof.get_m1())?;
    let m2 = bytes_to_scalar(proof.get_m2())?;
    let m3 = bytes_to_scalar(proof.get_m3())?;
    let m4 = bytes_to_scalar(proof.get_m4())?;
    let m5 = bytes_to_scalar(proof.get_m5())?;
    let t1_p = bytes_to_point(proof.get_t1())?;
    let t2_p = bytes_to_point(proof.get_t2())?;
    let t3_p = bytes_to_point(proof.get_t3())?;
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&t3_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));
    let check = hash_to_scalar(&hash_vec);

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
    if t1_v == t1_p && t2_v == t2_p && t3_v == t3_p {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment tuples satisfying sum relationships,
/// where each commitment tuple contains three commitment points,
/// c1_point = c1_point_list[i], c2_point = c2_point_list[i], c3_point =
/// c3_point_list[i], and the values embedded in c1_point, c2_point, c3_point
/// satisfying c1_value + c2_value = c3_value.
pub fn verify_sum_relationship_in_batch(
    c1_point_list: &Vec<RistrettoPoint>,
    c2_point_list: &Vec<RistrettoPoint>,
    c3_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<BalanceProof>,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c1_point_list.len() != c2_point_list.len()
        && c1_point_list.len() != c3_point_list.len()
        && c1_point_list.len() != proof_list.len()
    {
        return Ok(false);
    };
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut t2_sum_expected: RistrettoPoint = Default::default();
    let mut t3_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut c2_c_expected: RistrettoPoint = Default::default();
    let mut c3_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::zero();
    let mut m2_expected: Scalar = Scalar::zero();
    let mut m3_expected: Scalar = Scalar::zero();
    let mut m4_expected: Scalar = Scalar::zero();
    let mut m5_expected: Scalar = Scalar::zero();
    for i in 0..c1_point_list.len() {
        // 32 bit random scalar
        // let blinding_factor = Scalar::from(get_random_u32());
        // let blinding_factor = Scalar::one();
        let m1 = bytes_to_scalar(proof_list[i].get_m1())?;
        let m2 = bytes_to_scalar(proof_list[i].get_m2())?;
        let m3 = bytes_to_scalar(proof_list[i].get_m3())?;
        let m4 = bytes_to_scalar(proof_list[i].get_m4())?;
        let m5 = bytes_to_scalar(proof_list[i].get_m5())?;
        let t1_p = bytes_to_point(proof_list[i].get_t1())?;
        let t2_p = bytes_to_point(proof_list[i].get_t2())?;
        let t3_p = bytes_to_point(proof_list[i].get_t3())?;
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];
        let c3_point = c3_point_list[i];
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&t1_p));
        hash_vec.append(&mut point_to_bytes(&t2_p));
        hash_vec.append(&mut point_to_bytes(&t3_p));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(value_basepoint));
        let check = hash_to_scalar(&hash_vec);
        // let c_factor = blinding_factor * check;
        // m1_expected += blinding_factor * m1;
        // m2_expected += blinding_factor * m2;
        // m3_expected += blinding_factor * m3;
        // m4_expected += blinding_factor * m4;
        // m5_expected += blinding_factor * m5;
        // t1_sum_expected += blinding_factor * t1_p;
        // t2_sum_expected += blinding_factor * t2_p;
        // t3_sum_expected += blinding_factor * t3_p;
        // c1_c_expected += c_factor * c1_point;
        // c2_c_expected += c_factor * c2_point;
        // c3_c_expected += c_factor * c3_point;

        let c_factor = check;
        m1_expected += m1;
        m2_expected += m2;
        m3_expected += m3;
        m4_expected += m4;
        m5_expected += m5;
        t1_sum_expected += t1_p;
        t2_sum_expected += t2_p;
        t3_sum_expected += t3_p;
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
        c3_c_expected += c_factor * c3_point;
    }

    // let t1_compute_sum_final = m1_expected * value_basepoint
    //     + m2_expected * blinding_basepoint
    //     + c1_c_expected;
    // let t2_compute_sum_final = m3_expected * value_basepoint
    //     + m4_expected * blinding_basepoint
    //     + c2_c_expected;
    // let t3_compute_sum_final = (m1_expected + m3_expected) * value_basepoint
    //     + m5_expected * blinding_basepoint
    //     + c3_c_expected;

    let t1_compute_sum_final = m1_expected * value_basepoint
        + m2_expected * blinding_basepoint
        + c1_c_expected;
    let t2_compute_sum_final = m3_expected * value_basepoint
        + m4_expected * blinding_basepoint
        + c2_c_expected;
    let t3_compute_sum_final = (m1_expected + m3_expected) * value_basepoint
        + m5_expected * blinding_basepoint
        + c3_c_expected;

    if t1_compute_sum_final == t1_sum_expected
        && t2_compute_sum_final == t2_sum_expected
        && t3_compute_sum_final == t3_sum_expected
    {
        return Ok(true);
    }
    Ok(false)
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
    proof.set_t1(point_to_bytes(&t1_p));
    proof.set_t2(point_to_bytes(&t2_p));
    proof.set_t3(point_to_bytes(&t3_p));
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
    let t1_p = bytes_to_point(proof.get_t1())?;
    let t2_p = bytes_to_point(proof.get_t2())?;
    let t3_p = bytes_to_point(proof.get_t3())?;
    let m1 = bytes_to_scalar(proof.get_m1())?;
    let m2 = bytes_to_scalar(proof.get_m2())?;
    let m3 = bytes_to_scalar(proof.get_m3())?;
    let m4 = bytes_to_scalar(proof.get_m4())?;
    let m5 = bytes_to_scalar(proof.get_m5())?;

    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&t3_p));
    hash_vec.append(&mut point_to_bytes(c1_point));
    hash_vec.append(&mut point_to_bytes(c2_point));
    hash_vec.append(&mut point_to_bytes(c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));
    let check = hash_to_scalar(&hash_vec);

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

    if t1_v == t1_p && t2_v == t2_p && t3_v == t3_p {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment tuples satisfying product relationships,
/// where each commitment tuple contains three commitment points,
/// c1_point = c1_point_list[i], c2_point = c2_point_list[i], c3_point =
/// c3_point_list[i], and the values embedded in c1_point, c2_point, c3_point
/// satisfying c1_value * c2_value = c3_value.
pub fn verify_product_relationship_in_batch(
    c1_point_list: &Vec<RistrettoPoint>,
    c2_point_list: &Vec<RistrettoPoint>,
    c3_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<BalanceProof>,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c1_point_list.len() != c2_point_list.len()
        && c1_point_list.len() != c3_point_list.len()
        && c1_point_list.len() != proof_list.len()
    {
        return Ok(false);
    };
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut t2_sum_expected: RistrettoPoint = Default::default();
    let mut t3_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut c2_c_expected: RistrettoPoint = Default::default();
    let mut c3_c_expected: RistrettoPoint = Default::default();
    let mut t3_c1_c_expected: RistrettoPoint = Default::default();
    let mut t3_c2_c_expected: RistrettoPoint = Default::default();
    let mut t3_c3_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::zero();
    let mut m1_m3_expected: Scalar = Scalar::zero();
    let mut m2_expected: Scalar = Scalar::zero();
    let mut m3_expected: Scalar = Scalar::zero();
    let mut m4_expected: Scalar = Scalar::zero();
    let mut m5_expected: Scalar = Scalar::zero();
    for i in 0..c1_point_list.len() {
        // 32 bit random scalar
        let blinding_factor = Scalar::from(get_random_u32());
        let m1 = bytes_to_scalar(proof_list[i].get_m1())?;
        let m2 = bytes_to_scalar(proof_list[i].get_m2())?;
        let m3 = bytes_to_scalar(proof_list[i].get_m3())?;
        let m4 = bytes_to_scalar(proof_list[i].get_m4())?;
        let m5 = bytes_to_scalar(proof_list[i].get_m5())?;
        let t1_p = bytes_to_point(proof_list[i].get_t1())?;
        let t2_p = bytes_to_point(proof_list[i].get_t2())?;
        let t3_p = bytes_to_point(proof_list[i].get_t3())?;
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];
        let c3_point = c3_point_list[i];
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&t1_p));
        hash_vec.append(&mut point_to_bytes(&t2_p));
        hash_vec.append(&mut point_to_bytes(&t3_p));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(value_basepoint));
        let check = hash_to_scalar(&hash_vec);
        m1_expected += blinding_factor * m1;
        let c_factor = blinding_factor * check;
        m1_m3_expected += blinding_factor * m1 * m3;
        m2_expected += blinding_factor * m2;
        m3_expected += blinding_factor * m3;
        m4_expected += blinding_factor * m4;
        m5_expected += blinding_factor * m5;
        t1_sum_expected += blinding_factor * t1_p;
        t2_sum_expected += blinding_factor * t2_p;
        t3_sum_expected += blinding_factor * t3_p;
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
        c3_c_expected += c_factor * c3_point;
        t3_c1_c_expected += blinding_factor * check * m3 * c1_point;
        t3_c2_c_expected += blinding_factor * check * m1 * c2_point;
        t3_c3_c_expected += blinding_factor * check * check * c3_point;
    }

    let t1_compute_sum_final = m1_expected * value_basepoint
        + m2_expected * blinding_basepoint
        + c1_c_expected;
    let t2_compute_sum_final = m3_expected * value_basepoint
        + m4_expected * blinding_basepoint
        + c2_c_expected;
    let t3_compute_sum_final = m1_m3_expected * value_basepoint
        + m5_expected * blinding_basepoint
        + t3_c3_c_expected
        + t3_c1_c_expected
        + t3_c2_c_expected;

    if t1_compute_sum_final == t1_sum_expected
        && t2_compute_sum_final == t2_sum_expected
        && t3_compute_sum_final == t3_sum_expected
    {
        return Ok(true);
    }
    Ok(false)
}

/// Proves two commitments satisfying an equality relationship, i.e.
/// the values embedded in c1_point and c2_point satisfying c1_value = c2_value,
/// where c1_point = c1_value * basepoint1, c2_point = c2_value * basepoint2.
/// It returns a proof for the above equality relationship.
pub fn prove_equality_relationship_proof(
    c1_value: &Scalar,
    basepoint1: &RistrettoPoint,
    basepoint2: &RistrettoPoint,
) -> EqualityProof {
    let blinding_a = get_random_scalar();
    let c1_point =
        RistrettoPoint::multiscalar_mul(&[*c1_value], &[*basepoint1]);
    let c2_point =
        RistrettoPoint::multiscalar_mul(&[*c1_value], &[*basepoint2]);

    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a], &[*basepoint1]);
    let t2_p = RistrettoPoint::multiscalar_mul(&[blinding_a], &[*basepoint2]);
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(basepoint1));
    hash_vec.append(&mut point_to_bytes(basepoint2));

    let check = hash_to_scalar(&hash_vec);
    let m1 = blinding_a - (check * (c1_value));

    let mut proof = EqualityProof::new();
    proof.set_m1(scalar_to_bytes(&m1));
    proof.set_t1(point_to_bytes(&t1_p));
    proof.set_t2(point_to_bytes(&t2_p));
    proof
}

/// Verifies two commitments satisfying an equality relationship, i.e.
/// the values embedded in c1_point, c2_point satisfying
/// c1_value = c2_value,
/// where c1_point = c1_value * basepoint1, c2_point = c2_value * basepoint2.
pub fn verify_equality_relationship_proof(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    proof: &EqualityProof,
    basepoint1: &RistrettoPoint,
    basepoint2: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let m1 = bytes_to_scalar(proof.get_m1())?;
    let t1_p = bytes_to_point(proof.get_t1())?;
    let t2_p = bytes_to_point(proof.get_t2())?;
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(basepoint1));
    hash_vec.append(&mut point_to_bytes(basepoint2));

    let check = hash_to_scalar(&hash_vec);
    let t1_v = RistrettoPoint::multiscalar_mul(&[m1, check], &[
        *basepoint1,
        *c1_point,
    ]);
    let t2_v = RistrettoPoint::multiscalar_mul(&[m1, check], &[
        *basepoint2,
        *c2_point,
    ]);
    if t1_v == t1_p && t2_v == t2_p {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment pairs satisfying equality relationships,
/// where each commitment pair contains two commitment points,
/// c1_point = c1_point_list[i], c2_point = c2_point_list[i],
/// and the values embedded in c1_point, c2_point satisfying
/// c1_value = c2_value.
pub fn verify_equality_relationship_proof_in_batch(
    c1_point_list: &Vec<RistrettoPoint>,
    c2_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<EqualityProof>,
    basepoint1: &RistrettoPoint,
    basepoint2: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c1_point_list.len() != c2_point_list.len()
        && c1_point_list.len() != proof_list.len()
    {
        return Ok(false);
    };
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut t2_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut c2_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::zero();
    for i in 0..c1_point_list.len() {
        // 32 bit random scalar
        let blinding_factor = Scalar::from(get_random_u32());
        let m1 = bytes_to_scalar(proof_list[i].get_m1())?;
        let t1_p = bytes_to_point(proof_list[i].get_t1())?;
        let t2_p = bytes_to_point(proof_list[i].get_t2())?;
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&t1_p));
        hash_vec.append(&mut point_to_bytes(&t2_p));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(basepoint1));
        hash_vec.append(&mut point_to_bytes(basepoint2));
        let check = hash_to_scalar(&hash_vec);
        let c_factor = blinding_factor * check;
        m1_expected += blinding_factor * m1;
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
        t1_sum_expected += blinding_factor * t1_p;
        t2_sum_expected += blinding_factor * t2_p;
    }
    let t1_compute_sum_final = m1_expected * basepoint1 + c1_c_expected;
    let t2_compute_sum_final = m1_expected * basepoint2 + c2_c_expected;
    if t1_sum_expected == t1_compute_sum_final
        && t2_sum_expected == t2_compute_sum_final
    {
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_crypto_zkp_utils::{BASEPOINT_G1, BASEPOINT_G2};

    const BATCH_SIZE: usize = 10;

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
    fn test_sum_relationship_proof_in_batch() {
        let mut proofs: Vec<BalanceProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let mut c2_points: Vec<RistrettoPoint> = vec![];
        let mut c3_points: Vec<RistrettoPoint> = vec![];
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;
        for _ in 0..BATCH_SIZE {
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
            proofs.push(proof);
            c1_points.push(c1_point);
            c2_points.push(c2_point);
            c3_points.push(c3_point);
        }
        assert_eq!(
            true,
            verify_sum_relationship_in_batch(
                &c1_points,
                &c2_points,
                &c3_points,
                &proofs,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c2_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_sum_relationship_in_batch(
                &c1_points,
                &c2_points,
                &c3_points,
                &proofs,
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

    #[test]
    fn test_product_relationship_proof_in_batch() {
        let mut proofs: Vec<BalanceProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let mut c2_points: Vec<RistrettoPoint> = vec![];
        let mut c3_points: Vec<RistrettoPoint> = vec![];
        let value_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;
        for _ in 0..BATCH_SIZE {
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
            proofs.push(proof);
            c1_points.push(c1_point);
            c2_points.push(c2_point);
            c3_points.push(c3_point);
        }
        assert_eq!(
            true,
            verify_product_relationship_in_batch(
                &c1_points,
                &c2_points,
                &c3_points,
                &proofs,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c2_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_sum_relationship_in_batch(
                &c1_points,
                &c2_points,
                &c3_points,
                &proofs,
                &value_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_equality_relationship_proof() {
        let c_value = get_random_scalar();
        let c_wrong_value = get_random_scalar();
        let basepoint1 = *BASEPOINT_G1;
        let basepoint2 = *BASEPOINT_G2;
        let c1_point = basepoint1 * &c_value;
        let c2_point = basepoint2 * &c_value;
        let proof = prove_equality_relationship_proof(
            &c_value,
            &basepoint1,
            &basepoint2,
        );
        assert_eq!(
            true,
            verify_equality_relationship_proof(
                &c1_point,
                &c2_point,
                &proof,
                &basepoint1,
                &basepoint2
            )
            .unwrap()
        );
        let c2_wrong_point = basepoint2 * &c_wrong_value;
        assert_eq!(
            false,
            verify_equality_relationship_proof(
                &c1_point,
                &c2_wrong_point,
                &proof,
                &basepoint1,
                &basepoint2
            )
            .unwrap()
        );
    }

    #[test]
    fn test_equality_relationship_proof_in_batch() {
        let mut proofs: Vec<EqualityProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let mut c2_points: Vec<RistrettoPoint> = vec![];
        let basepoint1 = *BASEPOINT_G1;
        let basepoint2 = *BASEPOINT_G2;
        for _ in 0..BATCH_SIZE {
            let c_value = get_random_scalar();
            let c1_point = basepoint1 * &c_value;
            let c2_point = basepoint2 * &c_value;
            let proof = prove_equality_relationship_proof(
                &c_value,
                &basepoint1,
                &basepoint2,
            );
            assert_eq!(
                true,
                verify_equality_relationship_proof(
                    &c1_point,
                    &c2_point,
                    &proof,
                    &basepoint1,
                    &basepoint2
                )
                .unwrap()
            );
            proofs.push(proof);
            c1_points.push(c1_point);
            c2_points.push(c2_point);
        }
        assert_eq!(
            true,
            verify_equality_relationship_proof_in_batch(
                &c1_points,
                &c2_points,
                &proofs,
                &basepoint1,
                &basepoint2
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c2_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_equality_relationship_proof_in_batch(
                &c1_points,
                &c2_points,
                &proofs,
                &basepoint1,
                &basepoint2
            )
            .unwrap()
        );
    }
}
