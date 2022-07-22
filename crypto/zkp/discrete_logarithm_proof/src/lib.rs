// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Zero-knowledge proof (ZKP) functions based on DLP construction.

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use rand::Rng;
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, hash_to_scalar, point_to_bytes, ArithmeticProof,
    BalanceProof, EqualityProof, FormatProof, KnowledgeProof,
};

use wedpr_l_utils::error::WedprError;

pub fn aggregate_ristretto_point(
    point_sum: &RistrettoPoint,
    point_share: &RistrettoPoint,
) -> Result<RistrettoPoint, WedprError> {
    Ok(point_sum + point_share)
}

/// Proves three commitments satisfying either or equality relationships, i.e.
/// the values embedded in c1_point = c1_value * c_basepoint + c1_blinding *
/// blinding_basepoint c2_point = c2_value * c_basepoint + c2_blinding *
/// blinding_basepoint c3_point = c3_blinding * blinding_basepoint
/// where c1_value = c2_value or 0,
/// It returns a proof for the above equality relationship.
pub fn prove_either_equality_relationship_proof(
    c1_value: u64,
    c2_value: u64,
    c1_blinding: &Scalar,
    c2_blinding: &Scalar,
    c3_blinding: &Scalar,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> BalanceProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let blinding_c = get_random_scalar();
    let blinding_d = get_random_scalar();
    let blinding_e = get_random_scalar();
    let blinding_f = get_random_scalar();
    let blinding_w = get_random_scalar();
    let c1_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c1_value), *c1_blinding],
        &[*c_basepoint, *blinding_basepoint],
    );
    let c2_point = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(c2_value), *c2_blinding],
        &[*c_basepoint, *blinding_basepoint],
    );
    let c3_point = c3_blinding * blinding_basepoint;

    let (check1, check2, m1, m2, m3, m4, m5, m6) = if c1_value == c2_value {
        let t1_p =
            RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
                *c_basepoint,
                *blinding_basepoint,
            ]);
        let t2_p =
            RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_c], &[
                *c_basepoint,
                *blinding_basepoint,
            ]);
        let t3_p = RistrettoPoint::multiscalar_mul(
            &[blinding_w, blinding_d, blinding_e],
            &[c3_point, *c_basepoint, *blinding_basepoint],
        );
        let t4_p = RistrettoPoint::multiscalar_mul(
            &[blinding_w, blinding_d, blinding_f],
            &[c1_point, *c_basepoint, *blinding_basepoint],
        );

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&t1_p));
        hash_vec.append(&mut point_to_bytes(&t2_p));
        hash_vec.append(&mut point_to_bytes(&t3_p));
        hash_vec.append(&mut point_to_bytes(&t4_p));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(c_basepoint));
        hash_vec.append(&mut point_to_bytes(blinding_basepoint));

        let check = hash_to_scalar(&hash_vec) - blinding_w;
        (
            check,
            blinding_w,
            blinding_a - (check * Scalar::from(c2_value)),
            blinding_b - (check * c2_blinding),
            blinding_c - (check * c1_blinding),
            blinding_d,
            blinding_e,
            blinding_f,
        )
    } else if c1_value == 0 {
        let t1_p = RistrettoPoint::multiscalar_mul(
            &[blinding_w, blinding_a, blinding_b],
            &[c2_point, *c_basepoint, *blinding_basepoint],
        );
        let t2_p = RistrettoPoint::multiscalar_mul(
            &[blinding_w, blinding_a, blinding_c],
            &[c1_point, *c_basepoint, *blinding_basepoint],
        );
        let t3_p =
            RistrettoPoint::multiscalar_mul(&[blinding_d, blinding_e], &[
                *c_basepoint,
                *blinding_basepoint,
            ]);
        let t4_p =
            RistrettoPoint::multiscalar_mul(&[blinding_d, blinding_f], &[
                *c_basepoint,
                *blinding_basepoint,
            ]);

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&t1_p));
        hash_vec.append(&mut point_to_bytes(&t2_p));
        hash_vec.append(&mut point_to_bytes(&t3_p));
        hash_vec.append(&mut point_to_bytes(&t4_p));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(c_basepoint));
        hash_vec.append(&mut point_to_bytes(blinding_basepoint));

        let check = hash_to_scalar(&hash_vec) - blinding_w;
        (
            blinding_w,
            check,
            blinding_a,
            blinding_b,
            blinding_c,
            blinding_d,
            blinding_e - (check * c3_blinding),
            blinding_f - (check * c1_blinding),
        )
    } else {
        return BalanceProof::default();
    };
    return BalanceProof {
        check1: check1,
        check2: check2,
        m1: m1,
        m2: m2,
        m3: m3,
        m4: m4,
        m5: m5,
        m6: m6,
    };
}

/// Verifies owner know a commitment's secret value c_value and c_blinding, i.e.
/// the values embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint
pub fn verify_either_equality_relationship_proof(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &BalanceProof,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let t1_v = RistrettoPoint::multiscalar_mul(
        &[proof.check1, proof.m1, proof.m2],
        &[*c2_point, *c_basepoint, *blinding_basepoint],
    );
    let t2_v = RistrettoPoint::multiscalar_mul(
        &[proof.check1, proof.m1, proof.m3],
        &[*c1_point, *c_basepoint, *blinding_basepoint],
    );
    let t3_v = RistrettoPoint::multiscalar_mul(
        &[proof.check2, proof.m4, proof.m5],
        &[*c3_point, *c_basepoint, *blinding_basepoint],
    );
    let t4_v = RistrettoPoint::multiscalar_mul(
        &[proof.check2, proof.m4, proof.m6],
        &[*c1_point, *c_basepoint, *blinding_basepoint],
    );

    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_v));
    hash_vec.append(&mut point_to_bytes(&t2_v));
    hash_vec.append(&mut point_to_bytes(&t3_v));
    hash_vec.append(&mut point_to_bytes(&t4_v));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(c_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));
    let check = hash_to_scalar(&hash_vec);

    if check == (proof.check1 + proof.check2) {
        return Ok(true);
    }
    Ok(false)
}

/// Proves owner know a commitment's secret value c_value and c_blinding, i.e.
/// the values embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint It returns a proof for the above balance relationship.
pub fn prove_knowledge_proof(
    c_value: u64,
    c_blinding: &Scalar,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> KnowledgeProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *c_basepoint,
        *blinding_basepoint,
    ]);
    let c_scalar_value = Scalar::from(c_value);
    let c_point =
        RistrettoPoint::multiscalar_mul(&[c_scalar_value, *c_blinding], &[
            *c_basepoint,
            *blinding_basepoint,
        ]);
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&c_point));
    hash_vec.append(&mut point_to_bytes(c_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));

    let check = hash_to_scalar(&hash_vec);
    let m1 = blinding_a - (check * c_scalar_value);
    let m2 = blinding_b - (check * c_blinding);
    return KnowledgeProof {
        t1: t1_p,
        m1: m1,
        m2: m2,
    };
}

/// Verifies owner know a commitment's secret value c_value and c_blinding, i.e.
/// the values embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint
pub fn verify_knowledge_proof(
    c_point: &RistrettoPoint,
    proof: &KnowledgeProof,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&c_point));
    hash_vec.append(&mut point_to_bytes(c_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));
    let check = hash_to_scalar(&hash_vec);
    let t1_v =
        RistrettoPoint::multiscalar_mul(&[check, proof.m1, proof.m2], &[
            *c_point,
            *c_basepoint,
            *blinding_basepoint,
        ]);

    if t1_v == proof.t1 {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment pairs satisfying knowledge relationships,
/// where each commitment pair contains one commitment points,
/// c_point = c_point_list[i],
/// the values embedded in c_point = c_value * c_basepoint + c_blinding *
/// blinding_basepoint
pub fn verify_knowledge_proof_in_batch(
    c_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<KnowledgeProof>,
    c_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c_point_list.len() != proof_list.len() {
        return Err(WedprError::FormatError);
    }
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::zero();
    let mut m2_expected: Scalar = Scalar::zero();

    for i in 0..c_point_list.len() {
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c_point = c_point_list[i];

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&c_point));
        hash_vec.append(&mut point_to_bytes(c_basepoint));
        hash_vec.append(&mut point_to_bytes(blinding_basepoint));
        let check = hash_to_scalar(&hash_vec);

        let c_factor = blinding_factor * check;
        m1_expected += blinding_factor * proof_list[i].m1;
        m2_expected += blinding_factor * proof_list[i].m2;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        c1_c_expected += c_factor * c_point;
    }
    let t1_compute_sum_final = m1_expected * c_basepoint
        + m2_expected * blinding_basepoint
        + c1_c_expected;

    if t1_compute_sum_final == t1_sum_expected {
        return Ok(true);
    }
    Ok(false)
}

/// Proves two commitments satisfying an equality relationship, i.e.
/// the values embedded in c1_point and c2_point satisfying c1_blinding =
/// c2_blinding, where c1_point = c1_value * c1_basepoint + c1_blinding *
/// blinding_basepoint, c2_point = c2_blinding * c2_basepoint. It returns a
/// proof for the above equality relationship.
pub fn prove_format_proof(
    c1_value: u64,
    c_blinding: &Scalar,
    c1_basepoint: &RistrettoPoint,
    c2_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> FormatProof {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let t1_p = RistrettoPoint::multiscalar_mul(&[blinding_a, blinding_b], &[
        *c1_basepoint,
        *blinding_basepoint,
    ]);
    let t2_p = c2_basepoint * blinding_b;
    let c1_scalar_value = Scalar::from(c1_value);
    let c1_point =
        RistrettoPoint::multiscalar_mul(&[c1_scalar_value, *c_blinding], &[
            *c1_basepoint,
            *blinding_basepoint,
        ]);
    let c2_point = c_blinding * c2_basepoint;
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&t1_p));
    hash_vec.append(&mut point_to_bytes(&t2_p));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(c1_basepoint));
    hash_vec.append(&mut point_to_bytes(c2_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));

    let check = hash_to_scalar(&hash_vec);
    let m1 = blinding_a - (check * c1_scalar_value);
    let m2 = blinding_b - (check * c_blinding);
    return FormatProof {
        t1: t1_p,
        t2: t2_p,
        m1: m1,
        m2: m2,
    };
}

/// Verifies two commitments satisfying an equality relationship, i.e.
/// the values embedded in c1_point and c2_point satisfying c1_blinding =
/// c2_blinding, where c1_point = c1_value * c1_basepoint + c1_blinding *
/// blinding_basepoint, c2_point = c2_blinding * c2_basepoint.
pub fn verify_format_proof(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    proof: &FormatProof,
    c1_basepoint: &RistrettoPoint,
    c2_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&proof.t2));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(c1_basepoint));
    hash_vec.append(&mut point_to_bytes(c2_basepoint));
    hash_vec.append(&mut point_to_bytes(blinding_basepoint));
    let check = hash_to_scalar(&hash_vec);
    let t1_v =
        RistrettoPoint::multiscalar_mul(&[check, proof.m1, proof.m2], &[
            *c1_point,
            *c1_basepoint,
            *blinding_basepoint,
        ]);
    let t2_v = RistrettoPoint::multiscalar_mul(&[check, proof.m2], &[
        *c2_point,
        *c2_basepoint,
    ]);

    if t1_v == proof.t1 && t2_v == proof.t2 {
        return Ok(true);
    }
    Ok(false)
}

/// Verifies all commitment pairs satisfying equality relationships,
/// where each commitment pair contains two commitment points,
/// c1_point = c1_point_list[i], c2_point = c2_point_list[i],
/// and the values embedded in c1_point, c2_point satisfying
/// c1_blinding = c2_blinding.
pub fn verify_format_proof_in_batch(
    c1_point_list: &Vec<RistrettoPoint>,
    c2_point_list: &Vec<RistrettoPoint>,
    proof_list: &Vec<FormatProof>,
    c1_basepoint: &RistrettoPoint,
    c2_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    if c1_point_list.len() != c1_point_list.len()
        || c1_point_list.len() != proof_list.len()
    {
        return Err(WedprError::FormatError);
    }
    let mut t1_sum_expected: RistrettoPoint = Default::default();
    let mut t2_sum_expected: RistrettoPoint = Default::default();
    let mut c1_c_expected: RistrettoPoint = Default::default();
    let mut c2_c_expected: RistrettoPoint = Default::default();
    let mut m1_expected: Scalar = Scalar::zero();
    let mut m2_expected: Scalar = Scalar::zero();

    for i in 0..c1_point_list.len() {
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];

        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t2));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(c1_basepoint));
        hash_vec.append(&mut point_to_bytes(c2_basepoint));
        hash_vec.append(&mut point_to_bytes(blinding_basepoint));
        let check = hash_to_scalar(&hash_vec);

        let c_factor = blinding_factor * check;
        m1_expected += blinding_factor * proof_list[i].m1;
        m2_expected += blinding_factor * proof_list[i].m2;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        t2_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t2);
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
    }
    let t1_compute_sum_final = m1_expected * c1_basepoint
        + m2_expected * blinding_basepoint
        + c1_c_expected;
    let t2_compute_sum_final = m2_expected * c2_basepoint + c2_c_expected;

    if t1_compute_sum_final == t1_sum_expected
        && t2_compute_sum_final == t2_sum_expected
    {
        return Ok(true);
    }
    Ok(false)
}

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
) -> ArithmeticProof {
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
    return ArithmeticProof {
        t1: t1_p,
        t2: t2_p,
        t3: t3_p,
        m1: m1,
        m2: m2,
        m3: m3,
        m4: m4,
        m5: m5,
    };
}

/// Verifies three commitments satisfying a sum relationship, i.e.
/// the values embedded in c1_point, c2_point, c3_point satisfying
/// c1_value + c2_value = c3_value.
pub fn verify_sum_relationship(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &ArithmeticProof,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&proof.t2));
    hash_vec.append(&mut point_to_bytes(&proof.t3));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(&c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));
    let check = hash_to_scalar(&hash_vec);

    let t1_v =
        RistrettoPoint::multiscalar_mul(&[proof.m1, proof.m2, check], &[
            *value_basepoint,
            *blinding_basepoint,
            *c1_point,
        ]);
    let t2_v =
        RistrettoPoint::multiscalar_mul(&[proof.m3, proof.m4, check], &[
            *value_basepoint,
            *blinding_basepoint,
            *c2_point,
        ]);
    let t3_v = RistrettoPoint::multiscalar_mul(
        &[proof.m1 + (proof.m3), proof.m5, check],
        &[*value_basepoint, *blinding_basepoint, *c3_point],
    );
    if t1_v == proof.t1 && t2_v == proof.t2 && t3_v == proof.t3 {
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
    proof_list: &Vec<ArithmeticProof>,
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
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];
        let c3_point = c3_point_list[i];
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t2));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t3));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(value_basepoint));
        let check = hash_to_scalar(&hash_vec);
        let c_factor = blinding_factor * check;
        m1_expected += blinding_factor * proof_list[i].m1;
        m2_expected += blinding_factor * proof_list[i].m2;
        m3_expected += blinding_factor * proof_list[i].m3;
        m4_expected += blinding_factor * proof_list[i].m4;
        m5_expected += blinding_factor * proof_list[i].m5;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        t2_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t2);
        t3_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t3);
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
        c3_c_expected += c_factor * c3_point;
    }

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
) -> ArithmeticProof {
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

    return ArithmeticProof {
        t1: t1_p,
        t2: t2_p,
        t3: t3_p,
        m1: m1,
        m2: m2,
        m3: m3,
        m4: m4,
        m5: m5,
    };
}

/// Verifies three commitments satisfying a product relationship, i.e.
/// the values embedded in c1_point, c2_point, c3_point satisfying
/// c1_value * c2_value = c3_value.
pub fn verify_product_relationship(
    c1_point: &RistrettoPoint,
    c2_point: &RistrettoPoint,
    c3_point: &RistrettoPoint,
    proof: &ArithmeticProof,
    value_basepoint: &RistrettoPoint,
    blinding_basepoint: &RistrettoPoint,
) -> Result<bool, WedprError> {
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&proof.t2));
    hash_vec.append(&mut point_to_bytes(&proof.t3));
    hash_vec.append(&mut point_to_bytes(c1_point));
    hash_vec.append(&mut point_to_bytes(c2_point));
    hash_vec.append(&mut point_to_bytes(c3_point));
    hash_vec.append(&mut point_to_bytes(value_basepoint));
    let check = hash_to_scalar(&hash_vec);

    let t1_v =
        RistrettoPoint::multiscalar_mul(&[proof.m1, proof.m2, check], &[
            *value_basepoint,
            *blinding_basepoint,
            *c1_point,
        ]);
    let t2_v =
        RistrettoPoint::multiscalar_mul(&[proof.m3, proof.m4, check], &[
            *value_basepoint,
            *blinding_basepoint,
            *c2_point,
        ]);
    let t3_v = RistrettoPoint::multiscalar_mul(
        &[
            proof.m1 * proof.m3,
            proof.m5,
            check * check,
            check * proof.m3,
            check * proof.m1,
        ],
        &[
            *value_basepoint,
            *blinding_basepoint,
            *c3_point,
            *c1_point,
            *c2_point,
        ],
    );

    if t1_v == proof.t1 && t2_v == proof.t2 && t3_v == proof.t3 {
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
    proof_list: &Vec<ArithmeticProof>,
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
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];
        let c3_point = c3_point_list[i];
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t2));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t3));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(&c3_point));
        hash_vec.append(&mut point_to_bytes(value_basepoint));
        let check = hash_to_scalar(&hash_vec);
        m1_expected += blinding_factor * proof_list[i].m1;
        let c_factor = blinding_factor * check;
        m1_m3_expected += blinding_factor * proof_list[i].m1 * proof_list[i].m3;
        m2_expected += blinding_factor * proof_list[i].m2;
        m3_expected += blinding_factor * proof_list[i].m3;
        m4_expected += blinding_factor * proof_list[i].m4;
        m5_expected += blinding_factor * proof_list[i].m5;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        t2_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t2);
        t3_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t3);
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
        c3_c_expected += c_factor * c3_point;
        t3_c1_c_expected +=
            blinding_factor * check * proof_list[i].m3 * c1_point;
        t3_c2_c_expected +=
            blinding_factor * check * proof_list[i].m1 * c2_point;
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

    return EqualityProof {
        m1: m1,
        t1: t1_p,
        t2: t2_p,
    };
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
    let mut hash_vec = Vec::new();
    hash_vec.append(&mut point_to_bytes(&proof.t1));
    hash_vec.append(&mut point_to_bytes(&proof.t2));
    hash_vec.append(&mut point_to_bytes(&c1_point));
    hash_vec.append(&mut point_to_bytes(&c2_point));
    hash_vec.append(&mut point_to_bytes(basepoint1));
    hash_vec.append(&mut point_to_bytes(basepoint2));

    let check = hash_to_scalar(&hash_vec);
    let t1_v = RistrettoPoint::multiscalar_mul(&[proof.m1, check], &[
        *basepoint1,
        *c1_point,
    ]);
    let t2_v = RistrettoPoint::multiscalar_mul(&[proof.m1, check], &[
        *basepoint2,
        *c2_point,
    ]);
    if t1_v == proof.t1 && t2_v == proof.t2 {
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
        // 8 bit random scalar
        let random_scalar = get_random_u8();
        let blinding_factor = Scalar::from(random_scalar);
        let c1_point = c1_point_list[i];
        let c2_point = c2_point_list[i];
        let mut hash_vec = Vec::new();
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t1));
        hash_vec.append(&mut point_to_bytes(&proof_list[i].t2));
        hash_vec.append(&mut point_to_bytes(&c1_point));
        hash_vec.append(&mut point_to_bytes(&c2_point));
        hash_vec.append(&mut point_to_bytes(basepoint1));
        hash_vec.append(&mut point_to_bytes(basepoint2));
        let check = hash_to_scalar(&hash_vec);
        let c_factor = blinding_factor * check;
        m1_expected += blinding_factor * proof_list[i].m1;
        c1_c_expected += c_factor * c1_point;
        c2_c_expected += c_factor * c2_point;
        t1_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t1);
        t2_sum_expected +=
            small_scalar_point_mul(random_scalar, proof_list[i].t2);
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

fn small_scalar_point_mul(scalar: u8, point: RistrettoPoint) -> RistrettoPoint {
    let mut rbyte = scalar;
    let mut base_point = point;
    let mut result_point = RistrettoPoint::default();

    while rbyte != 0 {
        if rbyte & 1u8 == 1 {
            result_point = result_point + base_point;
        }
        base_point += base_point;
        rbyte >>= 1;
    }
    result_point
}

pub fn get_random_u8() -> u8 {
    let mut rng = rand::thread_rng();
    let blinding: u8 = rng.gen();
    blinding
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_crypto_zkp_utils::{
        get_random_u32, BASEPOINT_G1, BASEPOINT_G2,
    };

    const BATCH_SIZE: usize = 10;

    #[test]
    fn test_either_equality() {
        let c1_value = 100u64;
        let c1_blinding = get_random_scalar();
        let c2_blinding = get_random_scalar();
        let c3_blinding = get_random_scalar();
        let c2_value = c1_value;
        let c_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2;
        let c1_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c1_value), c1_blinding],
            &[c_basepoint, blinding_basepoint],
        );
        let c2_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(c2_value), c2_blinding],
            &[c_basepoint, blinding_basepoint],
        );
        let c3_point =
            RistrettoPoint::multiscalar_mul(&[Scalar::zero(), c3_blinding], &[
                c_basepoint,
                blinding_basepoint,
            ]);

        let proof = prove_either_equality_relationship_proof(
            c1_value,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &c_basepoint,
            &blinding_basepoint,
        );
        assert_eq!(
            true,
            verify_either_equality_relationship_proof(
                &c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &c_basepoint,
                &blinding_basepoint,
            )
            .unwrap()
        );

        let zero_c1_point = c1_blinding * blinding_basepoint;

        let proof_zero = prove_either_equality_relationship_proof(
            0,
            c2_value,
            &c1_blinding,
            &c2_blinding,
            &c3_blinding,
            &c_basepoint,
            &blinding_basepoint,
        );
        assert_eq!(
            true,
            verify_either_equality_relationship_proof(
                &zero_c1_point,
                &c2_point,
                &c3_point,
                &proof_zero,
                &c_basepoint,
                &blinding_basepoint,
            )
            .unwrap()
        );

        let invalid_c1_point = RistrettoPoint::multiscalar_mul(
            &[Scalar::from(101u64), c1_blinding],
            &[c_basepoint, blinding_basepoint],
        );

        assert_eq!(
            false,
            verify_either_equality_relationship_proof(
                &invalid_c1_point,
                &c2_point,
                &c3_point,
                &proof,
                &c_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_knowledge_proof_in_batch() {
        let mut proofs: Vec<KnowledgeProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let c1_basepoint = *BASEPOINT_G1;
        let blinding_basepoint = *BASEPOINT_G2 * get_random_scalar();
        for _ in 0..BATCH_SIZE {
            let c1_value = get_random_u32() as u64;
            let c1_blinding = get_random_scalar();

            let proof = prove_knowledge_proof(
                c1_value,
                &c1_blinding,
                &c1_basepoint,
                &blinding_basepoint,
            );
            let c1_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c1_value), c1_blinding],
                &[c1_basepoint, blinding_basepoint],
            );

            assert_eq!(
                true,
                verify_knowledge_proof(
                    &c1_point,
                    &proof,
                    &c1_basepoint,
                    &blinding_basepoint
                )
                .unwrap()
            );
            proofs.push(proof);
            c1_points.push(c1_point);
        }
        assert_eq!(
            true,
            verify_knowledge_proof_in_batch(
                &c1_points,
                &proofs,
                &c1_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c1_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_knowledge_proof_in_batch(
                &c1_points,
                &proofs,
                &c1_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

    #[test]
    fn test_format_proof_in_batch() {
        let mut proofs: Vec<FormatProof> = vec![];
        let mut c1_points: Vec<RistrettoPoint> = vec![];
        let mut c2_points: Vec<RistrettoPoint> = vec![];
        let c1_basepoint = *BASEPOINT_G1;
        let c2_basepoint = *BASEPOINT_G2;
        let blinding_basepoint = *BASEPOINT_G2 * get_random_scalar();
        for _ in 0..BATCH_SIZE {
            let c1_value = get_random_u32() as u64;
            let c1_blinding = get_random_scalar();

            let proof = prove_format_proof(
                c1_value,
                &c1_blinding,
                &c1_basepoint,
                &c2_basepoint,
                &blinding_basepoint,
            );
            let c1_point = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(c1_value), c1_blinding],
                &[c1_basepoint, blinding_basepoint],
            );
            let c2_point = c1_blinding * c2_basepoint;

            assert_eq!(
                true,
                verify_format_proof(
                    &c1_point,
                    &c2_point,
                    &proof,
                    &c1_basepoint,
                    &c2_basepoint,
                    &blinding_basepoint
                )
                .unwrap()
            );
            proofs.push(proof);
            c1_points.push(c1_point);
            c2_points.push(c2_point);
        }
        assert_eq!(
            true,
            verify_format_proof_in_batch(
                &c1_points,
                &c2_points,
                &proofs,
                &c1_basepoint,
                &c2_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
        // Setting the wrong point should cause proof verification failure.
        c1_points[BATCH_SIZE - 2] = c2_points[BATCH_SIZE - 1];
        assert_eq!(
            false,
            verify_format_proof_in_batch(
                &c1_points,
                &c2_points,
                &proofs,
                &c1_basepoint,
                &c2_basepoint,
                &blinding_basepoint
            )
            .unwrap()
        );
    }

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
        let mut proofs: Vec<ArithmeticProof> = vec![];
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
        let mut proofs: Vec<ArithmeticProof> = vec![];
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

    #[test]
    fn test_fast_small_scalar_point() {
        for i in 0..255u8 {
            let scalar = i;
            let point = *BASEPOINT_G1;
            let point_get = small_scalar_point_mul(scalar, point);
            let expect_point = Scalar::from(scalar) * point;
            assert_eq!(
                point_to_bytes(&point_get),
                point_to_bytes(&expect_point)
            );
        }
    }
}
