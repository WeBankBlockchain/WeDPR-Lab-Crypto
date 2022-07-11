// Copyright 2021 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#[macro_use]
extern crate criterion;
use criterion::Criterion;

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use wedpr_l_crypto_zkp_discrete_logarithm_proof::{
    self, prove_sum_relationship, verify_sum_relationship,
    verify_sum_relationship_in_batch,
};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, ArithmeticProof, BASEPOINT_G1, BASEPOINT_G2,
};

fn create_verify_sum_proof_helper(c: &mut Criterion) {
    let label = format!("create_verify_sum_proof_helper");
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
    c.bench_function(&label, move |b| {
        b.iter(|| {
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
        })
    });
}

fn create_verify_sum_proof_in_batch_helper(
    c: &mut Criterion,
    batch_size: usize,
) {
    let label = format!(
        "create_verify_sum_proof_in_batch_helper, batch_size is {}",
        batch_size
    );
    let mut proofs: Vec<ArithmeticProof> = vec![];
    let mut c1_points: Vec<RistrettoPoint> = vec![];
    let mut c2_points: Vec<RistrettoPoint> = vec![];
    let mut c3_points: Vec<RistrettoPoint> = vec![];
    let value_basepoint = *BASEPOINT_G1;
    let blinding_basepoint = *BASEPOINT_G2;
    for _ in 0..batch_size {
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

    c.bench_function(&label, move |b| {
        b.iter(|| {
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
        })
    });
}

fn create_scalar_add_helper(c: &mut Criterion) {
    let label = format!("create_scalar_add_helper",);
    let scalar_1 = get_random_scalar();
    let scalar_2 = get_random_scalar();
    c.bench_function(&label, move |b| b.iter(|| scalar_1 + scalar_2));
}

fn create_scalar_mul_helper(c: &mut Criterion) {
    let label = format!("create_scalar_mul_helper",);
    let scalar_1 = get_random_scalar();
    let scalar_2 = get_random_scalar();
    c.bench_function(&label, move |b| b.iter(|| scalar_1 * scalar_2));
}

fn create_point_mul_helper(c: &mut Criterion) {
    let label = format!("create_point_mul_helper",);
    let scalar_1 = get_random_scalar();
    let value_basepoint = *BASEPOINT_G1;
    c.bench_function(&label, move |b| b.iter(|| scalar_1 * value_basepoint));
}

fn create_point_mul_1_helper(c: &mut Criterion) {
    let label = format!("create_point_mul_1_helper",);
    let scalar_1 = Scalar::one();
    let value_basepoint = *BASEPOINT_G1;
    c.bench_function(&label, move |b| b.iter(|| scalar_1 * value_basepoint));
}

fn create_point_mul_u32_helper(c: &mut Criterion) {
    let label = format!("create_point_mul_u32_helper",);
    let scalar_1 = Scalar::from(8827322u32);
    let value_basepoint = *BASEPOINT_G1;
    c.bench_function(&label, move |b| b.iter(|| scalar_1 * value_basepoint));
}

fn create_point_add_helper(c: &mut Criterion) {
    let label = format!("create_point_add_helper",);
    let value_basepoint = *BASEPOINT_G1;
    let blinding_basepoint = *BASEPOINT_G2;

    c.bench_function(&label, move |b| {
        b.iter(|| value_basepoint + blinding_basepoint)
    });
}

fn create_verify_sum_proof_in_batch_10(c: &mut Criterion) {
    create_verify_sum_proof_in_batch_helper(c, 10);
}

fn create_verify_sum_proof_in_batch_50(c: &mut Criterion) {
    create_verify_sum_proof_in_batch_helper(c, 50);
}

fn create_verify_sum_proof_in_batch_100(c: &mut Criterion) {
    create_verify_sum_proof_in_batch_helper(c, 100);
}

criterion_group! {
    name = init_dlp_test;
    config = Criterion::default().sample_size(10);
targets =
create_verify_sum_proof_helper,
create_verify_sum_proof_in_batch_10,
create_verify_sum_proof_in_batch_50,
create_verify_sum_proof_in_batch_100,
create_scalar_add_helper,
create_scalar_mul_helper,
create_point_add_helper,
create_point_mul_helper,
create_point_mul_1_helper,
create_point_mul_u32_helper,
}

criterion_main!(init_dlp_test);
