#![allow(non_snake_case)]

extern crate criterion;
use criterion::{criterion_group, criterion_main, Criterion};
extern crate crypto;
use crypto::curve_25519_vrf;

fn create_vrf_gen_key_helper(c: &mut Criterion) {
    let label = format!("create_vrf_gen_key_helper helper");
    let x = "random message";
    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = curve_25519_vrf::curve25519_vrf_gen_pubkey(x);
        });
    });
}

fn create_vrf_is_valid_key_helper(c: &mut Criterion) {
    let label = format!("create_vrf_is_valid_key_helper helper");
    let x = "random message";
    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = curve_25519_vrf::curve25519_vrf_gen_pubkey(x);
        });
    });
}

fn create_vrf_proof_helper(c: &mut Criterion) {
    let label = format!("create_vrf_proof_helper helper");
    let x = "random message";
    let y = curve_25519_vrf::curve25519_vrf_gen_pubkey(x);
    let alpha = "test msg";
    assert_eq!(curve_25519_vrf::curve25519_vrf_is_valid_pubkey(&y), true);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _proof = curve_25519_vrf::curve25519_vrf_prove(x, alpha).unwrap();
        });
    });
}

fn create_vrf_verify_helper(c: &mut Criterion) {
    let label = format!("create_vrf_verify_helper helper");
    let x = "random message";
    let y = curve_25519_vrf::curve25519_vrf_gen_pubkey(x);
    let alpha = "test msg";
    assert_eq!(curve_25519_vrf::curve25519_vrf_is_valid_pubkey(&y), true);
    let proof = curve_25519_vrf::curve25519_vrf_prove(x, alpha).unwrap();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let result = curve_25519_vrf::curve25519_vrf_verify(&y, alpha, &proof);
            assert_eq!(result, true);
        });
    });
}

fn create_vrf_hash_helper(c: &mut Criterion) {
    let label = format!("create_vrf_hash_helper helper");
    let x = "random message";
    let y = curve_25519_vrf::curve25519_vrf_gen_pubkey(x);
    let alpha = "test msg";
    assert_eq!(curve_25519_vrf::curve25519_vrf_is_valid_pubkey(&y), true);
    let proof = curve_25519_vrf::curve25519_vrf_prove(x, alpha).unwrap();
    let result = curve_25519_vrf::curve25519_vrf_verify(&y, alpha, &proof);
    assert_eq!(result, true);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let hash = curve_25519_vrf::curve25519_vrf_proof_to_hash(&proof).unwrap();
            assert_eq!(hash.is_empty(), false);
        });
    });
}

criterion_group! {
    name = create_vrf;
    config = Criterion::default().sample_size(10);
    targets =
    create_vrf_gen_key_helper,
    create_vrf_proof_helper,
    create_vrf_is_valid_key_helper,
    create_vrf_verify_helper,
    create_vrf_hash_helper,

}
criterion_main!(create_vrf);
