// Copyright 2021 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use wedpr_bls12_381;
use rand::Rng;

fn create_equality_encrypt_helper(c: &mut Criterion) {
    let label = format!(
        "create_equality_encrypt_helper",
    );
    let message: &[u8] = b"hello world";

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = wedpr_bls12_381::encrypt_message(message);
        })
    });
}

fn create_equality_test_true_helper(
    c: &mut Criterion,
) {
    let label = format!(
        "create_equality_test_true_helper",
    );
    let message1: &[u8] = b"hello world";
    // let message2: &[u8] = b"hello world";
    let c1 = wedpr_bls12_381::encrypt_message(message1);
    let c2 = wedpr_bls12_381::encrypt_message(message1);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            assert_eq!(wedpr_bls12_381::equality_test(&c1, &c2), true);
        })
    });
}


fn create_equality_test_false_helper(
    c: &mut Criterion,
) {
    let label = format!(
        "create_equality_test_false_helper",
    );
    let message1: &[u8] = b"hello world";
    let message2: &[u8] = b"hello wedpr";
    let c1 = wedpr_bls12_381::encrypt_message(message1);
    let c2 = wedpr_bls12_381::encrypt_message(message2);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            assert_eq!(wedpr_bls12_381::equality_test(&c1, &c2), false);
        })
    });
}

criterion_group! {
    name = init_equality_test;
    config = Criterion::default().sample_size(100);
targets =
    create_equality_encrypt_helper,
    create_equality_test_true_helper,
    create_equality_test_false_helper,
}

criterion_main!(init_equality_test);
