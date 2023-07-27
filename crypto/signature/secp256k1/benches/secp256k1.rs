// Copyright 2021 WeDPR Lab Project Authors. Licensed under Apache-2.0.

use criterion::Criterion;
use wedpr_l_crypto_signature_secp256k1::WedprSecp256k1Recover;
use wedpr_l_utils::{
    constant::tests::BASE64_ENCODED_TEST_MESSAGE, traits::Signature,
};

#[macro_use]
extern crate criterion;

fn create_sign_helper(c: &mut Criterion, message_size: usize) {
    let label = format!("create_sign_helper, message_size = {}", message_size);
    let secp256k1 = WedprSecp256k1Recover::default();
    let (pk_b, sk_b) = secp256k1.generate_keypair();

    let message = BASE64_ENCODED_TEST_MESSAGE;

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = secp256k1.sign(&sk_b, &message.to_vec());
        })
    });
}

fn create_verify_helper(c: &mut Criterion, message_size: usize) {
    let label =
        format!("create_verify_helper, message_size = {}", message_size);
    let label = format!("create_sign_helper, message_size = {}", message_size);
    let secp256k1 = WedprSecp256k1Recover::default();
    let (pk_b, sk_b) = secp256k1.generate_keypair();

    let message = BASE64_ENCODED_TEST_MESSAGE;

    let sign_obj = secp256k1.sign(&sk_b, &message.to_vec()).unwrap();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = secp256k1.recover_public_key(&message.to_vec(), &sign_obj);
        })
    });
}
fn create_sign_helper_10(c: &mut Criterion) {
    create_sign_helper(c, 10);
}

fn create_sign_helper_100(c: &mut Criterion) {
    create_sign_helper(c, 100);
}

fn create_sign_helper_1000(c: &mut Criterion) {
    create_sign_helper(c, 1000);
}

fn create_verify_helper_10(c: &mut Criterion) {
    create_verify_helper(c, 10);
}

fn create_verify_helper_100(c: &mut Criterion) {
    create_verify_helper(c, 100);
}

fn create_verify_helper_1000(c: &mut Criterion) {
    create_verify_helper(c, 1000);
}

criterion_group! {
    name = init_secp256k1_ecies_test;
    config = Criterion::default().sample_size(10);
targets =
    // create_sign_helper_10,
    // create_sign_helper_100,
    create_sign_helper_1000,
    // create_verify_helper_10,
    // create_verify_helper_100,
    create_verify_helper_1000,
}

criterion_main!(init_secp256k1_ecies_test);
