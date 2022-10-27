// Copyright 2021 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use wedpr_l_crypto_ecies_sm2::{WedprSm2Ecies, SM2_CTX};

// create_encrypt_helper, message_size = 10
// time:   [676.32 us 697.08 us 725.54 us]
// change: [-7.6677% -4.4748% -1.0071%] (p = 0.02 < 0.05)
// Performance has improved.
//
// Benchmarking create_encrypt_helper, message_size = 100: Collecting 10 samples
// in estimated
// create_encrypt_helper, message_size = 100 time:   [656.60 us 668.11 us 682.65
// us] change: [-11.193% -9.5813% -7.8530%] (p = 0.00 < 0.05)
// Performance has improved.
// Found 1 outliers among 10 measurements (10.00%)
// 1 (10.00%) high mild
//
// Benchmarking create_encrypt_helper, message_size = 1000: Collecting 10
// samples in estimate
// create_encrypt_helper, message_size = 1000 time:   [693.57 us 696.39 us
// 699.70 us] change: [-11.448% -8.2187% -5.1503%] (p = 0.00 < 0.05)
// Performance has improved.
//
// Benchmarking create_decrypt_helper, message_size = 10: Collecting 10 samples
// in estimated
// create_decrypt_helper, message_size = 10 time:   [576.76 us 587.40 us 592.27
// us]
//
// Benchmarking create_decrypt_helper, message_size = 100: Collecting 10 samples
// in estimated
// create_decrypt_helper, message_size = 100 time:   [568.95 us 585.22 us 601.45
// us]
//
// Benchmarking create_decrypt_helper, message_size = 1000: Collecting 10
// samples in estimate
// create_decrypt_helper, message_size = 1000 time:   [661.54 us 705.09 us
// 744.70 us]

fn create_encrypt_helper(c: &mut Criterion, message_size: usize) {
    let label =
        format!("create_encrypt_helper, message_size = {}", message_size);
    let sm2_ecies = WedprSm2Ecies::default();
    let (pk_b, sk_b) = SM2_CTX.new_keypair().unwrap();
    let public_key = SM2_CTX.serialize_pubkey(&pk_b, false).unwrap();
    // let secret_key = SM2_CTX.serialize_seckey(&sk_b).unwrap();
    let message: Vec<u8> =
        (0..message_size).map(|_| rand::random::<u8>()).collect();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let ciphertext = sm2_ecies
                .encrypt(&public_key, &message, message_size)
                .unwrap();
        })
    });
}

fn create_decrypt_helper(c: &mut Criterion, message_size: usize) {
    let label =
        format!("create_decrypt_helper, message_size = {}", message_size);
    let sm2_ecies = WedprSm2Ecies::default();
    let (pk_b, sk_b) = SM2_CTX.new_keypair().unwrap();
    let public_key = SM2_CTX.serialize_pubkey(&pk_b, false).unwrap();
    let secret_key = SM2_CTX.serialize_seckey(&sk_b).unwrap();
    let message: Vec<u8> =
        (0..message_size).map(|_| rand::random::<u8>()).collect();
    let ciphertext = sm2_ecies
        .encrypt(&public_key, &message, message_size)
        .unwrap();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let decrypted_msg = sm2_ecies
                .decrypt(&secret_key, &ciphertext, message_size)
                .unwrap();
            assert_eq!(decrypted_msg, message);
        })
    });
}
fn create_encrypt_helper_10(c: &mut Criterion) {
    create_encrypt_helper(c, 10);
}

fn create_encrypt_helper_100(c: &mut Criterion) {
    create_encrypt_helper(c, 100);
}

fn create_encrypt_helper_1000(c: &mut Criterion) {
    create_encrypt_helper(c, 1000);
}

fn create_decrypt_helper_10(c: &mut Criterion) {
    create_decrypt_helper(c, 10);
}

fn create_decrypt_helper_100(c: &mut Criterion) {
    create_decrypt_helper(c, 100);
}

fn create_decrypt_helper_1000(c: &mut Criterion) {
    create_decrypt_helper(c, 1000);
}

criterion_group! {
    name = init_sm2_ecies_test;
    config = Criterion::default().sample_size(10);
targets =
    create_encrypt_helper_10,
    create_encrypt_helper_100,
    create_encrypt_helper_1000,
    create_decrypt_helper_10,
    create_decrypt_helper_100,
    create_decrypt_helper_1000,
}

criterion_main!(init_sm2_ecies_test);
