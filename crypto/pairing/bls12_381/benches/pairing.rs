// Copyright 2021 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand::Rng;
use wedpr_bls12_381;

/*
create_equality_encrypt_helper
                        time:   [1.8652 ms 1.9010 ms 1.9386 ms]
                        change: [+5.4197% +7.1372% +8.5629%] (p = 0.00 < 0.05)
                        Performance has regressed.

Benchmarking create_equality_test_true_helper: Collecting 100 samples in estimated 5.0818                                                                                         create_equality_test_true_helper
                        time:   [3.6239 ms 3.6720 ms 3.7206 ms]
                        change: [-0.7217% +0.7001% +2.2908%] (p = 0.38 > 0.05)
                        No change in performance detected.

Benchmarking create_equality_test_false_helper: Collecting 100 samples in estimated 5.068                                                                                         create_equality_test_false_helper
                        time:   [3.6027 ms 3.6737 ms 3.7520 ms]
                        change: [-2.9942% -0.6142% +1.7741%] (p = 0.63 > 0.05)
                        No change in performance detected.
*/

fn create_equality_encrypt_helper(c: &mut Criterion) {
    let label = format!("create_equality_encrypt_helper",);
    let message: &[u8] = b"hello world";

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = wedpr_bls12_381::encrypt_message(message);
        })
    });
}

fn create_equality_test_true_helper(c: &mut Criterion) {
    let label = format!("create_equality_test_true_helper",);
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

fn create_equality_test_false_helper(c: &mut Criterion) {
    let label = format!("create_equality_test_false_helper",);
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
