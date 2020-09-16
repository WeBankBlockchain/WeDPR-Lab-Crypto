// #![allow(non_snake_case)]
// #[macro_use]
// extern crate wedpr_macros;
// extern crate criterion;
// use criterion::{criterion_group, criterion_main, Criterion};

// extern crate common;
// use common::{constant::tests, utils};

// fn create_secp256k1_signature_helper(c: &mut Criterion) {
//     let label = format!("create secp256k1 signature helper");
//     let message_hash = "hello WeDPR";
//     // 10c1b07e0a6a0d0554b153bb8f1527892358c533e319c6db7fa7a291a0082a88
//     let sk_valid = tests::TEST_SECRET_KEY;
//     // 02906b9a4d0f1f13e9e0496f9e1966c0488092555d0db5fe32272a30be7dd5e0b6
//     let pk_valid = tests::TEST_PUBLIC_KEY;
//     let sign_valid = utils::sign(&sk_valid, message_hash).unwrap();

//     c.bench_function(&label, move |b| {
//         b.iter(|| {
//             // storage verify argument
//             let verify_valid = utils::verify_signature(&pk_valid, message_hash, &sign_valid);
//             assert_eq!(verify_valid, true);
//         });
//     });
// }

// criterion_group! {
//     name = create_signature;
//     config = Criterion::default().sample_size(10);
//     targets =
//     create_secp256k1_signature_helper,

// }
// criterion_main!(create_signature);
