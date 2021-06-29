#[macro_use]
extern crate criterion;
use num_bigint::BigUint;
use criterion::Criterion;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use base_ot_mod::utils::get_random_biguint;
use base_ot_mod::constant::{G_GENERATOR, N_MOD};
use std::ops::Add;
use num_integer::Integer;

fn create_base_ot_mod(c: &mut Criterion) {
    let label =
        format!("create_base_ot_mod");
    let random_number = get_random_biguint();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = G_GENERATOR.modpow(&random_number, &N_MOD);
        })
    });
}

fn create_base_ot_mul(c: &mut Criterion) {
    let label =
        format!("create_base_ot_mul");
    let random_number1 = get_random_biguint();
    let random_number2 = get_random_biguint();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            // let _ = (random_number1 * random_number2) % *N_MOD;
        })
    });
}
//
// fn create_base_ot_add(c: &mut Criterion) {
//     let label =
//         format!("create_base_ot_add");
//     let random_number1 = get_random_biguint();
//     let random_number2 = get_random_biguint();
//
//     c.bench_function(&label, move |b| {
//         b.iter(|| {
//             let _ = random_number1.add(&random_number2).mod_floor(&N_MOD);
//         })
//     });
// }

criterion_group! {
    name = init_base_ot_test;
    config = Criterion::default().sample_size(10);
targets =
    // create_base_ot_add,
    // create_base_ot_mul,
    create_base_ot_mod,
}

criterion_main!(init_base_ot_test);
