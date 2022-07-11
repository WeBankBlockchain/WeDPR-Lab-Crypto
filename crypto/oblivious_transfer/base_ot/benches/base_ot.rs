// Copyright 2021 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use wedpr_l_crypto_ot_base_ot::{
    ot_kv::OtKvKOutOfN,
    ot_message::{make_two_ot_messages, OtMessages1OutOf2},
};

fn create_base_ot_message_1_out_of_2_helper(c: &mut Criterion, str_len: u64) {
    let label = format!(
        "create_base_ot_message_1_out_of_2_helper, str_len = {}",
        str_len
    );
    let random_message0: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(str_len as usize)
        .collect();
    let random_message1: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(str_len as usize)
        .collect();
    let data = make_two_ot_messages(&random_message0, &random_message1);

    let choose_zero = true;
    let expected_message = random_message0.as_bytes().to_vec();
    let ot = OtMessages1OutOf2::default();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let (receiver_secret, receiver_commitment) =
                ot.receiver_init(choose_zero);
            let sender_ciphertexts =
                ot.sender_init(&data, &receiver_commitment).unwrap();
            let decrypt_message = ot.receiver_decrypt(
                choose_zero,
                &receiver_secret,
                &sender_ciphertexts,
            );
            assert_eq!(decrypt_message, expected_message);
        })
    });
}

fn create_base_ot_kv_k_out_of_n_helper(
    c: &mut Criterion,
    k_choose_count: usize,
    n_message_count: usize,
    str_len: usize,
) {
    let label = format!(
        "create_base_ot_kv_k_out_of_n_helper, k_choose_count = {}, \
         n_message_count = {}, str_len = {}",
        k_choose_count, n_message_count, str_len
    );
    let mut id_list = Vec::new();
    let mut message_list = Vec::new();
    let mut expected: Vec<Vec<u8>> = vec![];
    for _ in 0..n_message_count {
        let random_id: String =
            thread_rng().sample_iter(&Alphanumeric).take(18).collect();
        let random_message: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(str_len as usize)
            .collect();
        id_list.push(random_id.as_bytes().to_vec());
        message_list.push(random_message.as_bytes().to_vec());
    }
    let mut choice_list = vec![];
    for i in 0..k_choose_count {
        choice_list.push(id_list[i].to_vec());
        expected.push(message_list[i].to_vec());
    }
    let ot = OtKvKOutOfN::default();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let (receiver_secret, receiver_commitment) =
                ot.receiver_init(&choice_list);
            let sender_ciphertexts = ot
                .sender_init(&id_list, &message_list, &receiver_commitment)
                .unwrap();
            let message = ot
                .receiver_decrypt(
                    &receiver_secret,
                    &sender_ciphertexts,
                    k_choose_count as usize,
                )
                .unwrap();
            assert_eq!(message, expected);
        })
    });
}

fn create_base_ot_kv_k_out_of_n_1_300_10(c: &mut Criterion) {
    create_base_ot_kv_k_out_of_n_helper(c, 1, 300, 10);
}

fn create_base_ot_kv_k_out_of_n_3_300_10(c: &mut Criterion) {
    create_base_ot_kv_k_out_of_n_helper(c, 3, 300, 10);
}

fn create_base_ot_kv_k_out_of_n_10_300_10(c: &mut Criterion) {
    create_base_ot_kv_k_out_of_n_helper(c, 10, 300, 10);
}

fn create_base_ot_message_1_out_of_2_10(c: &mut Criterion) {
    create_base_ot_message_1_out_of_2_helper(c, 10);
}

criterion_group! {
    name = init_base_ot_test;
    config = Criterion::default().sample_size(10);
targets =
    create_base_ot_message_1_out_of_2_10,
    create_base_ot_kv_k_out_of_n_1_300_10,
    create_base_ot_kv_k_out_of_n_3_300_10,
    create_base_ot_kv_k_out_of_n_10_300_10,
}

criterion_main!(init_base_ot_test);
