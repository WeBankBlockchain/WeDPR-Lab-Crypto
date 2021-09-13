#[macro_use]
extern crate criterion;
use criterion::Criterion;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use wedpr_l_crypto_ot_base_ot::{
    k_out_of_n::{
        receiver_decrypt_k_out_of_n, receiver_init_k_out_of_n,
        sender_init_k_out_of_n,
    },
    one_out_of_n::{receiver_decrypt, receiver_init, sender_init},
    one_out_of_two::{
        receiver_decrypt_1_out_of_2, receiver_init_1_out_of_2,
        sender_init_1_out_of_2, DataOneOutOfTwo,
    },
};
use wedpr_l_protos::generated::ot::{IdList, SenderData, SenderDataPair};

fn create_base_ot_1_out_of_2_helper(c: &mut Criterion, str_len: u64) {
    let label =
        format!("create_base_ot_1_out_of_2_helper, str_len = {}", str_len);
    let random_message0: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(str_len as usize)
        .collect();
    let random_message1: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(str_len as usize)
        .collect();
    let data = DataOneOutOfTwo {
        data0: random_message0.as_bytes().to_vec(),
        data1: random_message1.as_bytes().to_vec(),
    };

    let choice = false;
    let true_message = random_message0.as_bytes().to_vec();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let (blinding_b, point_x, point_y, point_z) =
                receiver_init_1_out_of_2(choice);
            let sender_public =
                sender_init_1_out_of_2(&data, &point_x, &point_y, &point_z);
            let decrypt_message = receiver_decrypt_1_out_of_2(
                choice,
                &blinding_b,
                &sender_public,
            );
            assert_eq!(decrypt_message, true_message);
        })
    });
}

fn create_base_ot_k_out_of_n_helper(
    c: &mut Criterion,
    k_choose_count: u64,
    n_message_count: u64,
    str_len: u64,
) {
    let label = format!(
        "create_base_ot_k_out_of_n_helper, k_choose_count = {}, \
         n_message_count = {}, str_len = {}",
        k_choose_count, n_message_count, str_len
    );
    let mut sender_data = SenderData::default();
    let mut expect: Vec<Vec<u8>> = vec![];
    for _ in 0..n_message_count {
        let random_id: String =
            thread_rng().sample_iter(&Alphanumeric).take(18).collect();
        let random_message: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(str_len as usize)
            .collect();
        sender_data.mut_pair().push(SenderDataPair {
            id: random_id.as_bytes().to_vec(),
            message: random_message.as_bytes().to_vec(),
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        })
    }
    let mut choose_id_list = IdList::default();
    for i in 0..k_choose_count {
        choose_id_list
            .mut_id()
            .push(sender_data.get_pair()[i as usize].get_id().to_vec());
        expect.push(sender_data.get_pair()[i as usize].get_message().to_vec())
    }
    let use_data = sender_data.clone();
    c.bench_function(&label, move |b| {
        b.iter(|| {
            let (r_secret, r_public) =
                receiver_init_k_out_of_n(&choose_id_list);
            let s_public =
                sender_init_k_out_of_n(&use_data, &r_public).unwrap();
            let message =
                receiver_decrypt_k_out_of_n(&r_secret, &s_public).unwrap();
            assert_eq!(message, expect);
        })
    });
}

fn create_base_ot_helper(c: &mut Criterion, message_count: u64, str_len: u64) {
    let label = format!(
        "create_base_ot_helper, message_count = {}, str_len = {}",
        message_count, str_len
    );
    let mut sender_data = SenderData::default();
    for _ in 0..message_count {
        let random_id: String =
            thread_rng().sample_iter(&Alphanumeric).take(18).collect();
        let random_message: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(str_len as usize)
            .collect();
        sender_data.mut_pair().push(SenderDataPair {
            id: random_id.as_bytes().to_vec(),
            message: random_message.as_bytes().to_vec(),
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        })
    }
    let use_data = sender_data.clone();
    let choose_id =
        sender_data.get_pair()[sender_data.get_pair().len() / 2].get_id();
    let true_message =
        sender_data.get_pair()[sender_data.get_pair().len() / 2].get_message();
    // let choose_id =
    //     sender_data.get_pair()[0].get_id();
    // let true_message =
    //     sender_data.get_pair()[0].get_message();
    c.bench_function(&label, move |b| {
        b.iter(|| {
            let (r_secret, r_public) = receiver_init(choose_id);
            let s_public = sender_init(&use_data, &r_public).unwrap();
            let message = receiver_decrypt(&r_secret, &s_public).unwrap();
            assert_eq!(message.as_slice(), true_message);
        })
    });
}

fn create_base_ot_10_10(c: &mut Criterion) {
    create_base_ot_helper(c, 10, 10);
}

fn create_base_ot_100_10(c: &mut Criterion) {
    create_base_ot_helper(c, 100, 10);
}

fn create_base_ot_1000_10(c: &mut Criterion) {
    create_base_ot_helper(c, 1000, 10);
}

fn create_base_ot_10000_10(c: &mut Criterion) {
    create_base_ot_helper(c, 10000, 10);
}

fn create_base_ot_300_10(c: &mut Criterion) {
    create_base_ot_helper(c, 300, 10);
}

fn create_base_ot_3000_10(c: &mut Criterion) {
    create_base_ot_helper(c, 3000, 10);
}

fn create_base_ot_30000_10(c: &mut Criterion) {
    create_base_ot_helper(c, 30000, 10);
}

fn create_base_ot_k_out_of_n_1_300_10(c: &mut Criterion) {
    create_base_ot_k_out_of_n_helper(c, 1, 300, 10);
}

fn create_base_ot_k_out_of_n_3_300_10(c: &mut Criterion) {
    create_base_ot_k_out_of_n_helper(c, 3, 300, 10);
}

fn create_base_ot_k_out_of_n_15_300_10(c: &mut Criterion) {
    create_base_ot_k_out_of_n_helper(c, 15, 300, 10);
}

fn create_base_ot_k_out_of_n_30_300_10(c: &mut Criterion) {
    create_base_ot_k_out_of_n_helper(c, 30, 300, 10);
}

fn create_base_ot_k_out_of_n_60_300_10(c: &mut Criterion) {
    create_base_ot_k_out_of_n_helper(c, 60, 300, 10);
}

fn create_base_ot_1_out_of_2_10(c: &mut Criterion) {
    create_base_ot_1_out_of_2_helper(c, 10);
}

criterion_group! {
    name = init_base_ot_test;
    config = Criterion::default().sample_size(10);
targets =
    create_base_ot_1_out_of_2_10,
create_base_ot_10_10,
create_base_ot_100_10,
create_base_ot_1000_10,
create_base_ot_10000_10,
    create_base_ot_300_10,
    create_base_ot_3000_10,
    create_base_ot_30000_10,
    create_base_ot_k_out_of_n_1_300_10,
    create_base_ot_k_out_of_n_3_300_10,
    create_base_ot_k_out_of_n_15_300_10,
    create_base_ot_k_out_of_n_30_300_10,
    create_base_ot_k_out_of_n_60_300_10,
}

criterion_main!(init_base_ot_test);
