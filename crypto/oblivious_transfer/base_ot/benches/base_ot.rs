#[macro_use]
extern crate criterion;
use base_ot::{receiver_decrypt, receiver_init, sender_init};
use criterion::Criterion;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use wedpr_l_protos::generated::ot::{SenderData, SenderDataPair};

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

criterion_group! {
    name = init_base_ot_test;
    config = Criterion::default().sample_size(10);
targets =
create_base_ot_10_10,
create_base_ot_100_10,
create_base_ot_1000_10,
create_base_ot_10000_10,
}

criterion_main!(init_base_ot_test);
