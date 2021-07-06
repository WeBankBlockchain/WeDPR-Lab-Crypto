extern crate criterion;

use criterion::{criterion_group, criterion_main, Criterion};
use wedpr_l_crypto_signature_sm2::WedprSm2p256v1;
use wedpr_l_utils::{
    constant::tests::BASE64_ENCODED_TEST_MESSAGE,
    traits::Signature,
};

fn create_sm2p256v1_signature_sign_slow_helper(c: &mut Criterion) {
    let label = format!("create_sm2p256v1_signature_sign_slow_helper");

    let sm2_sign = WedprSm2p256v1::default();

    // The message hash (NOT the original message) is required for
    // generating a valid signature.
    let msg_hash = BASE64_ENCODED_TEST_MESSAGE;

    let (public_key, private_key) = sm2_sign.generate_keypair();

    let public_key_derive = sm2_sign.derive_public_key(&private_key).unwrap();
    assert_eq!(public_key, public_key_derive);

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = sm2_sign.sign(&private_key, &msg_hash.to_vec()).unwrap();
        });
    });
}

fn create_sm2p256v1_signature_sign_fast_helper(c: &mut Criterion) {
    let label = format!("create_sm2p256v1_signature_sign_fast_helper");

    let sm2_sign = WedprSm2p256v1::default();

    // The message hash (NOT the original message) is required for
    // generating a valid signature.
    let msg_hash = BASE64_ENCODED_TEST_MESSAGE;

    let (public_key, private_key) = sm2_sign.generate_keypair();

    let public_key_derive = sm2_sign.derive_public_key(&private_key).unwrap();
    assert_eq!(public_key, public_key_derive);

    let _ =
        sm2_sign.sign(&private_key, &msg_hash.to_vec()).unwrap();

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let _ = sm2_sign
                .sign_fast(&private_key, &public_key, &msg_hash.to_vec())
                .unwrap();
        });
    });
}

fn create_sm2p256v1_signature_verify_helper(c: &mut Criterion) {
    let label = format!("create_sm2p256v1_signature_verify_helper");

    let sm2_sign = WedprSm2p256v1::default();

    // The message hash (NOT the original message) is required for
    // generating a valid signature.
    let msg_hash = BASE64_ENCODED_TEST_MESSAGE;

    let (public_key, private_key) = sm2_sign.generate_keypair();

    let public_key_derive = sm2_sign.derive_public_key(&private_key).unwrap();
    assert_eq!(public_key, public_key_derive);

    let signature_normal =
        sm2_sign.sign(&private_key, &msg_hash.to_vec()).unwrap();
    assert_eq!(
        true,
        sm2_sign.verify(
            &public_key_derive,
            &msg_hash.to_vec(),
            &signature_normal
        )
    );
    let signature_fast = sm2_sign
    .sign_fast(&private_key, &public_key, &msg_hash.to_vec())
    .unwrap();
    c.bench_function(&label, move |b| {
        b.iter(|| {

            assert_eq!(
                true,
                sm2_sign.verify(
                    &public_key,
                    &msg_hash.to_vec(),
                    &signature_fast
                )
            );
        });
    });
}

criterion_group! {
    name = create_signature;
    config = Criterion::default().sample_size(100);
    targets =
    create_sm2p256v1_signature_sign_slow_helper,
    create_sm2p256v1_signature_sign_fast_helper,
    create_sm2p256v1_signature_verify_helper,

}
criterion_main!(create_signature);
