use super::*;

fn database() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    (
        vec![b"id0".to_vec(), b"id1".to_vec(), b"id2".to_vec()],
        vec![b"YES".to_vec(), b"NO".to_vec(), b"HIV_POSITIVE".to_vec()],
    )
}

#[test]
fn decrypts_all_choices_without_public_plaintext_fingerprints() {
    let ot = OtKvKOutOfN::default();
    let (ids, mut messages) = database();
    messages[0] = vec![42u8; 1024];
    let (secret, query) =
        ot.receiver_init(&vec![ids[0].clone(), ids[2].clone()]);
    let response = ot.sender_init(&ids, &messages, &query).unwrap();
    assert_eq!(
        ot.receiver_decrypt(&secret, &response, 2).unwrap(),
        vec![messages[0].clone(), messages[2].clone()]
    );
    let second = ot.sender_init(&ids, &messages, &query).unwrap();
    assert_ne!(
        response[1].encrypted_choices[0].encrypted_message,
        second[1].encrypted_choices[0].encrypted_message
    );
    // The previous dictionary attack compared SHA3(guess) to a public field.
    let digest = WedprSha3_256::default().hash(&messages[1]);
    for entry in &response[1].encrypted_choices {
        assert!(!entry
            .encrypted_message
            .windows(digest.len())
            .any(|window| window == digest.as_slice()));
    }
}

#[test]
fn independent_masks_defeat_pair_difference_dictionary_attack() {
    let ot = OtKvKOutOfN::default();
    let (ids, _) = database();
    let (_, query) = ot.receiver_init(&vec![ids[0].clone(), ids[2].clone()]);
    let delta = query.choices[0].point_z - query.choices[1].point_z;
    for first in &ids {
        for second in &ids {
            let predicted = *BASEPOINT_G1
                * (Scalar::hash_from_bytes::<Sha3_512>(second)
                    - Scalar::hash_from_bytes::<Sha3_512>(first));
            assert_ne!(delta, predicted);
        }
    }
    let (_, repeated) = ot.receiver_init(&vec![ids[0].clone(), ids[2].clone()]);
    assert_ne!(query.choices[0].point_z, repeated.choices[0].point_z);
}

#[test]
fn rejects_corruption_reordering_and_a_different_query() {
    let ot = OtKvKOutOfN::default();
    let (ids, messages) = database();
    let selections = vec![ids[0].clone(), ids[2].clone()];
    let (secret, query) = ot.receiver_init(&selections);
    let response = ot.sender_init(&ids, &messages, &query).unwrap();
    let mut corrupted = response.clone();
    corrupted[0].encrypted_choices[0].iv[0] ^= 1;
    assert!(ot.receiver_decrypt(&secret, &corrupted, 2).is_err());
    let mut corrupted = response.clone();
    corrupted[0].encrypted_choices[0].encrypted_message[8] ^= 1;
    assert!(ot.receiver_decrypt(&secret, &corrupted, 2).is_err());
    let mut reordered = response.clone();
    reordered.swap(0, 2);
    assert!(ot.receiver_decrypt(&secret, &reordered, 2).is_err());
    let mut duplicated = response.clone();
    duplicated[2] = duplicated[0].clone();
    assert!(ot.receiver_decrypt(&secret, &duplicated, 2).is_err());
    let mut swapped = response.clone();
    swapped[0].encrypted_choices.swap(0, 1);
    assert!(ot.receiver_decrypt(&secret, &swapped, 2).is_err());
    let (different_secret, _) = ot.receiver_init(&selections);
    assert!(ot
        .receiver_decrypt(&different_secret, &response, 2)
        .is_err());
    assert!(ot.receiver_decrypt(&secret, &response, 1).is_err());
}

#[test]
fn rejects_invalid_shapes_identity_points_and_legacy_versions() {
    let ot = OtKvKOutOfN::default();
    let (ids, messages) = database();
    let (secret, query) = ot.receiver_init(&vec![ids[0].clone()]);
    assert!(ot.sender_init(&ids, &vec![], &query).is_err());
    assert!(ot
        .sender_init(&vec![ids[0].clone(); 3], &messages, &query)
        .is_err());
    let (_, empty) = ot.receiver_init(&vec![]);
    assert!(ot.sender_init(&ids, &messages, &empty).is_err());
    let mut legacy = query.clone();
    legacy.version = 1;
    assert!(ot.sender_init(&ids, &messages, &legacy).is_err());
    let mut invalid = query.clone();
    invalid.choices[0].point_y = RistrettoPoint::default();
    assert!(ot.sender_init(&ids, &messages, &invalid).is_err());
    let response = ot.sender_init(&ids, &messages, &query).unwrap();
    let mut legacy = response.clone();
    legacy[0].version = 1;
    assert!(ot.receiver_decrypt(&secret, &legacy, 1).is_err());
    let mut short = response.clone();
    short[0].encrypted_choices.clear();
    assert!(ot.receiver_decrypt(&secret, &short, 1).is_err());
    let mut invalid_iv = response.clone();
    invalid_iv[0].encrypted_choices[0].iv.clear();
    assert!(ot.receiver_decrypt(&secret, &invalid_iv, 1).is_err());
}
