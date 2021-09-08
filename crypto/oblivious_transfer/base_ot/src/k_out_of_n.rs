// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! K/N Oblivious transfer (OT) functions.
/// Sender has n data records, the format of each record is (id, message),
/// K/N Oblivious transfer (OT) can help receiver to get k messages using k
/// ids one time but does't disclose receiver's k ids, and help sender keep the other n-1 messages privacy.
use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use sha3::Sha3_512;
use wedpr_l_crypto_hash_sha3::WedprSha3_256;
use wedpr_l_crypto_zkp_utils::{
    bytes_to_point, bytes_to_scalar, get_random_scalar, point_to_bytes,
    scalar_to_bytes, BASEPOINT_G1,
};
use wedpr_l_protos::generated::ot::{
    IdList, ReceiverPublic, ReceiverPublicKOutOfN, ReceiverSecret, SenderData,
    SenderPublic, SenderPublicPair, SenderPublicPairKOutOfN,
};
use wedpr_l_utils::{error::WedprError, traits::Hash};

lazy_static! {
    pub static ref HASH_SHA3_256: WedprSha3_256 = WedprSha3_256::default();
}

// Generates a request based on receiver's id list and private key, where the
// id list contains k messages' id receiver want to inquery, the
// private key used to get the message inquired is kept secretly by the
// receiver, and the request contains three public keys being sent to sender to
// encrypt the his messages.
pub fn receiver_init_k_out_of_n(
    id_list: &IdList,
) -> (ReceiverSecret, ReceiverPublicKOutOfN) {
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let mut r_public = ReceiverPublicKOutOfN::default();
    let c_id = blinding_a * blinding_b;
    let point_x =
        RistrettoPoint::multiscalar_mul(&[blinding_a], &[*BASEPOINT_G1]);
    let point_y =
        RistrettoPoint::multiscalar_mul(&[blinding_b], &[*BASEPOINT_G1]);
    r_public.set_point_x(point_to_bytes(&point_x));
    r_public.set_point_y(point_to_bytes(&point_y));
    for id in id_list.get_id() {
        let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);
        let point_z = RistrettoPoint::multiscalar_mul(&[c_id - id_scalar], &[
            *BASEPOINT_G1,
        ]);
        r_public.mut_point_z().push(point_to_bytes(&point_z));
    }
    (
        ReceiverSecret {
            scalar_a: scalar_to_bytes(&blinding_a),
            scalar_b: scalar_to_bytes(&blinding_b),
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        },
        r_public,
    )
}

// Computes sender's public responce(n pairs data for n messages), where each
// pair contains a symmetric ciphertext, a asymmetric ciphertext and a hash for
// each message(n messages in total).
// - The symmetric ciphertext is computed by encrypting the message using the symmetric
// key randomly generated for this message.
// - The asymmetric ciphertext is computed by encrypting the symmetric
// key using three public keys from receiver.
// - The hash is hash of the symmetric key, in order to help the receiver identify
// whether a certain message is the message he inquired.
pub fn sender_init_k_out_of_n(
    data: &SenderData,
    r_public: &ReceiverPublicKOutOfN,
) -> Result<SenderPublic, WedprError> {
    let mut sender_public = SenderPublic::default();
    let point_x = bytes_to_point(r_public.get_point_x())?;
    let point_y = bytes_to_point(r_public.get_point_y())?;

    for data_pair in data.get_pair() {
        let mut pair = SenderPublicPairKOutOfN::default();
        let blinding_r = get_random_scalar();
        let blinding_s = get_random_scalar();
        let point_w =
            RistrettoPoint::multiscalar_mul(&[blinding_s, blinding_r], &[
                point_x,
                *BASEPOINT_G1,
            ]);
        let message = data_pair.get_message();
        let id = data_pair.get_id();
        let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);
        pair.set_figure_print(HASH_SHA3_256.hash(message));
        pair.set_point_w(point_to_bytes(&point_w));
        for k_point_z in r_public.get_point_z() {
            let point_z = bytes_to_point(k_point_z)?;
            let point_key = RistrettoPoint::multiscalar_mul(
                &[blinding_s, blinding_s * id_scalar, blinding_r],
                &[point_z, *BASEPOINT_G1, point_y],
            );
            let mut bytes_key = point_to_bytes(&point_key);
            while message.len() > bytes_key.len() {
                for key_bytes in bytes_key.clone() {
                    bytes_key.push(key_bytes);
                }
            }
            let encrypt_message: Vec<u8> = message
                .iter()
                .zip(bytes_key.iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();
            pair.mut_encrypt_message().push(encrypt_message);
        }
        sender_public.mut_pairKN().push(pair)
    }
    Ok(sender_public)
}

// Recovers k messages receiver inquired, specifically for each pair data from
// sender, receiver
// step1. uses receiver's private key to decrypt the asymmetric
// ciphertext to obtain the symmetric key.
// step2.
// calculates the hash of the symmetric key and compare it with the received
// hash. If it matches, specify that the corresponding symmetric ciphertext is
// the ciphertext of message inquired, otherwise, perform the calculation of the
// next pair data.
// step3. uses the symmetric key in step1 to decrypt the
// symmetric ciphertext identified in step2 to obtain the message inquired.
pub fn receiver_decrypt_k_out_of_n(
    secret: &ReceiverSecret,
    sender_public: &SenderPublic,
) -> Result<Vec<Vec<u8>>, WedprError> {
    let blinding_b = bytes_to_scalar(secret.get_scalar_b())?;
    let mut result: Vec<Vec<u8>> = vec![];
    let mut skip_vector: Vec<&[u8]> = vec![];
    for pair in sender_public.get_pairKN() {
        let point_w = bytes_to_point(pair.get_point_w())?;
        if skip_vector.contains(&pair.get_figure_print()) {
            continue;
        }
        let point_key =
            RistrettoPoint::multiscalar_mul(&[blinding_b], &[point_w]);
        let mut bytes_key = point_to_bytes(&point_key);
        for encrypt_message in pair.get_encrypt_message() {
            while encrypt_message.len() > bytes_key.len() {
                for key_bytes in bytes_key.clone() {
                    bytes_key.push(key_bytes);
                }
            }
            let decrypt_message: Vec<u8> = encrypt_message
                .iter()
                .zip(bytes_key.iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();
            if &HASH_SHA3_256.hash(&decrypt_message) == pair.get_figure_print()
            {
                result.push(decrypt_message);
                skip_vector.push(pair.get_figure_print());
            }
        }
    }
    Ok(result)
}

pub fn receiver_init(id: &[u8]) -> (ReceiverSecret, ReceiverPublic) {
    let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);
    let blinding_a = get_random_scalar();
    let blinding_b = get_random_scalar();
    let c_id = blinding_a * blinding_b;
    let point_x =
        RistrettoPoint::multiscalar_mul(&[blinding_a], &[*BASEPOINT_G1]);
    let point_y =
        RistrettoPoint::multiscalar_mul(&[blinding_b], &[*BASEPOINT_G1]);
    let point_z =
        RistrettoPoint::multiscalar_mul(&[c_id - id_scalar], &[*BASEPOINT_G1]);
    (
        ReceiverSecret {
            scalar_a: scalar_to_bytes(&blinding_a),
            scalar_b: scalar_to_bytes(&blinding_b),
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        },
        ReceiverPublic {
            point_x: point_to_bytes(&point_x),
            point_y: point_to_bytes(&point_y),
            point_z: point_to_bytes(&point_z),
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        },
    )
}

pub fn sender_init(
    data: &SenderData,
    r_public: &ReceiverPublic,
) -> Result<SenderPublic, WedprError> {
    let mut sender_public = SenderPublic::default();
    let point_x = bytes_to_point(r_public.get_point_x())?;
    let point_y = bytes_to_point(r_public.get_point_y())?;
    let point_z = bytes_to_point(r_public.get_point_z())?;
    for data_pair in data.get_pair() {
        let blinding_r = get_random_scalar();
        let blinding_s = get_random_scalar();
        let point_w =
            RistrettoPoint::multiscalar_mul(&[blinding_s, blinding_r], &[
                point_x,
                *BASEPOINT_G1,
            ]);
        let message = data_pair.get_message();
        let id = data_pair.get_id();
        let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);
        let point_key = RistrettoPoint::multiscalar_mul(
            &[blinding_s, blinding_s * id_scalar, blinding_r],
            &[point_z, *BASEPOINT_G1, point_y],
        );
        let mut bytes_key = point_to_bytes(&point_key);
        while message.len() > bytes_key.len() {
            for key_bytes in bytes_key.clone() {
                bytes_key.push(key_bytes);
            }
        }
        let encrypt_message: Vec<u8> = message
            .iter()
            .zip(bytes_key.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        sender_public.mut_pair().push(SenderPublicPair {
            figure_print: HASH_SHA3_256.hash(message),
            point_w: point_to_bytes(&point_w),
            encrypt_message,
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        })
    }
    Ok(sender_public)
}

pub fn receiver_decrypt(
    secret: &ReceiverSecret,
    // id: &[u8],
    sender_public: &SenderPublic,
) -> Result<Vec<u8>, WedprError> {
    let blinding_b = bytes_to_scalar(secret.get_scalar_b())?;
    for pair in sender_public.get_pair() {
        // if id != pair.get_id() {
        //     continue;
        // }
        let point_w = bytes_to_point(pair.get_point_w())?;
        let encrypt_message = pair.get_encrypt_message();
        let point_key =
            RistrettoPoint::multiscalar_mul(&[blinding_b], &[point_w]);
        let mut bytes_key = point_to_bytes(&point_key);
        while encrypt_message.len() > bytes_key.len() {
            for key_bytes in bytes_key.clone() {
                bytes_key.push(key_bytes);
            }
        }
        let decrypt_message: Vec<u8> = encrypt_message
            .iter()
            .zip(bytes_key.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        if &HASH_SHA3_256.hash(&decrypt_message) == pair.get_figure_print() {
            return Ok(decrypt_message);
        }
    }
    Err(WedprError::ArgumentError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_protos::generated::ot::SenderDataPair;

    #[test]
    fn test_base_ot_k_out_of_n() {
        let mut choose_id_pb = IdList::default();
        let mut expect: Vec<Vec<u8>> = vec![];
        choose_id_pb.mut_id().push("10086".as_bytes().to_vec());
        choose_id_pb.mut_id().push("10010".as_bytes().to_vec());
        let mut sender_data = SenderData::default();
        for (id, message) in vec![
            ("10000".as_bytes(), "wedpr test1".as_bytes()),
            ("10086".as_bytes(), "wedpr test2".as_bytes()),
            ("10010".as_bytes(), "wedpr test3".as_bytes()),
        ] {
            sender_data.mut_pair().push(SenderDataPair {
                id: id.to_vec(),
                message: message.to_vec(),
                unknown_fields: Default::default(),
                cached_size: Default::default(),
            })
        }
        let (r_secret, r_public) = receiver_init_k_out_of_n(&choose_id_pb);
        let s_public = sender_init_k_out_of_n(&sender_data, &r_public).unwrap();
        let message =
            receiver_decrypt_k_out_of_n(&r_secret, &s_public).unwrap();
        expect.push("wedpr test2".as_bytes().to_vec());
        expect.push("wedpr test3".as_bytes().to_vec());
        assert_eq!(message, expect);
    }
}
