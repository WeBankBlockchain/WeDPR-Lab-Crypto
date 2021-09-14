// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! KV oblivious transfer (OT) functions.

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
    BytesToBytesPair, DataDict, IdList, OtCiphertextItemKOutOfN,
    OtCiphertextsKOutOfN, ReceiverCommitmentKOutOfN, ReceiverSecretKOutOfN,
};
use wedpr_l_utils::{error::WedprError, traits::Hash};

lazy_static! {
    static ref HASH_SHA3_256: WedprSha3_256 = WedprSha3_256::default();
}

/// Implements a k-out-of-n KV OT instance.
/// Sender has n KV pairs, where each pair is (id, message),
/// k-out-of-n KV OT can help receiver to get exactly k messages from k matching
/// ids without disclosing receiver's actual choice and the rest of sender's
/// messages.
#[derive(Default, Debug, Clone)]
pub struct OtKvKOutOfN {}

impl OtKvKOutOfN {
    /// Generates an OT query based on receiver's choice of ids from
    /// choice_list. It returns ReceiverSecret and ReceiverCommitment.
    /// ReceiverSecret will be later used to decrypt the chosen message
    /// which should by kept secretly by receiver. ReceiverCommitment is the
    /// actual query to be sent to sender for generating OT response.
    pub fn receiver_init(
        &self,
        choice_list: &IdList,
    ) -> (ReceiverSecretKOutOfN, ReceiverCommitmentKOutOfN) {
        let blinding_a = get_random_scalar();
        let blinding_b = get_random_scalar();
        let mut receiver_commitment = ReceiverCommitmentKOutOfN::default();
        let c_id = blinding_a * blinding_b;
        let point_x =
            RistrettoPoint::multiscalar_mul(&[blinding_a], &[*BASEPOINT_G1]);
        let point_y =
            RistrettoPoint::multiscalar_mul(&[blinding_b], &[*BASEPOINT_G1]);
        receiver_commitment.set_point_x(point_to_bytes(&point_x));
        receiver_commitment.set_point_y(point_to_bytes(&point_y));
        for id in choice_list.get_id() {
            let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);
            let point_z =
                RistrettoPoint::multiscalar_mul(&[c_id - id_scalar], &[
                    *BASEPOINT_G1,
                ]);
            receiver_commitment
                .mut_point_z()
                .push(point_to_bytes(&point_z));
        }
        (
            ReceiverSecretKOutOfN {
                scalar_b: scalar_to_bytes(&blinding_b),
                unknown_fields: Default::default(),
                cached_size: Default::default(),
            },
            receiver_commitment,
        )
    }

    /// Computes OT ciphertexts based on the ReceiverCommitment from receiver.
    /// It returns ciphertext OT response for all available KV pairs. It will
    /// raise error if a plaintext message is too long.
    pub fn sender_init(
        &self,
        data: &DataDict,
        receiver_commitment: &ReceiverCommitmentKOutOfN,
    ) -> Result<OtCiphertextsKOutOfN, WedprError> {
        let point_x = bytes_to_point(receiver_commitment.get_point_x())?;
        let point_y = bytes_to_point(receiver_commitment.get_point_y())?;

        let mut sender_ciphertexts = OtCiphertextsKOutOfN::default();
        for data_pair in data.get_pair() {
            let blinding_r = get_random_scalar();
            let blinding_s = get_random_scalar();
            let key_basepoint =
                RistrettoPoint::multiscalar_mul(&[blinding_s, blinding_r], &[
                    point_x,
                    *BASEPOINT_G1,
                ]);
            let message = data_pair.get_message();
            let id = data_pair.get_id();
            let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);

            let mut ciphertext = OtCiphertextItemKOutOfN::default();
            ciphertext.set_fingerprint(HASH_SHA3_256.hash(message));
            ciphertext.set_key_basepoint(point_to_bytes(&key_basepoint));
            for k_point_z in receiver_commitment.get_point_z() {
                // TODO: Extract common OT computation to utility.
                let point_z = bytes_to_point(k_point_z)?;
                let bytes_key =
                    point_to_bytes(&RistrettoPoint::multiscalar_mul(
                        &[blinding_s, blinding_s * id_scalar, blinding_r],
                        &[point_z, *BASEPOINT_G1, point_y],
                    ));
                // TODO: Add KDF function to extend the key size for long
                // message.
                if bytes_key.len() < message.len() {
                    return Err(WedprError::ArgumentError);
                }
                let encrypted_message: Vec<u8> = message
                    .iter()
                    .zip(bytes_key.iter())
                    .map(|(&x1, &x2)| x1 ^ x2)
                    .collect();
                ciphertext.mut_encrypted_message().push(encrypted_message);
            }
            sender_ciphertexts.mut_ciphertext().push(ciphertext)
        }
        Ok(sender_ciphertexts)
    }

    /// Decrypts the ciphertext OT response based on receiver's choice and
    /// ReceiverSecret. Receiver can only decrypt exactly choice_count OT
    /// messages. It returns the list of decrypted message bytes.
    pub fn receiver_decrypt(
        &self,
        receiver_secret: &ReceiverSecretKOutOfN,
        sender_ciphertexts: &OtCiphertextsKOutOfN,
        choice_count: usize,
    ) -> Result<Vec<Vec<u8>>, WedprError> {
        let blinding_b = bytes_to_scalar(receiver_secret.get_scalar_b())?;
        let mut result: Vec<Vec<u8>> = vec![];
        for ciphertext in sender_ciphertexts.get_ciphertext() {
            // Get all messages already.
            if result.len() == choice_count {
                break;
            }

            let key_basepoint = bytes_to_point(ciphertext.get_key_basepoint())?;
            let bytes_key = point_to_bytes(&RistrettoPoint::multiscalar_mul(
                &[blinding_b],
                &[key_basepoint],
            ));
            // TODO: Add KDF function to extend the key size for long message.
            for encrypted_message in ciphertext.get_encrypted_message() {
                let decrypted_message: Vec<u8> = encrypted_message
                    .iter()
                    .zip(bytes_key.iter())
                    .map(|(&x1, &x2)| x1 ^ x2)
                    .collect();
                if &HASH_SHA3_256.hash(&decrypted_message)
                    == ciphertext.get_fingerprint()
                {
                    result.push(decrypted_message);
                    break;
                }
            }
        }
        Ok(result)
    }
}

/// Creates OT bytes choice list from an id list.
pub fn make_choice_list(choice_list: Vec<&str>) -> IdList {
    let mut id_list = IdList::default();
    for id in choice_list {
        id_list.mut_id().push(id.as_bytes().to_vec());
    }
    id_list
}

/// Creates OT bytes KV collection from string lists.
pub fn make_data_dict(id_list: Vec<&str>, message_list: Vec<&str>) -> DataDict {
    // TODO: Change to Result return type if necessary.
    assert_eq!(id_list.len(), message_list.len());
    let mut data_dict = DataDict::default();
    for (id, message) in id_list.iter().zip(message_list.iter()) {
        data_dict.mut_pair().push(BytesToBytesPair {
            id: (*id.as_bytes()).to_vec(),
            message: (*message.as_bytes()).to_vec(),
            unknown_fields: Default::default(),
            cached_size: Default::default(),
        })
    }
    data_dict
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ot_kv_k_out_of_n() {
        let id0 = "10-11";
        let id1 = "10#12";
        let id2 = "20-x3";
        let id3 = "30-w*";

        let message0 = "wedpr test 0";
        let message1 = "wedpr test 1";
        let message2 = "wedpr test 2";
        let message3 = "wedpr test 3";

        // Pick values of id0 and id2.
        let choice_list = make_choice_list(vec![id0, id2]);
        let data = make_data_dict(vec![id0, id1, id2, id3], vec![
            message0, message1, message2, message3,
        ]);
        let ot = OtKvKOutOfN::default();

        let (receiver_secret, receiver_commitment) =
            ot.receiver_init(&choice_list);
        let sender_ciphertexts =
            ot.sender_init(&data, &receiver_commitment).unwrap();
        let message = ot
            .receiver_decrypt(
                &receiver_secret,
                &sender_ciphertexts,
                choice_list.get_id().len(),
            )
            .unwrap();
        assert_eq!(
            vec![message0.as_bytes().to_vec(), message2.as_bytes().to_vec()],
            message
        );

        // Test error condition when an input message is too long.
        let too_long_message = "message123message123message123message123message123message123message123message123";
        let too_long_data =
            make_data_dict(vec![id0, id1], vec![message0, too_long_message]);
        assert_eq!(
            ot.sender_init(&too_long_data, &receiver_commitment)
                .unwrap_err(),
            WedprError::ArgumentError
        );
    }
}
