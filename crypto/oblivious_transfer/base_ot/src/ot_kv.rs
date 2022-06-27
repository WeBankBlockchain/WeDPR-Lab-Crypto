// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! KV oblivious transfer (OT) functions.

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use sha3::Sha3_512;
use wedpr_l_crypto_hash_sha3::WedprSha3_256;
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, point_to_bytes, BASEPOINT_G1,
};
use wedpr_l_utils::{error::WedprError, traits::Hash};

lazy_static! {
    static ref HASH_SHA3_256: WedprSha3_256 = WedprSha3_256::default();
}

// Receiver's secret to decrypt the chosen messages during k-out-of-n OT.
#[derive(Default, Debug, Clone)]
pub struct ReceiverSecretKOutOfN {
    pub blinding_b: Scalar,
}

// Receiver's commitment for the chosen messages during k-out-of-n OT.
#[derive(Default, Debug, Clone)]
pub struct ReceiverCommitmentKOutOfN {
    pub point_x: RistrettoPoint,
    pub point_y: RistrettoPoint,
    pub point_z: Vec<RistrettoPoint>,
}

// Sender's ciphertext item for a single encrypted message of k-out-of-n OT.
#[derive(Default, Debug, Clone)]
pub struct OtCiphertextItemKOutOfN {
    pub fingerprint: Vec<u8>,
    pub key_basepoint: RistrettoPoint,
    pub encrypted_message: Vec<Vec<u8>>,
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
        choice_list: &Vec<Vec<u8>>,
    ) -> (ReceiverSecretKOutOfN, ReceiverCommitmentKOutOfN) {
        let blinding_a = get_random_scalar();
        let blinding_b = get_random_scalar();
        let c_id = blinding_a * blinding_b;
        let point_x =
            RistrettoPoint::multiscalar_mul(&[blinding_a], &[*BASEPOINT_G1]);
        let point_y =
            RistrettoPoint::multiscalar_mul(&[blinding_b], &[*BASEPOINT_G1]);
        let mut point_z_list = Vec::new();
        for id in choice_list {
            let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);
            point_z_list
                .push(RistrettoPoint::multiscalar_mul(&[c_id - id_scalar], &[
                    *BASEPOINT_G1,
                ]));
        }
        (
            ReceiverSecretKOutOfN {
                blinding_b: blinding_b,
            },
            ReceiverCommitmentKOutOfN {
                point_x: point_x,
                point_y: point_y,
                point_z: point_z_list,
            },
        )
    }

    /// Computes OT ciphertexts based on the ReceiverCommitment from receiver.
    /// It returns ciphertext OT response for all available KV pairs. It will
    /// raise error if a plaintext message is too long.
    pub fn sender_init(
        &self,
        id_list: &Vec<Vec<u8>>,
        message_list: &Vec<Vec<u8>>,
        receiver_commitment: &ReceiverCommitmentKOutOfN,
    ) -> Result<Vec<OtCiphertextItemKOutOfN>, WedprError> {
        let mut sender_ciphertexts = Vec::new();
        let mut i = 0;
        for id in id_list {
            let blinding_r = get_random_scalar();
            let blinding_s = get_random_scalar();
            let key_basepoint =
                RistrettoPoint::multiscalar_mul(&[blinding_s, blinding_r], &[
                    receiver_commitment.point_x,
                    *BASEPOINT_G1,
                ]);
            let message = &message_list[i];
            let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);
            i += 1;
            let mut ciphertext = OtCiphertextItemKOutOfN {
                fingerprint: Vec::new(),
                key_basepoint: RistrettoPoint::default(),
                encrypted_message: Vec::new(),
            };
            ciphertext.fingerprint = HASH_SHA3_256.hash(&message);
            ciphertext.key_basepoint = key_basepoint;

            for k_point_z in &receiver_commitment.point_z {
                // TODO: Extract common OT computation to utility.
                let base_key_point = &RistrettoPoint::multiscalar_mul(
                    &[blinding_s, blinding_s * id_scalar, blinding_r],
                    &[*k_point_z, *BASEPOINT_G1, receiver_commitment.point_y],
                );
                let bytes_key = point_to_bytes(&base_key_point);
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
                ciphertext.encrypted_message.push(encrypted_message);
            }
            sender_ciphertexts.push(ciphertext)
        }
        Ok(sender_ciphertexts)
    }

    /// Decrypts the ciphertext OT response based on receiver's choice and
    /// ReceiverSecret. Receiver can only decrypt exactly choice_count OT
    /// messages. It returns the list of decrypted message bytes.
    pub fn receiver_decrypt(
        &self,
        receiver_secret: &ReceiverSecretKOutOfN,
        sender_ciphertexts: &Vec<OtCiphertextItemKOutOfN>,
        choice_count: usize,
    ) -> Result<Vec<Vec<u8>>, WedprError> {
        let mut result: Vec<Vec<u8>> = vec![];
        for ciphertext in sender_ciphertexts {
            // Get all messages already.
            if result.len() == choice_count {
                break;
            }
            let bytes_key = point_to_bytes(&RistrettoPoint::multiscalar_mul(
                &[receiver_secret.blinding_b],
                &[ciphertext.key_basepoint],
            ));
            // TODO: Add KDF function to extend the key size for long message.
            for encrypted_message in &ciphertext.encrypted_message {
                let decrypted_message: Vec<u8> = encrypted_message
                    .iter()
                    .zip(bytes_key.iter())
                    .map(|(&x1, &x2)| x1 ^ x2)
                    .collect();
                if &HASH_SHA3_256.hash(&decrypted_message)
                    == &ciphertext.fingerprint
                {
                    result.push(decrypted_message);
                    break;
                }
            }
        }
        Ok(result)
    }
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
        let choice_list =
            vec![id0.as_bytes().to_vec(), id2.as_bytes().to_vec()];
        let id_list = vec![
            id0.as_bytes().to_vec(),
            id1.as_bytes().to_vec(),
            id2.as_bytes().to_vec(),
            id3.as_bytes().to_vec(),
        ];
        let message_list = vec![
            message0.as_bytes().to_vec(),
            message1.as_bytes().to_vec(),
            message2.as_bytes().to_vec(),
            message3.as_bytes().to_vec(),
        ];
        let ot = OtKvKOutOfN::default();

        let (receiver_secret, receiver_commitment) =
            ot.receiver_init(&choice_list);
        let sender_ciphertexts = ot
            .sender_init(&id_list, &message_list, &receiver_commitment)
            .unwrap();
        let message = ot
            .receiver_decrypt(
                &receiver_secret,
                &sender_ciphertexts,
                choice_list.len(),
            )
            .unwrap();
        assert_eq!(
            vec![message0.as_bytes().to_vec(), message2.as_bytes().to_vec()],
            message
        );

        // Test error condition when an input message is too long.
        let too_long_message = "message123message123message123message123message123message123message123message123";
        let too_long_data_id_list =
            vec![id0.as_bytes().to_vec(), id1.as_bytes().to_vec()];
        let tool_long_data_message_list = vec![
            message0.as_bytes().to_vec(),
            too_long_message.as_bytes().to_vec(),
        ];
        assert_eq!(
            ot.sender_init(
                &too_long_data_id_list,
                &tool_long_data_message_list,
                &receiver_commitment
            )
            .unwrap_err(),
            WedprError::ArgumentError
        );
    }
}
