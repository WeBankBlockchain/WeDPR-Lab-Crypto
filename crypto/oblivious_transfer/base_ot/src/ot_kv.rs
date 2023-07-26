// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! KV oblivious transfer (OT) functions.

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use rand::Rng;
use sha3::Sha3_512;
use wedpr_l_crypto_block_cipher_aes;
use wedpr_l_crypto_hash_sha3::WedprSha3_256;
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, point_to_bytes, BASEPOINT_G1,
};
use wedpr_l_protos::generated::ot::{
    DataDict, IdList, OtCiphertextItemKOutOfN, OtCiphertextsKOutOfN,
    OtReceiverCommitmentKOutOfN, OtReceiverSecretKOutOfN,
};
use wedpr_l_utils::{
    error::WedprError,
    traits::{BlockCipher, Hash},
};

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
pub struct CiphertextItemKOutOfN {
    pub fingerprint: Vec<u8>,
    pub key_basepoint: RistrettoPoint,
    pub encrypted_message: Vec<Vec<u8>>,
}
// pub struct TwoDeepVector {}
//
// impl TwoDeepVector {
//
//     pub fn to_bytes(two_deep_vector: &Vec<Vec<u8>>) -> Vec<u8> {
//         let mut result_data = vec![];
//         if two_deep_vector.len() > 254 {
//             return vec![];
//         }
//         result_data.push(two_deep_vector.len() as u8);
//         for deep_data in two_deep_vector {
//             if deep_data.len() > 254 {
//                 return vec![];
//             }
//             result_data.push(deep_data.len() as u8);
//             for data_bytes in deep_data {
//                 result_data.push(data_bytes.clone());
//             }
//     }
//         return result_data;
//     }
//
//     pub fn from_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>, WedprError> {
//         let mut result: Vec<Vec<u8>> = vec![];
//         let true_len = data.len();
//         if true_len == 0 {
//             return Err(WedprError::FormatError);
//         }
//         let mut index = 0;
//         let out_len = data[index] as usize;
//         index = index +1 ;
//
//         if out_len > true_len {
//             return Err(WedprError::FormatError);
//         }
//         for _ in 0..out_len {
//             let mut loop_vec = vec![];
//             let mut loop_len = data[index] as usize;
//             index = index +1 ;
//             if index > true_len {
//                 return Err(WedprError::FormatError);
//             }
//             for _ in 0..loop_len {
//                 loop_vec.push(data[index]);
//                 index = index +1 ;
//
//                 if index > true_len {
//                     return Err(WedprError::FormatError);
//                 }
//             }
//             result.push(loop_vec);
//         }
//         Ok(result)
//
//
//     }
// }

/// Implements a k-out-of-n KV OT instance.
/// Sender has n KV pairs, where each pair is (id, message),
/// k-out-of-n KV OT can help receiver to get exactly k messages from k matching
/// ids without disclosing receiver's actual choice and the rest of sender's
/// messages.
#[derive(Default, Debug, Clone)]
pub struct OtKvKOutOfN {}

impl OtKvKOutOfN {
    // pub fn ot_make_choice(choice_list: &Vec<Vec<u8>>) -> IdList {
    //
    // }

    /// Generates an OT query based on receiver's choice of ids from
    /// choice_list. It returns ReceiverSecret and ReceiverCommitment.
    /// ReceiverSecret will be later used to decrypt the chosen message
    /// which should by kept secretly by receiver. ReceiverCommitment is the
    /// actual query to be sent to sender for generating OT response.
    pub fn receiver_init(
        &self,
        choice_list: &Vec<Vec<u8>>,
        // choice_list: &IdList,
    ) -> (ReceiverSecretKOutOfN, ReceiverCommitmentKOutOfN) {
        let blinding_a = get_random_scalar();
        let blinding_b = get_random_scalar();
        let c_id = blinding_a * blinding_b;
        let point_x =
            RistrettoPoint::multiscalar_mul(&[blinding_a], &[*BASEPOINT_G1]);
        let point_y =
            RistrettoPoint::multiscalar_mul(&[blinding_b], &[*BASEPOINT_G1]);
        let mut point_z_list = Vec::new();

        let mut ot_receiver_secret = OtReceiverSecretKOutOfN::new();
        ot_receiver_secret.set_scalar_b(blinding_b.to_bytes().to_vec());
        let mut ot_receiver_commitment = OtReceiverCommitmentKOutOfN::new();

        for id in choice_list.id {
            let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id.as_slice());
            point_z_list
                .push(RistrettoPoint::multiscalar_mul(&[c_id - id_scalar], &[
                    *BASEPOINT_G1,
                ]));
            // ot_receiver_commitment.point_z.
            // push(RistrettoPoint::multiscalar_mul(&[c_id - id_scalar], &[
            //     *BASEPOINT_G1,
            // ]).compress().to_bytes().to_vec());
            // point_z_list
            //     .push(RistrettoPoint::multiscalar_mul(&[c_id - id_scalar], &[
            //         *BASEPOINT_G1,
            //     ]).compress().to_bytes().to_vec());
        }

        // ot_receiver_commitment.set_point_z(point_z_list);
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
                // if bytes_key.len() < message.len() {
                //     return Err(WedprError::ArgumentError);
                // }
                let mut bytes_key_cp = bytes_key.clone();
                while bytes_key_cp.len() < message.len() {
                    // let random_number: u8 = rand::thread_rng().gen();
                    bytes_key_cp.append(&mut bytes_key.clone());
                }
                let encrypted_message: Vec<u8> = message
                    .iter()
                    .zip(bytes_key_cp.iter())
                    .map(|(&x1, &x2)| x1 ^ x2)
                    .collect();

                // let key1 = bytes_key[0..16].to_vec();
                // let iv1 = bytes_key[16..32].to_vec();
                // let aes256 =
                // wedpr_l_crypto_block_cipher_aes::WedprBlockCipherAes256::default();
                // let encrypted_message = match
                // aes256.encrypt(message, &key1, &iv1) {
                //     Ok(v) =>v,
                //     Err(_) => {
                //         wedpr_println!("aes256 encrypt failed");
                //         return Err(WedprError::FormatError)
                //     },
                // };

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
            let base_key_point = &RistrettoPoint::multiscalar_mul(
                &[receiver_secret.blinding_b],
                &[ciphertext.key_basepoint],
            );
            let bytes_key = point_to_bytes(base_key_point);

            // TODO: Add KDF function to extend the key size for long message.
            for encrypted_message in &ciphertext.encrypted_message {
                let mut bytes_key_cp = bytes_key.clone().to_vec();

                while bytes_key_cp.len() < encrypted_message.len() {
                    bytes_key_cp.append(&mut bytes_key.clone());
                }
                let decrypted_message: Vec<u8> = encrypted_message
                    .iter()
                    .zip(bytes_key_cp.iter())
                    .map(|(&x1, &x2)| x1 ^ x2)
                    .collect();
                // let aes256 =
                // wedpr_l_crypto_block_cipher_aes::WedprBlockCipherAes256::default();
                // let decrypted_message = match
                // aes256.encrypt(encrypted_message, &bytes_key, &bytes_key) {
                //     Ok(v) =>v,
                //     Err(_) => {
                //         wedpr_println!("secp256k1 ECIES encrypt failed");
                //         return Err(WedprError::FormatError)
                //     },
                // };
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
        // let message2 = "wedpr test 2";
        let message2 = "message123message123message123message123message123message123message123message123";
        let message3 = "wedpr test 3";

        // Pick values of id0 and id2.
        let choice_list =
            vec![id0.as_bytes().to_vec(), id2.as_bytes().to_vec()];
        let choice_list_bytes = TwoDeepVector::to_bytes(&choice_list);
        let choice_list_recover =
            TwoDeepVector::from_bytes(&choice_list_bytes).unwrap();
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
            ot.receiver_init(&choice_list_recover);
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
        let message_bytes = TwoDeepVector::to_bytes(&message);
        let message_bytes_recover =
            TwoDeepVector::from_bytes(&message_bytes).unwrap();
        assert_eq!(
            vec![message0.as_bytes().to_vec(), message2.as_bytes().to_vec()],
            message_bytes_recover
        );
    }
}
