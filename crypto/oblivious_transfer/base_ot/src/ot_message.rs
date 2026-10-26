// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Authenticated 1-out-of-2 message OT using the version 2 KV OT protocol.
//! Security assumes semi-honest participants. The padded lengths are public;
//! decryption failures must remain local to avoid selective-failure feedback.

use crate::ot_kv::{
    OtCiphertextItemKOutOfN, OtKvKOutOfN, ReceiverCommitmentKOutOfN,
    ReceiverSecretKOutOfN,
};
use wedpr_l_utils::error::WedprError;

// Fixed, distinct IDs separate this application from caller-chosen KV IDs.
const ID_ZERO: &[u8] = b"WeDPR/1-out-of-2-OT/v2/zero";
const ID_ONE: &[u8] = b"WeDPR/1-out-of-2-OT/v2/one";

/// Sender's plaintext messages.
#[derive(Default, Debug, Clone)]
pub struct TwoOtMessages {
    pub message0: Vec<u8>,
    pub message1: Vec<u8>,
}

/// Version 2 row containing one authenticated encrypted choice. The legacy
/// raw XOR wire layout must not be accepted or translated automatically.
pub type TwoOtCiphertextItem = OtCiphertextItemKOutOfN;

/// Sender's two version 2 ciphertext rows, in fixed order.
#[derive(Default, Debug, Clone)]
pub struct TwoOtCiphertexts {
    pub ciphertext0: TwoOtCiphertextItem,
    pub ciphertext1: TwoOtCiphertextItem,
}

/// Private state, including the query transcript. Never transmit or log it.
#[derive(Default, Clone)]
pub struct ReceiverSecret1OutOf2 {
    choose_zero: bool,
    inner: ReceiverSecretKOutOfN,
}

/// Version 2 query with exactly one independently blinded choice.
pub type ReceiverCommitment1OutOf2 = ReceiverCommitmentKOutOfN;

/// Semi-honest 1-out-of-2 OT with hashed DH keys and authenticated ciphertexts.
#[derive(Default, Debug, Clone)]
pub struct OtMessages1OutOf2 {}

impl OtMessages1OutOf2 {
    /// Create a fresh query and private state for one choice.
    pub fn receiver_init(
        &self,
        choose_zero: bool,
    ) -> (ReceiverSecret1OutOf2, ReceiverCommitment1OutOf2) {
        let id = if choose_zero { ID_ZERO } else { ID_ONE };
        let (inner, commitment) =
            OtKvKOutOfN::default().receiver_init(&vec![id.to_vec()]);
        (ReceiverSecret1OutOf2 { choose_zero, inner }, commitment)
    }

    /// Encrypt both messages using the checked KV OT implementation. Its KDF
    /// binds the shared secret, query, row index and sender's ephemeral point.
    pub fn sender_init(
        &self,
        data: &TwoOtMessages,
        receiver_commitment: &ReceiverCommitment1OutOf2,
    ) -> Result<TwoOtCiphertexts, WedprError> {
        if receiver_commitment.choices.len() != 1 {
            return Err(WedprError::ArgumentError);
        }
        let rows = OtKvKOutOfN::default().sender_init(
            &vec![ID_ZERO.to_vec(), ID_ONE.to_vec()],
            &vec![data.message0.clone(), data.message1.clone()],
            receiver_commitment,
        )?;
        let mut rows = rows.into_iter();
        Ok(TwoOtCiphertexts {
            ciphertext0: rows.next().ok_or(WedprError::FormatError)?,
            ciphertext1: rows.next().ok_or(WedprError::FormatError)?,
        })
    }

    /// Authenticate the selected message before releasing plaintext. A bad
    /// tag, wrong query, wrong choice or malformed response returns an error.
    pub fn receiver_decrypt(
        &self,
        choose_zero: bool,
        receiver_secret: &ReceiverSecret1OutOf2,
        sender_ciphertexts: &TwoOtCiphertexts,
    ) -> Result<Vec<u8>, WedprError> {
        if choose_zero != receiver_secret.choose_zero {
            return Err(WedprError::ArgumentError);
        }
        let mut messages = OtKvKOutOfN::default().receiver_decrypt(
            &receiver_secret.inner,
            &vec![
                sender_ciphertexts.ciphertext0.clone(),
                sender_ciphertexts.ciphertext1.clone(),
            ],
            1,
        )?;
        messages.pop().ok_or(WedprError::FormatError)
    }
}

/// Creates OT message data from strings.
pub fn make_two_ot_messages(message0: &str, message1: &str) -> TwoOtMessages {
    TwoOtMessages {
        message0: message0.as_bytes().to_vec(),
        message1: message1.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;

    #[test]
    fn both_choices_support_empty_and_long_messages() {
        let ot = OtMessages1OutOf2::default();
        for length in [0, 1, 32, 33, 1024] {
            let data = TwoOtMessages {
                message0: vec![0u8; length],
                message1: vec![1u8; length + 1],
            };
            for choose_zero in [true, false] {
                let (secret, query) = ot.receiver_init(choose_zero);
                let response = ot.sender_init(&data, &query).unwrap();
                let expected = if choose_zero {
                    &data.message0
                } else {
                    &data.message1
                };
                assert_eq!(
                    &ot.receiver_decrypt(choose_zero, &secret, &response)
                        .unwrap(),
                    expected
                );
                assert!(ot
                    .receiver_decrypt(!choose_zero, &secret, &response)
                    .is_err());
            }
        }
    }

    #[test]
    fn rejects_tampering_reordering_and_cross_query_replay() {
        let ot = OtMessages1OutOf2::default();
        let data =
            make_two_ot_messages("selected message", "unselected message");
        for choose_zero in [true, false] {
            let (secret, query) = ot.receiver_init(choose_zero);
            let response = ot.sender_init(&data, &query).unwrap();
            let selected = if choose_zero {
                &response.ciphertext0
            } else {
                &response.ciphertext1
            };
            for index in
                0..selected.encrypted_choices[0].encrypted_message.len()
            {
                let mut changed = response.clone();
                let row = if choose_zero {
                    &mut changed.ciphertext0
                } else {
                    &mut changed.ciphertext1
                };
                row.encrypted_choices[0].encrypted_message[index] ^= 1;
                assert!(ot
                    .receiver_decrypt(choose_zero, &secret, &changed)
                    .is_err());
            }
            let mut changed = response.clone();
            let row = if choose_zero {
                &mut changed.ciphertext0
            } else {
                &mut changed.ciphertext1
            };
            row.encrypted_choices[0].iv[0] ^= 1;
            assert!(ot
                .receiver_decrypt(choose_zero, &secret, &changed)
                .is_err());
            let mut changed = response.clone();
            let row = if choose_zero {
                &mut changed.ciphertext0
            } else {
                &mut changed.ciphertext1
            };
            row.encrypted_choices[0].key_basepoint = RistrettoPoint::default();
            assert!(ot
                .receiver_decrypt(choose_zero, &secret, &changed)
                .is_err());
            let mut changed = response.clone();
            std::mem::swap(&mut changed.ciphertext0, &mut changed.ciphertext1);
            assert!(ot
                .receiver_decrypt(choose_zero, &secret, &changed)
                .is_err());
            let (other, _) = ot.receiver_init(choose_zero);
            assert!(ot
                .receiver_decrypt(choose_zero, &other, &response)
                .is_err());
        }
    }

    #[test]
    fn rejects_legacy_versions_and_invalid_query_shapes() {
        let ot = OtMessages1OutOf2::default();
        let data = make_two_ot_messages("zero", "one");
        assert!(ot
            .sender_init(&data, &ReceiverCommitment1OutOf2::default())
            .is_err());
        let (secret, query) = ot.receiver_init(true);
        let mut invalid = query.clone();
        invalid.version = 1;
        assert!(ot.sender_init(&data, &invalid).is_err());
        let mut invalid = query.clone();
        invalid.choices[0].point_x = RistrettoPoint::default();
        assert!(ot.sender_init(&data, &invalid).is_err());
        let mut invalid = query.clone();
        invalid.choices.push(invalid.choices[0].clone());
        assert!(ot.sender_init(&data, &invalid).is_err());
        let mut response = ot.sender_init(&data, &query).unwrap();
        response.ciphertext0.version = 1;
        assert!(ot.receiver_decrypt(true, &secret, &response).is_err());
    }
}
