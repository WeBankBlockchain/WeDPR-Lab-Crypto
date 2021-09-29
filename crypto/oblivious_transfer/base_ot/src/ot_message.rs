// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Message oblivious transfer (OT) functions.

use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, point_to_bytes, BASEPOINT_G1,
};
use wedpr_l_utils::error::WedprError;

// TODO: Move the following structs to protos if necessary.

/// Sender's plaintext bytes collection of 1-out-of-2 OT.
#[derive(Default, Debug, Clone)]
pub struct TwoOtMessages {
    pub message0: Vec<u8>,
    pub message1: Vec<u8>,
}

/// Sender's ciphertext item for a single encrypted message of 1-out-of-2 OT.
#[derive(Default, Debug, Clone)]
pub struct TwoOtCiphertextItem {
    pub key_basepoint: RistrettoPoint,
    pub encrypted_message: Vec<u8>,
}

/// Sender's ciphertext collection of 1-out-of-2 OT.
#[derive(Default, Debug, Clone)]
pub struct TwoOtCiphertexts {
    pub ciphertext0: TwoOtCiphertextItem,
    pub ciphertext1: TwoOtCiphertextItem,
}

/// Receiver's secret to decrypt the chosen messages during 1-out-of-2 OT.
#[derive(Default, Debug, Clone)]
pub struct ReceiverSecret1OutOf2 {
    pub scalar_b: Scalar,
}

/// Receiver's commitment for the chosen messages during 1-out-of-2 OT.
#[derive(Default, Debug, Clone)]
pub struct ReceiverCommitment1OutOf2 {
    pub point_x: RistrettoPoint,
    pub point_y: RistrettoPoint,
    pub point_z: RistrettoPoint,
}

/// Implements a 1-out-of-2 message OT instance.
/// Sender has two data messages, message0 and message1,
/// 1-out-of-2 message OT can help receiver to get
/// exactly one chosen message without disclosing receiver's actual choice and
/// the rest of sender's messages.
#[derive(Default, Debug, Clone)]
pub struct OtMessages1OutOf2 {}

impl OtMessages1OutOf2 {
    /// Generates an OT query based on receiver's choice. It will pick message0
    /// if choose_zero is true otherwise message1.
    /// It returns ReceiverSecret and ReceiverCommitment. ReceiverSecret will be
    /// later used to decrypt the chosen message which should by kept secretly
    /// by receiver. ReceiverCommitment is the actual query to be sent to
    /// sender for generating OT response.
    pub fn receiver_init(
        &self,
        choose_zero: bool,
    ) -> (ReceiverSecret1OutOf2, ReceiverCommitment1OutOf2) {
        let blinding_a = get_random_scalar();
        let blinding_b = get_random_scalar();
        let c_id = blinding_a * blinding_b;
        let point_x =
            RistrettoPoint::multiscalar_mul(&[blinding_a], &[*BASEPOINT_G1]);
        let point_y =
            RistrettoPoint::multiscalar_mul(&[blinding_b], &[*BASEPOINT_G1]);
        let point_z: RistrettoPoint;
        if choose_zero {
            point_z =
                RistrettoPoint::multiscalar_mul(&[c_id], &[*BASEPOINT_G1]);
        } else {
            point_z =
                RistrettoPoint::multiscalar_mul(&[c_id - Scalar::one()], &[
                    *BASEPOINT_G1,
                ]);
        }
        (
            ReceiverSecret1OutOf2 {
                scalar_b: blinding_b,
            },
            ReceiverCommitment1OutOf2 {
                point_x,
                point_y,
                point_z,
            },
        )
    }

    /// Computes OT ciphertexts based on the ReceiverCommitment from receiver.
    /// It returns ciphertext OT response for all available messages. It will
    /// raise error if a plaintext message is too long.
    pub fn sender_init(
        &self,
        data: &TwoOtMessages,
        receiver_commitment: &ReceiverCommitment1OutOf2,
    ) -> Result<TwoOtCiphertexts, WedprError> {
        let ReceiverCommitment1OutOf2 {
            point_x,
            point_y,
            point_z,
        } = receiver_commitment;

        // Encrypt message 0.
        let (key_basepoint0, encrypted_message0) =
            OtMessages1OutOf2::sender_encrypt_message(
                &data.message0,
                point_x,
                point_y,
                point_z,
            )?;
        // Encrypt message 1.
        let point_z1 = point_z + *BASEPOINT_G1;
        let (key_basepoint1, encrypted_message1) =
            OtMessages1OutOf2::sender_encrypt_message(
                &data.message1,
                point_x,
                point_y,
                &point_z1,
            )?;

        Ok(TwoOtCiphertexts {
            ciphertext0: TwoOtCiphertextItem {
                key_basepoint: key_basepoint0,
                encrypted_message: encrypted_message0,
            },
            ciphertext1: TwoOtCiphertextItem {
                key_basepoint: key_basepoint1,
                encrypted_message: encrypted_message1,
            },
        })
    }

    /// Decrypts the ciphertext OT response based on receiver's choice and
    /// ReceiverSecret. Receiver can only decrypt exactly one OT message. It
    /// returns the decrypted message bytes.
    pub fn receiver_decrypt(
        &self,
        choose_zero: bool,
        receiver_secret: &ReceiverSecret1OutOf2,
        sender_ciphertexts: &TwoOtCiphertexts,
    ) -> Vec<u8> {
        let blinding_b = receiver_secret.scalar_b;
        if choose_zero {
            OtMessages1OutOf2::receiver_decrypt_message(
                &sender_ciphertexts.ciphertext0,
                &blinding_b,
            )
        } else {
            OtMessages1OutOf2::receiver_decrypt_message(
                &sender_ciphertexts.ciphertext1,
                &blinding_b,
            )
        }
    }

    fn sender_encrypt_message(
        message: &Vec<u8>,
        point_x: &RistrettoPoint,
        point_y: &RistrettoPoint,
        point_z: &RistrettoPoint,
    ) -> Result<(RistrettoPoint, Vec<u8>), WedprError> {
        let blinding_r = get_random_scalar();
        let blinding_s = get_random_scalar();
        let key_basepoint =
            RistrettoPoint::multiscalar_mul(&[blinding_s, blinding_r], &[
                *point_x,
                *BASEPOINT_G1,
            ]);
        let bytes_key = point_to_bytes(&RistrettoPoint::multiscalar_mul(
            &[blinding_s, blinding_r],
            &[*point_z, *point_y],
        ));
        // TODO: Add KDF function to extend the key size for long message.
        if bytes_key.len() < message.len() {
            return Err(WedprError::ArgumentError);
        }
        let encrypted_message: Vec<u8> = message
            .iter()
            .zip(bytes_key.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        Ok((key_basepoint, encrypted_message))
    }

    fn receiver_decrypt_message(
        ciphertext: &TwoOtCiphertextItem,
        blinding_b: &Scalar,
    ) -> Vec<u8> {
        let bytes_key =
            point_to_bytes(&RistrettoPoint::multiscalar_mul([blinding_b], [
                ciphertext.key_basepoint,
            ]));
        // TODO: Add KDF function to extend the key size for long message.
        ciphertext
            .encrypted_message
            .iter()
            .zip(bytes_key.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect()
    }
}

/// Creates OT bytes message collection from strings.
pub fn make_two_ot_messages(message0: &str, message1: &str) -> TwoOtMessages {
    TwoOtMessages {
        message0: message0.as_bytes().to_vec(),
        message1: message1.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ot_message_1_out_of_2() {
        let message0 = "wedpr test 0";
        let message1 = "wedpr test 1";
        let ot = OtMessages1OutOf2::default();
        let data = make_two_ot_messages(message0, message1);

        // Pick the first (index = 0) message.
        let choose_zero = true;
        let (receiver_secret, receiver_commitment) =
            ot.receiver_init(choose_zero);
        let sender_ciphertexts =
            ot.sender_init(&data, &receiver_commitment).unwrap();
        let decrypted_message = ot.receiver_decrypt(
            choose_zero,
            &receiver_secret,
            &sender_ciphertexts,
        );
        assert_eq!(String::from_utf8(decrypted_message).unwrap(), message0);

        // Pick the second (index = 1) message.
        let choose_zero = false;
        let (receiver_secret, receiver_commitment) =
            ot.receiver_init(choose_zero);
        let sender_ciphertexts =
            ot.sender_init(&data, &receiver_commitment).unwrap();
        let decrypted_message = ot.receiver_decrypt(
            choose_zero,
            &receiver_secret,
            &sender_ciphertexts,
        );
        assert_eq!(String::from_utf8(decrypted_message).unwrap(), message1);

        // Test error condition when an input message is too long.
        let too_long_data = make_two_ot_messages(
            message0, "message123message123message123message123message123message123message123message123");
        assert_eq!(
            ot.sender_init(&too_long_data, &receiver_commitment)
                .unwrap_err(),
            WedprError::ArgumentError
        );
    }
}
