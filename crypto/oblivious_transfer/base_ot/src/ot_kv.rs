// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Version 2 KV OT: independent queries and authenticated encrypted messages.
//! This composes independent semi-honest 1-out-of-n queries; it does not claim
//! malicious-party security. Choice count and padded message lengths are public.
//! The sender must enforce application query limits.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use sha3::Sha3_512;
use std::collections::HashSet;
use wedpr_l_crypto_block_cipher_aes::WedprBlockCipherAes256;
use wedpr_l_crypto_hash_sha3::WedprSha3_256;
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, point_to_bytes, BASEPOINT_G1,
};
use wedpr_l_utils::{
    error::WedprError,
    traits::{BlockCipher, Hash},
};
use zeroize::Zeroizing;

/// Protocol version. Version 1 queries and responses must not be accepted.
pub const OT_KV_VERSION: u8 = 2;

/// Private receiver state. Never send it to the sender or log it.
#[derive(Default, Clone)]
pub struct ReceiverSecretKOutOfN {
    blinding_b: Vec<Scalar>,
    commitment: ReceiverCommitmentKOutOfN,
}

/// One independently masked choice.
#[derive(Default, Debug, Clone)]
pub struct ReceiverChoiceCommitment {
    pub point_x: RistrettoPoint,
    pub point_y: RistrettoPoint,
    pub point_z: RistrettoPoint,
}

/// Public query. Version 2 replaces the old shared-mask query layout.
#[derive(Default, Debug, Clone)]
pub struct ReceiverCommitmentKOutOfN {
    pub version: u8,
    pub choices: Vec<ReceiverChoiceCommitment>,
}

/// Authenticated encryption of a message for one receiver choice.
#[derive(Default, Debug, Clone)]
pub struct OtCiphertextChoice {
    pub key_basepoint: RistrettoPoint,
    pub iv: Vec<u8>,
    pub encrypted_message: Vec<u8>,
}

/// One database row. Contains no public hash or verifier of its plaintext.
#[derive(Default, Debug, Clone)]
pub struct OtCiphertextItemKOutOfN {
    pub version: u8,
    pub encrypted_choices: Vec<OtCiphertextChoice>,
}

/// k-out-of-n KV OT for unique sender IDs.
#[derive(Default, Debug, Clone)]
pub struct OtKvKOutOfN {}

fn nonzero_scalar() -> Scalar {
    loop {
        let scalar = get_random_scalar();
        if scalar != Scalar::zero() {
            return scalar;
        }
    }
}

// Hash the secret DH point with a fixed-length public transcript.
// Indices prevent reordering, copying rows and swapping choice slots.
fn message_key(
    shared: &RistrettoPoint,
    choice: &ReceiverChoiceCommitment,
    key_basepoint: &RistrettoPoint,
    item_index: usize,
    choice_index: usize,
) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::new());
    input.extend_from_slice(b"WeDPR/KV-OT/v2/message-key");
    input.extend_from_slice(&(item_index as u64).to_be_bytes());
    input.extend_from_slice(&(choice_index as u64).to_be_bytes());
    for point in &[
        choice.point_x,
        choice.point_y,
        choice.point_z,
        *key_basepoint,
        *shared,
    ] {
        input.extend_from_slice(&point_to_bytes(point));
    }
    Zeroizing::new(WedprSha3_256::default().hash(&input[..]))
}

impl OtKvKOutOfN {
    /// Generate independent a and b for EVERY choice. Reusing a*b exposed
    /// H(id_j)-H(id_i) through public point differences.
    pub fn receiver_init(
        &self,
        choice_list: &Vec<Vec<u8>>,
    ) -> (ReceiverSecretKOutOfN, ReceiverCommitmentKOutOfN) {
        let mut blindings = Vec::with_capacity(choice_list.len());
        let mut choices = Vec::with_capacity(choice_list.len());
        for id in choice_list {
            let blinding_a = nonzero_scalar();
            let blinding_b = nonzero_scalar();
            let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);
            blindings.push(blinding_b);
            choices.push(ReceiverChoiceCommitment {
                point_x: *BASEPOINT_G1 * blinding_a,
                point_y: *BASEPOINT_G1 * blinding_b,
                point_z: *BASEPOINT_G1 * (blinding_a * blinding_b - id_scalar),
            });
        }
        let commitment = ReceiverCommitmentKOutOfN {
            version: OT_KV_VERSION,
            choices,
        };
        (
            ReceiverSecretKOutOfN {
                blinding_b: blindings,
                commitment: commitment.clone(),
            },
            commitment,
        )
    }

    /// Encrypt each row independently for each query choice. Reject malformed
    /// queries before accessing rows or producing any outputs.
    pub fn sender_init(
        &self,
        id_list: &Vec<Vec<u8>>,
        message_list: &Vec<Vec<u8>>,
        receiver_commitment: &ReceiverCommitmentKOutOfN,
    ) -> Result<Vec<OtCiphertextItemKOutOfN>, WedprError> {
        let choices = &receiver_commitment.choices;
        let identity = RistrettoPoint::default();
        if receiver_commitment.version != OT_KV_VERSION
            || id_list.is_empty()
            || id_list.len() != message_list.len()
            || choices.is_empty()
            || choices.len() > id_list.len()
            || id_list.iter().collect::<HashSet<_>>().len() != id_list.len()
            || choices.iter().any(|c| {
                c.point_x == identity
                    || c.point_y == identity
                    || c.point_z == identity
            })
        {
            return Err(WedprError::ArgumentError);
        }
        let aes = WedprBlockCipherAes256::default();
        let mut result = Vec::with_capacity(id_list.len());
        for (item_index, (id, message)) in
            id_list.iter().zip(message_list).enumerate()
        {
            let id_scalar = Scalar::hash_from_bytes::<Sha3_512>(id);
            let mut encrypted_choices = Vec::with_capacity(choices.len());
            for (choice_index, choice) in choices.iter().enumerate() {
                let (key_basepoint, shared) = loop {
                    let r = nonzero_scalar();
                    let s = nonzero_scalar();
                    let key_basepoint = choice.point_x * s + *BASEPOINT_G1 * r;
                    let shared = (choice.point_z + *BASEPOINT_G1 * id_scalar)
                        * s
                        + choice.point_y * r;
                    if key_basepoint != identity && shared != identity {
                        break (key_basepoint, shared);
                    }
                };
                let key = message_key(
                    &shared,
                    choice,
                    &key_basepoint,
                    item_index,
                    choice_index,
                );
                let iv = aes.generate_iv();
                let encrypted_message =
                    aes.encrypt(message.as_slice(), &key[..], iv.as_slice())?;
                encrypted_choices.push(OtCiphertextChoice {
                    key_basepoint,
                    iv,
                    encrypted_message,
                });
            }
            result.push(OtCiphertextItemKOutOfN {
                version: OT_KV_VERSION,
                encrypted_choices,
            });
        }
        Ok(result)
    }

    /// Recover ALL choices in database order. Only a valid keyed tag identifies
    /// a chosen message. Keep failures local to avoid selective-failure signals.
    pub fn receiver_decrypt(
        &self,
        receiver_secret: &ReceiverSecretKOutOfN,
        sender_ciphertexts: &Vec<OtCiphertextItemKOutOfN>,
        choice_count: usize,
    ) -> Result<Vec<Vec<u8>>, WedprError> {
        let choices = &receiver_secret.commitment.choices;
        if receiver_secret.commitment.version != OT_KV_VERSION
            || choice_count == 0
            || choice_count != choices.len()
            || choice_count != receiver_secret.blinding_b.len()
            || sender_ciphertexts.len() < choice_count
            || sender_ciphertexts.iter().any(|item| {
                item.version != OT_KV_VERSION
                    || item.encrypted_choices.len() != choice_count
                    || item.encrypted_choices.iter().any(|entry| {
                        entry.key_basepoint == RistrettoPoint::default()
                            || entry.iv.len() != 16
                    })
            })
        {
            return Err(WedprError::ArgumentError);
        }
        let aes = WedprBlockCipherAes256::default();
        let mut result = Vec::new();
        let mut recovered = vec![false; choice_count];
        for (item_index, item) in sender_ciphertexts.iter().enumerate() {
            let mut plaintext = None;
            for (choice_index, entry) in
                item.encrypted_choices.iter().enumerate()
            {
                let shared = entry.key_basepoint
                    * receiver_secret.blinding_b[choice_index];
                let key = message_key(
                    &shared,
                    &choices[choice_index],
                    &entry.key_basepoint,
                    item_index,
                    choice_index,
                );
                if let Ok(message) = aes.decrypt(
                    entry.encrypted_message.as_slice(),
                    &key[..],
                    entry.iv.as_slice(),
                ) {
                    if recovered[choice_index] {
                        return Err(WedprError::FormatError);
                    }
                    recovered[choice_index] = true;
                    plaintext = Some(message);
                }
            }
            if let Some(message) = plaintext {
                result.push(message);
            }
        }
        if result.len() != choice_count || recovered.iter().any(|done| !done) {
            return Err(WedprError::FormatError);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
