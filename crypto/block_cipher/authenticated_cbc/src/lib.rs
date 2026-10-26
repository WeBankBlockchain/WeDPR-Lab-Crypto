// Copyright 2026 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Versioned CBC encrypt-then-MAC. Legacy unauthenticated CBC is rejected.
//! Callers must generate a fresh, unpredictable 16-byte IV for every message.

use block_modes::{
    block_padding::Pkcs7,
    cipher::{
        generic_array::typenum::{Unsigned, U16},
        BlockCipher, NewBlockCipher,
    },
    BlockMode, Cbc,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use wedpr_l_utils::error::WedprError;
use zeroize::Zeroizing;

const HEADER: &[u8; 8] = b"WDPRETM\x01";
const BLOCK_SIZE: usize = 16;
const TAG_SIZE: usize = 32;
/// Extra bytes outside the padded CBC ciphertext.
pub const ENVELOPE_OVERHEAD: usize = HEADER.len() + TAG_SIZE;

/// Exact encoded length, or None if the calculation would overflow.
pub fn ciphertext_len(plaintext_len: usize) -> Option<usize> {
    (plaintext_len / BLOCK_SIZE)
        .checked_add(1)?
        .checked_mul(BLOCK_SIZE)?
        .checked_add(ENVELOPE_OVERHEAD)
}

fn derive_keys<C: NewBlockCipher>(
    key: &[u8],
    suite: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<[u8; 32]>), WedprError> {
    if key.len() != C::KeySize::to_usize() {
        return Err(WedprError::FormatError);
    }
    // Domain-separated extract and separate expand labels for the two keys.
    let kdf = Hkdf::<Sha256>::new(Some(suite), key);
    let mut encryption_key = Zeroizing::new(vec![0u8; key.len()]);
    let mut authentication_key = Zeroizing::new([0u8; 32]);
    kdf.expand(b"WeDPR/CBC-ETM/v1/encryption", &mut encryption_key[..])
        .map_err(|_| WedprError::FormatError)?;
    kdf.expand(
        b"WeDPR/CBC-ETM/v1/authentication",
        &mut authentication_key[..],
    )
    .map_err(|_| WedprError::FormatError)?;
    Ok((encryption_key, authentication_key))
}

/// Encrypt using independently derived encryption and authentication keys.
/// The MAC binds the version header, algorithm suite, IV and ciphertext.
pub fn encrypt<C>(
    message: &[u8],
    key: &[u8],
    iv: &[u8],
    suite: &[u8],
) -> Result<Vec<u8>, WedprError>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
{
    if iv.len() != BLOCK_SIZE {
        return Err(WedprError::FormatError);
    }
    let length =
        ciphertext_len(message.len()).ok_or(WedprError::FormatError)?;
    let (encryption_key, authentication_key) = derive_keys::<C>(key, suite)?;
    let cipher = Cbc::<C, Pkcs7>::new_var(&encryption_key, iv)
        .map_err(|_| WedprError::FormatError)?;
    let mut envelope = Vec::with_capacity(length);
    envelope.extend_from_slice(HEADER);
    envelope.extend_from_slice(&cipher.encrypt_vec(message));
    let mut mac = Hmac::<Sha256>::new_from_slice(&authentication_key[..])
        .map_err(|_| WedprError::FormatError)?;
    mac.update(suite);
    mac.update(iv);
    mac.update(&envelope);
    envelope.extend_from_slice(&mac.finalize().into_bytes());
    Ok(envelope)
}

/// Authenticate in constant time before CBC decryption or padding checks.
/// Every invalid ciphertext returns the same error and releases no plaintext.
pub fn decrypt<C>(
    envelope: &[u8],
    key: &[u8],
    iv: &[u8],
    suite: &[u8],
) -> Result<Vec<u8>, WedprError>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
{
    if iv.len() != BLOCK_SIZE
        || envelope.len() < ENVELOPE_OVERHEAD + BLOCK_SIZE
        || !envelope.starts_with(HEADER)
        || (envelope.len() - ENVELOPE_OVERHEAD) % BLOCK_SIZE != 0
    {
        return Err(WedprError::FormatError);
    }
    let (encryption_key, authentication_key) = derive_keys::<C>(key, suite)?;
    let tag_offset = envelope.len() - TAG_SIZE;
    let mut mac = Hmac::<Sha256>::new_from_slice(&authentication_key[..])
        .map_err(|_| WedprError::FormatError)?;
    mac.update(suite);
    mac.update(iv);
    mac.update(&envelope[..tag_offset]);
    mac.verify_slice(&envelope[tag_offset..])
        .map_err(|_| WedprError::FormatError)?;
    let cipher = Cbc::<C, Pkcs7>::new_var(&encryption_key, iv)
        .map_err(|_| WedprError::FormatError)?;
    cipher
        .decrypt_vec(&envelope[HEADER.len()..tag_offset])
        .map_err(|_| WedprError::FormatError)
}
