// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! WeDPR traits definitions for replaceable algorithms.

use crate::error::WedprError;

/// Trait of a replaceable hash algorithm.
pub trait Hash {
    /// Generates a fixed length hash bytes vector from a bytes array of any
    /// length.
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8>;
}

/// Trait of a replaceable coder algorithm.
pub trait Coder {
    /// Converts bytes to an encoded string.
    fn encode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> String;
    /// Decodes an encoded string to a bytes vector.
    fn decode(&self, input: &str) -> Result<Vec<u8>, WedprError>;
}

/// Trait of a replaceable elliptic curve integrated encryption scheme (ECIES)
/// algorithm.
pub trait Ecies {
    /// Encrypts a message by ECIES with a public key.
    fn encrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
    ) -> Result<Vec<u8>, WedprError>;

    /// Decrypts a ciphertext by ECIES with a private key.
    fn decrypt<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        ciphertext: &T,
    ) -> Result<Vec<u8>, WedprError>;
}

/// Trait of a replaceable signature algorithm.
pub trait Signature {
    /// Signs a message hash with the private key.
    fn sign<T: ?Sized + AsRef<[u8]>>(
        &self,
        private_key: &T,
        msg_hash: &T,
    ) -> Result<Vec<u8>, WedprError>;

    /// Verifies a message hash with the public key.
    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        msg_hash: &T,
        signature: &T,
    ) -> bool;

    /// Generates a new key pair for signature algorithm,
    /// where the first part is public key,
    /// the second part is private key.
    // TODO: Replace output list with a struct or protobuf.
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
}

/// Trait of a replaceable verifiable random function (VRF) algorithm, which is
/// the public-key version of a keyed cryptographic hash.
pub trait Vrf {
    /// Encodes a VRF proof to bytes.
    fn encode_proof(&self) -> Vec<u8>;

    /// Decode a VRF proof from bytes.
    fn decode_proof<T: ?Sized + AsRef<[u8]>>(
        proof: &T,
    ) -> Result<Self, WedprError>
    where Self: Sized;

    /// Proves a keyed VRF hash with a message and a private key.
    fn prove<T: ?Sized + AsRef<[u8]>>(
        private_key: &T,
        message: &T,
    ) -> Result<Self, WedprError>
    where
        Self: Sized;

    /// Proves a keyed VRF hash with a message faster with both the private and
    /// public keys.
    fn prove_fast<T: ?Sized + AsRef<[u8]>>(
        private_key: &T,
        public_key: &T,
        message: &T,
    ) -> Result<Self, WedprError>
    where
        Self: Sized;

    /// Verifies a keyed VRF hash with a message and its public key.
    fn verify<T: ?Sized + AsRef<[u8]>>(
        &self,
        public_key: &T,
        message: &T,
    ) -> bool;

    /// Derives a VRF public key from a private key.
    fn derive_public_key<T: ?Sized + AsRef<[u8]>>(private_key: &T) -> Vec<u8>;

    /// Hashes a VRF proof to bytes.
    fn proof_to_hash(&self) -> Result<Vec<u8>, WedprError>;

    /// Checks the validity of a VRF public key.
    fn is_valid_public_key<T: ?Sized + AsRef<[u8]>>(public_key: &T) -> bool;
}
