// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Common utility functions for ZKP.

use curve25519_dalek::constants::{
    RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT,
};

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

#[macro_use]
extern crate wedpr_l_macros;
#[macro_use]
extern crate lazy_static;

mod config;
use config::HASH;
use sha3::Sha3_512;
use std::convert::TryInto;
use wedpr_l_utils::{error::WedprError, traits::Hash};

lazy_static! {
    /// A base point used by various crypto algorithms.
    pub static ref BASEPOINT_G1: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    /// Another base point used by various crypto algorithms.
    pub static ref BASEPOINT_G2: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(
            RISTRETTO_BASEPOINT_COMPRESSED.as_bytes()
        );
}

/// Serialized data size of a point.
const RISTRETTO_POINT_SIZE_IN_BYTES: usize = 32;

/// Gets a random Scalar.
pub fn get_random_scalar() -> Scalar {
    Scalar::random(&mut rand::thread_rng())
}

/// Converts an arbitrary string to Scalar.
/// It will hash it first, and transform the numeric value of hash output to
/// Scalar.
pub fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Scalar {
    let mut array = [0; 32];
    array.clone_from_slice(&HASH.hash(input));
    Scalar::from_bytes_mod_order(array)
}

/// Converts Scalar to a vector.
pub fn scalar_to_bytes(input: &Scalar) -> Vec<u8> {
    input.as_bytes().to_vec()
}

/// Converts Scalar to a slice.
pub fn scalar_to_slice(input: &Scalar) -> [u8; 32] {
    input.as_bytes().clone()
}

/// Extracts a slice of &[u8; 32] from the given slice.
fn to_bytes32_slice(barry: &[u8]) -> Result<&[u8; 32], WedprError> {
    let pop_u8 = match barry.try_into() {
        Ok(v) => v,
        Err(_) => return Err(WedprError::FormatError),
    };
    Ok(pop_u8)
}

// Private utility functions.

/// Converts a vector to Scalar.
pub fn bytes_to_scalar(input: &[u8]) -> Result<Scalar, WedprError> {
    let get_num_u8 = to_bytes32_slice(&input)?;
    let scalar_num = Scalar::from_bits(*get_num_u8);
    Ok(scalar_num)
}

/// Converts RistrettoPoint to a bytes vector.
pub fn point_to_bytes(point: &RistrettoPoint) -> Vec<u8> {
    point.compress().to_bytes().to_vec()
}

/// Converts RistrettoPoint to a bytes slice.
pub fn point_to_slice(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

/// Converts a vector to RistrettoPoint.
pub fn bytes_to_point(point: &[u8]) -> Result<RistrettoPoint, WedprError> {
    if point.len() != RISTRETTO_POINT_SIZE_IN_BYTES {
        wedpr_println!("string_to_point decode failed");
        return Err(WedprError::FormatError);
    }
    let point_value = match CompressedRistretto::from_slice(&point).decompress()
    {
        Some(v) => v,
        None => {
            wedpr_println!(
                "string_to_point decompress CompressedRistretto failed"
            );
            return Err(WedprError::FormatError);
        },
    };
    Ok(point_value)
}
