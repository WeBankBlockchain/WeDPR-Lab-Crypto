// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! FISCO BCOS Java Sdk specific functions.

use curve25519_dalek::{
    ristretto, ristretto::RistrettoPoint, scalar::Scalar, traits::IsIdentity,
};
use wedpr_l_crypto_zkp_utils;
use wedpr_l_utils::error::WedprError;

/// Converts RistrettoPoint into String.
pub fn point_to_string(point: &RistrettoPoint) -> String {
    crate::bytes_to_string(&wedpr_l_crypto_zkp_utils::point_to_bytes(&point))
}

/// Converts Scalar into String.
pub fn scalar_to_string(number: &Scalar) -> String {
    crate::bytes_to_string(&wedpr_l_crypto_zkp_utils::scalar_to_bytes(&number))
}

/// Converts String into Scalar.
pub fn string_to_scalar(num: &str) -> Result<Scalar, WedprError> {
    check_canonical_hex(num)?;
    let scalar_bytes = crate::string_to_bytes(num)?;
    wedpr_l_crypto_zkp_utils::bytes_to_scalar(&scalar_bytes)
}

/// Converts String into RistrettoPoint.
pub fn string_to_point(
    point: &str,
) -> Result<ristretto::RistrettoPoint, WedprError> {
    check_canonical_hex(point)?;
    let point_bytes = crate::string_to_bytes(point)?;
    let point = wedpr_l_crypto_zkp_utils::bytes_to_point(&point_bytes)?;
    if point.is_identity() {
        return Err(WedprError::FormatError);
    }
    Ok(point)
}

fn check_canonical_hex(value: &str) -> Result<(), WedprError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(WedprError::FormatError);
    }
    Ok(())
}
