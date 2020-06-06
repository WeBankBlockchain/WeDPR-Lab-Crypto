extern crate base64;
use common::error::WedprError;
use curve25519_dalek::{
    ristretto,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

use common::constant::RISTRETTO_POINT_SIZE_IN_BYTES;
use common::utils;
use std::convert::TryInto;

/// Converts RistrettoPoint into String.
pub fn point_to_string(point: &RistrettoPoint) -> String {
    utils::bytes_to_string(&point.compress().to_bytes())
}

/// Converts CompressedRistretto into String.
pub fn compressed_to_string(point: &CompressedRistretto) -> String {
    utils::bytes_to_string(&point.to_bytes())
}

/// Converts Scalar into String.
pub fn scalar_to_string(number: &Scalar) -> String {
    utils::bytes_to_string(&number.to_bytes())
}

/// Converts String into Scalar.
pub fn string_to_scalar(num: &str) -> Result<Scalar, WedprError> {
    let num_u8 = match utils::string_to_bytes(num) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("string_to_scalar failed, string: {}", num,);
            return Err(WedprError::FormatError);
        }
    };
    let get_num_u8 = to_fix_array32(&num_u8)?;
    let scalar_num = Scalar::from_bits(*get_num_u8);
    Ok(scalar_num)
}

fn to_fix_array32(barry: &[u8]) -> Result<&[u8; 32], WedprError> {
    let pop_u8 = match barry.try_into() {
        Ok(v) => v,
        Err(_) => return Err(WedprError::FormatError),
    };
    Ok(pop_u8)
}

/// Converts String into RistrettoPoint.
pub fn string_to_point(point: &str) -> Result<ristretto::RistrettoPoint, WedprError> {
    let decode_tmp = utils::string_to_bytes(point)?;
    if decode_tmp.len() != RISTRETTO_POINT_SIZE_IN_BYTES {
        wedpr_println!("string_to_point decode failed!");
        return Err(WedprError::FormatError);
    }
    let point_value = match ristretto::CompressedRistretto::from_slice(&decode_tmp).decompress() {
        Some(v) => v,
        None => {
            wedpr_println!("string_to_point decompress CompressedRistretto failed");
            return Err(WedprError::FormatError);
        }
    };

    Ok(point_value)
}
