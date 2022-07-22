// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Common utility functions for ZKP.
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

#[macro_use]
extern crate wedpr_l_macros;
#[macro_use]
extern crate lazy_static;

mod config;
use config::HASH;
use rand::Rng;
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
const SCALAR_SIZE_IN_BYTE: usize = 32;

/// A trait for serializing a value as raw data for insertion into PSBT
/// key-value pairs.
pub trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSBT key-value pairs.
pub trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError>;
}

// ZKP data to verify the balance relationship among value commitments.
// For example, given C(x), C(y), C(z), this proof data can be used to
// verify whether x * y =? z.
#[derive(Default, Debug, Clone)]
pub struct BalanceProof {
    pub check1: Scalar,
    pub check2: Scalar,
    pub m1: Scalar,
    pub m2: Scalar,
    pub m3: Scalar,
    pub m4: Scalar,
    pub m5: Scalar,
    pub m6: Scalar,
}

impl Serialize for BalanceProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 * SCALAR_SIZE_IN_BYTE);
        buf.extend(&(scalar_to_bytes(&self.check1)));
        buf.extend(&(scalar_to_bytes(&self.check2)));
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(scalar_to_bytes(&self.m2)));
        buf.extend(&(scalar_to_bytes(&self.m3)));
        buf.extend(&(scalar_to_bytes(&self.m4)));
        buf.extend(&(scalar_to_bytes(&self.m5)));
        buf.extend(&(scalar_to_bytes(&self.m6)));
        buf
    }
}

impl Deserialize for BalanceProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 8 * SCALAR_SIZE_IN_BYTE {
            return Err(WedprError::ArgumentError);
        }
        // decode check1
        let mut offset = 0;
        let check1 =
            bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode check2
        offset += SCALAR_SIZE_IN_BYTE;
        let check2 =
            bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m1
        offset += SCALAR_SIZE_IN_BYTE;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m2
        offset += SCALAR_SIZE_IN_BYTE;
        let m2 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m3
        offset += SCALAR_SIZE_IN_BYTE;
        let m3 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m4
        offset += SCALAR_SIZE_IN_BYTE;
        let m4 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m5
        offset += SCALAR_SIZE_IN_BYTE;
        let m5 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m6
        offset += SCALAR_SIZE_IN_BYTE;
        let m6 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        Ok(BalanceProof {
            check1: check1,
            check2: check2,
            m1: m1,
            m2: m2,
            m3: m3,
            m4: m4,
            m5: m5,
            m6: m6,
        })
    }
}
#[derive(Default, Debug, Clone)]
pub struct KnowledgeProof {
    pub t1: RistrettoPoint,
    pub m1: Scalar,
    pub m2: Scalar,
}

impl Serialize for KnowledgeProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            2 * SCALAR_SIZE_IN_BYTE + RISTRETTO_POINT_SIZE_IN_BYTES,
        );
        buf.extend(&(point_to_bytes(&self.t1)));
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(scalar_to_bytes(&self.m2)));
        buf
    }
}

impl Deserialize for KnowledgeProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < 2 * SCALAR_SIZE_IN_BYTE + RISTRETTO_POINT_SIZE_IN_BYTES
        {
            return Err(WedprError::ArgumentError);
        }
        // decode t1
        let mut offset = 0;
        let t1 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode m1
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m2
        offset += SCALAR_SIZE_IN_BYTE;
        let m2 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        Ok(KnowledgeProof {
            t1: t1,
            m1: m1,
            m2: m2,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct FormatProof {
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
    pub m1: Scalar,
    pub m2: Scalar,
}

impl Serialize for FormatProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            2 * SCALAR_SIZE_IN_BYTE + 2 * RISTRETTO_POINT_SIZE_IN_BYTES,
        );
        buf.extend(&(point_to_bytes(&self.t1)));
        buf.extend(&(point_to_bytes(&self.t2)));
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(scalar_to_bytes(&self.m2)));
        buf
    }
}

impl Deserialize for FormatProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len()
            < 2 * SCALAR_SIZE_IN_BYTE + 2 * RISTRETTO_POINT_SIZE_IN_BYTES
        {
            return Err(WedprError::ArgumentError);
        }
        // decode t1
        let mut offset = 0;
        let t1 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode t2
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let t2 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode m1
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m2
        offset += SCALAR_SIZE_IN_BYTE;
        let m2 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        Ok(FormatProof {
            t1: t1,
            t2: t2,
            m1: m1,
            m2: m2,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct ArithmeticProof {
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
    pub t3: RistrettoPoint,
    pub m1: Scalar,
    pub m2: Scalar,
    pub m3: Scalar,
    pub m4: Scalar,
    pub m5: Scalar,
}

impl Serialize for ArithmeticProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            5 * SCALAR_SIZE_IN_BYTE + 3 * RISTRETTO_POINT_SIZE_IN_BYTES,
        );
        buf.extend(&(point_to_bytes(&self.t1)));
        buf.extend(&(point_to_bytes(&self.t2)));
        buf.extend(&(point_to_bytes(&self.t3)));
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(scalar_to_bytes(&self.m2)));
        buf.extend(&(scalar_to_bytes(&self.m3)));
        buf.extend(&(scalar_to_bytes(&self.m4)));
        buf.extend(&(scalar_to_bytes(&self.m5)));
        buf
    }
}

impl Deserialize for ArithmeticProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len()
            < 5 * SCALAR_SIZE_IN_BYTE + 3 * RISTRETTO_POINT_SIZE_IN_BYTES
        {
            return Err(WedprError::ArgumentError);
        }
        // decode t1
        let mut offset = 0;
        let t1 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode t2
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let t2 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode t3
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let t3 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode m1
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m2
        offset += SCALAR_SIZE_IN_BYTE;
        let m2 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m3
        offset += SCALAR_SIZE_IN_BYTE;
        let m3 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m4
        offset += SCALAR_SIZE_IN_BYTE;
        let m4 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode m5
        offset += SCALAR_SIZE_IN_BYTE;
        let m5 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        Ok(ArithmeticProof {
            t1: t1,
            t2: t2,
            t3: t3,
            m1: m1,
            m2: m2,
            m3: m3,
            m4: m4,
            m5: m5,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct EqualityProof {
    pub m1: Scalar,
    pub t1: RistrettoPoint,
    pub t2: RistrettoPoint,
}

impl Serialize for EqualityProof {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            SCALAR_SIZE_IN_BYTE + 2 * RISTRETTO_POINT_SIZE_IN_BYTES,
        );
        buf.extend(&(scalar_to_bytes(&self.m1)));
        buf.extend(&(point_to_bytes(&self.t1)));
        buf.extend(&(point_to_bytes(&self.t2)));
        buf
    }
}

impl Deserialize for EqualityProof {
    fn deserialize(bytes: &[u8]) -> Result<Self, WedprError> {
        if bytes.len() < SCALAR_SIZE_IN_BYTE + 2 * RISTRETTO_POINT_SIZE_IN_BYTES
        {
            return Err(WedprError::ArgumentError);
        }
        // decode m1
        let mut offset = 0;
        let m1 = bytes_to_scalar(&bytes[offset..offset + SCALAR_SIZE_IN_BYTE])?;
        // decode t1
        offset += SCALAR_SIZE_IN_BYTE;
        let t1 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        // decode t2
        offset += RISTRETTO_POINT_SIZE_IN_BYTES;
        let t2 = bytes_to_point(
            &bytes[offset..offset + RISTRETTO_POINT_SIZE_IN_BYTES],
        )?;
        Ok(EqualityProof {
            m1: m1,
            t1: t1,
            t2: t2,
        })
    }
}

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
        wedpr_println!("bytes_to_point decode failed");
        return Err(WedprError::FormatError);
    }
    let point_value = match CompressedRistretto::from_slice(&point).decompress()
    {
        Some(v) => v,
        None => {
            wedpr_println!(
                "bytes_to_point decompress CompressedRistretto failed"
            );
            return Err(WedprError::FormatError);
        },
    };
    Ok(point_value)
}

/// Gets a random u32 integer.
pub fn get_random_u32() -> u32 {
    let mut rng = rand::thread_rng();
    let blinding: u32 = rng.gen();
    blinding
}
