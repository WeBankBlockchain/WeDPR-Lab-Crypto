use common::error::WedprError;
use common::utils;
use libsm::sm3::hash::Sm3Hash;
use sha3::{Digest, Keccak256};

pub fn keccak256(msg: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::default();
    hasher.input(msg);
    hasher.result().to_vec()
}

pub fn sm3(msg: &[u8]) -> Vec<u8> {
    let mut hash = Sm3Hash::new(msg);
    hash.get_hash().to_vec()
}

pub fn keccak256_hex(msg: &str) -> Result<String, WedprError> {
    let message = utils::string_to_bytes(msg)?;
    let hash = keccak256(&message);
    Ok(utils::bytes_to_string(&hash))
}

pub fn sm3_hex(msg: &str) -> Result<String, WedprError> {
    let message = utils::string_to_bytes(msg)?;
    let hash = sm3(&message);
    Ok(utils::bytes_to_string(&hash))
}
