// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Keccak256 hash functions.

extern crate sha3;
use sha3::{Digest, Keccak256};

use wedpr_l_utils::traits::Hash;

/// Implements Keccak256 as a Hash instance.
#[derive(Default, Debug, Clone)]
pub struct WedprKeccak256 {}

impl Hash for WedprKeccak256 {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8> {
        let mut hash_algorithm = Keccak256::default();
        hash_algorithm.input(input);
        hash_algorithm.result().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::BASE64_ENCODED_TEST_MESSAGE;

    #[test]
    fn test_keccak256() {
        let keccak256 = WedprKeccak256::default();
        let expected_hash: [u8; 32] = [
            229, 45, 56, 86, 254, 135, 4, 37, 134, 235, 19, 64, 70, 172, 15,
            111, 111, 120, 31, 63, 247, 6, 86, 133, 87, 2, 175, 0, 144, 114,
            119, 212,
        ];
        assert_eq!(
            expected_hash.to_vec(),
            keccak256.hash(&BASE64_ENCODED_TEST_MESSAGE)
        );
    }
}
