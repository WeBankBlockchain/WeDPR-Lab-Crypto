// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! SHA3 hash functions.

extern crate sha3;
use sha3::{Digest, Sha3_256};

use wedpr_l_utils::traits::Hash;

/// Implements SHA3-256 as a Hash instance.
#[derive(Default, Debug, Clone)]
pub struct WedprSha3_256 {}

impl Hash for WedprSha3_256 {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8> {
        let mut hash_algorithm = Sha3_256::default();
        hash_algorithm.input(input);
        hash_algorithm.result().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::BASE64_ENCODED_TEST_MESSAGE;

    #[test]
    fn test_sha3_256() {
        let sha3_256 = WedprSha3_256::default();
        let expected_hash: [u8; 32] = [
            206, 42, 82, 168, 33, 46, 229, 150, 191, 246, 177, 4, 24, 68, 214,
            203, 247, 40, 59, 187, 6, 246, 187, 15, 39, 30, 37, 169, 51, 11,
            52, 237,
        ];
        assert_eq!(
            expected_hash.to_vec(),
            sha3_256.hash(&BASE64_ENCODED_TEST_MESSAGE)
        );
    }
}
