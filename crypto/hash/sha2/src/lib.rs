// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! SHA2 hash functions.

extern crate sha2;
use sha2::{Digest, Sha256};

use wedpr_l_utils::traits::Hash;

/// Implements SHA2-256 as a Hash instance.
#[derive(Default, Debug, Clone)]
pub struct WedprSha2_256 {}

impl Hash for WedprSha2_256 {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8> {
        let mut hash_algorithm = Sha256::new();
        hash_algorithm.update(input);
        hash_algorithm.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::BASE64_ENCODED_TEST_MESSAGE;

    #[test]
    fn test_sha2_256() {
        let sha2_256 = WedprSha2_256::default();
        let expected_hash: [u8; 32] = [
            190, 30, 62, 115, 252, 157, 117, 20, 37, 18, 117, 164, 4, 229, 228,
            35, 172, 107, 184, 122, 128, 7, 18, 122, 171, 219, 246, 115, 98,
            184, 133, 168,
        ];
        assert_eq!(
            expected_hash.to_vec(),
            sha2_256.hash(&BASE64_ENCODED_TEST_MESSAGE)
        );
    }
}
