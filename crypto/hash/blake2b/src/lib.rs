// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Blake2b hash functions.

extern crate blake2;
use blake2::{Blake2b, Digest};

use wedpr_l_utils::traits::Hash;

/// Implements Blake2b as a Hash instance.
#[derive(Default, Debug, Clone)]
pub struct WedprBlake2b {}

impl Hash for WedprBlake2b {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8> {
        let mut hash_algorithm = Blake2b::new();
        hash_algorithm.update(input);
        hash_algorithm.finalize()[..].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::BASE64_ENCODED_TEST_MESSAGE;

    #[test]
    fn test_blake2b() {
        let blake2b = WedprBlake2b::default();
        let expected_hash: [u8; 64] = [
            160, 107, 156, 125, 120, 142, 80, 102, 194, 240, 157, 64, 13, 186,
            17, 255, 165, 14, 143, 39, 139, 129, 93, 173, 174, 142, 172, 217,
            177, 87, 186, 51, 83, 161, 206, 220, 55, 106, 20, 128, 40, 161,
            235, 97, 122, 72, 121, 208, 72, 37, 10, 29, 157, 243, 21, 157, 209,
            165, 219, 38, 35, 232, 62, 138,
        ];
        assert_eq!(
            expected_hash.to_vec(),
            blake2b.hash(&BASE64_ENCODED_TEST_MESSAGE)
        );
    }
}
