// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Ripemd160 hash functions.

extern crate ripemd160;
use ripemd160::{Digest, Ripemd160};

use wedpr_l_utils::traits::Hash;

/// Implements Ripemd160 as a Hash instance.
#[derive(Default, Debug, Clone)]
pub struct WedprRipemd160 {}

impl Hash for WedprRipemd160 {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8> {
        let mut hash_algorithm = Ripemd160::new();
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
        let blake2 = WedprRipemd160::default();
        let expected_hash: [u8; 20] = [
            43, 86, 224, 109, 4, 234, 34, 233, 103, 85, 46, 191, 164, 66, 70,
            109, 107, 195, 199, 241,
        ];
        assert_eq!(
            expected_hash.to_vec(),
            blake2.hash(&BASE64_ENCODED_TEST_MESSAGE)
        );
    }
}
