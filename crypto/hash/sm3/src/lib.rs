// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! SM3 hash functions.

use wedpr_l_libsm::sm3::hash::Sm3Hash;
use wedpr_l_utils::traits::Hash;

/// Implements SM3 as a Hash instance.
#[derive(Default, Debug, Clone)]
pub struct WedprSm3 {}

impl Hash for WedprSm3 {
    fn hash<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> Vec<u8> {
        let mut hash_algorithm = Sm3Hash::new(input.as_ref());
        hash_algorithm.get_hash().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wedpr_l_utils::constant::tests::BASE64_ENCODED_TEST_MESSAGE;

    #[test]
    fn test_wedprsm3() {
        let sm3 = WedprSm3::default();
        let expected_hash: [u8; 32] = [
            237, 123, 250, 185, 152, 248, 114, 241, 56, 164, 167, 206, 22, 156,
            221, 254, 127, 211, 53, 208, 243, 175, 16, 130, 70, 226, 6, 135,
            92, 47, 202, 238,
        ];
        assert_eq!(
            expected_hash.to_vec(),
            sm3.hash(&BASE64_ENCODED_TEST_MESSAGE)
        );
    }
}
