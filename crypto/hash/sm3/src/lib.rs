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
