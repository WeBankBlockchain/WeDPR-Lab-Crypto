// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Shared config for ZKP.

use wedpr_l_crypto_hash_keccak256::WedprKeccak256;

lazy_static! {
    /// Shared hash algorithm reference for quick implementation replacement.
    /// Other code should use this reference, and not directly use a specific implementation.
    pub static ref HASH: WedprKeccak256 = WedprKeccak256::default();
}
