// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Shared config for wedpr_ffi_c_crypto.

// Secp256k1 section.

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
use wedpr_l_crypto_ecies_secp256k1::WedprSecp256k1Ecies;

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
lazy_static! {
    pub static ref ECIES_SECP256K1: WedprSecp256k1Ecies =
        WedprSecp256k1Ecies::default();
}

#[cfg(feature = "wedpr_f_signature_secp256k1")]
use wedpr_l_crypto_signature_secp256k1::WedprSecp256k1Recover;

#[cfg(feature = "wedpr_f_signature_secp256k1")]
lazy_static! {
    pub static ref SIGNATURE_SECP256K1: WedprSecp256k1Recover =
        WedprSecp256k1Recover::default();
}

#[cfg(feature = "wedpr_f_hash_keccak256")]
use wedpr_l_crypto_hash_keccak256::WedprKeccak256;

#[cfg(feature = "wedpr_f_hash_keccak256")]
lazy_static! {
    pub static ref HASH_KECCAK256: WedprKeccak256 = WedprKeccak256::default();
}

// SM section.

#[cfg(feature = "wedpr_f_signature_sm2")]
use wedpr_l_crypto_signature_sm2::WedprSm2p256v1;

#[cfg(feature = "wedpr_f_signature_sm2")]
lazy_static! {
    pub static ref SIGNATURE_SM2: WedprSm2p256v1 = WedprSm2p256v1::default();
}

#[cfg(feature = "wedpr_f_hash_sm3")]
use wedpr_l_crypto_hash_sm3::WedprSm3;

#[cfg(feature = "wedpr_f_hash_sm3")]
lazy_static! {
    pub static ref HASH_SM3: WedprSm3 = WedprSm3::default();
}
