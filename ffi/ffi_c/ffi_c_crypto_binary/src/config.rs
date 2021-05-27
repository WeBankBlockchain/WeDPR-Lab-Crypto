// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Shared config for wedpr_ffi_c_crypto.

#![cfg(not(tarpaulin_include))]

// ECIES section.

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
use wedpr_l_crypto_ecies_secp256k1::WedprSecp256k1Ecies;

#[cfg(feature = "wedpr_f_ecies_secp256k1")]
lazy_static! {
    pub static ref ECIES_SECP256K1: WedprSecp256k1Ecies =
        WedprSecp256k1Ecies::default();
}

// Signature section.

#[cfg(feature = "wedpr_f_signature_secp256k1")]
use wedpr_l_crypto_signature_secp256k1::WedprSecp256k1Recover;

#[cfg(feature = "wedpr_f_signature_secp256k1")]
lazy_static! {
    pub static ref SIGNATURE_SECP256K1: WedprSecp256k1Recover =
        WedprSecp256k1Recover::default();
}

#[cfg(feature = "wedpr_f_signature_sm2")]
use wedpr_l_crypto_signature_sm2::WedprSm2p256v1;

#[cfg(feature = "wedpr_f_signature_sm2")]
lazy_static! {
    pub static ref SIGNATURE_SM2: WedprSm2p256v1 = WedprSm2p256v1::default();
}

#[cfg(feature = "wedpr_f_signature_ed25519")]
use wedpr_l_crypto_signature_ed25519::WedprEd25519;

#[cfg(feature = "wedpr_f_signature_ed25519")]
lazy_static! {
    pub static ref SIGNATURE_ED25519: WedprEd25519 = WedprEd25519::default();
}

// Hash section.

#[cfg(feature = "wedpr_f_hash_keccak256")]
use wedpr_l_crypto_hash_keccak256::WedprKeccak256;

#[cfg(feature = "wedpr_f_hash_keccak256")]
lazy_static! {
    pub static ref HASH_KECCAK256: WedprKeccak256 = WedprKeccak256::default();
}

#[cfg(feature = "wedpr_f_hash_sm3")]
use wedpr_l_crypto_hash_sm3::WedprSm3;

#[cfg(feature = "wedpr_f_hash_sm3")]
lazy_static! {
    pub static ref HASH_SM3: WedprSm3 = WedprSm3::default();
}

#[cfg(feature = "wedpr_f_hash_sha3")]
use wedpr_l_crypto_hash_sha3::WedprSha3_256;

#[cfg(feature = "wedpr_f_hash_sha3")]
lazy_static! {
    pub static ref HASH_SHA3_256: WedprSha3_256 = WedprSha3_256::default();
}

#[cfg(feature = "wedpr_f_hash_ripemd160")]
use wedpr_l_crypto_hash_ripemd160::WedprRipemd160;

#[cfg(feature = "wedpr_f_hash_ripemd160")]
lazy_static! {
    pub static ref HASH_RIPEMD160: WedprRipemd160 = WedprRipemd160::default();
}

#[cfg(feature = "wedpr_f_hash_blake2b")]
use wedpr_l_crypto_hash_blake2b::WedprBlake2b;

#[cfg(feature = "wedpr_f_hash_blake2b")]
lazy_static! {
    pub static ref HASH_BLAKE2B: WedprBlake2b = WedprBlake2b::default();
}

// Block cipher section.

#[cfg(feature = "wedpr_f_crypto_block_cipher_aes")]
use wedpr_l_crypto_block_cipher_aes::WedprBlockCipherAes256;

#[cfg(feature = "wedpr_f_crypto_block_cipher_aes")]
lazy_static! {
    pub static ref BLOCK_CIPHER_AES256: WedprBlockCipherAes256 =
        WedprBlockCipherAes256::default();
}

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
use wedpr_l_crypto_block_cipher_sm4::WedprBlockCipherSm4;

#[cfg(feature = "wedpr_f_crypto_block_cipher_sm4")]
lazy_static! {
    pub static ref BLOCK_CIPHER_SM4: WedprBlockCipherSm4 =
        WedprBlockCipherSm4::default();
}
