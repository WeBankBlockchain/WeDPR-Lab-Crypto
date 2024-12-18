// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of FFI of wedpr_crypto wrapper functions, targeting C/C++
//! compatible architectures (including iOS), with fast binary interfaces.

#![cfg(not(tarpaulin_include))]
#[macro_use]
extern crate wedpr_ffi_macros;

// #[macro_use]
// extern crate wedpr_l_macros;

#[allow(unused_imports)]
#[macro_use]
extern crate lazy_static;

pub mod block_cipher;
mod config;
pub mod ecies;
pub mod hash;
pub mod signature;
pub mod vrf;
pub mod vrf_secp256k1;

// C/C++ FFI: C-style interfaces will be generated.
