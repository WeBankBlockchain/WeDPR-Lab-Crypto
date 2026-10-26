//! Library of FFI of wedpr_crypto wrapper functions, targeting C/C++
//! compatible architectures (including iOS), with fast binary interfaces.
// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.
pub mod discrete_logarithm_proof;
pub mod utils;

#[cfg(test)]
mod security_tests;
// C/C++ FFI: C-style interfaces will be generated.
