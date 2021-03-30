// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of FFI of wedpr_crypto wrapper functions, targeting
//! Java-compatible architectures (including Android), with fast binary
//! interfaces.

#![cfg(not(tarpaulin_include))]

extern crate jni;
#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;
#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_l_macros;
#[macro_use]
extern crate lazy_static;

pub mod block_cipher;
mod config;
pub mod ecies;
pub mod hash;
pub mod signature;
pub mod vrf;

use jni::{objects::JObject, JNIEnv};
use wedpr_ffi_common::utils::java_new_jobject;

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.crypto'.

#[allow(dead_code)]
// Result class name is 'com.webank.wedpr.crypto.CryptoResult'.
const RESULT_CRYPTO_CLASS_NAME: &str = "com/webank/wedpr/crypto/CryptoResult";

#[allow(dead_code)]
fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_CRYPTO_CLASS_NAME)
}
