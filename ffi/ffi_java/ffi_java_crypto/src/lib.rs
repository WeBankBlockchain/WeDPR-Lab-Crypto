// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of FFI of wedpr_crypto wrapper functions, targeting
//! Java-compatible architectures (including Android).

#![cfg(not(tarpaulin_include))]

#[cfg(all(feature = "wedpr_f_base64", feature = "wedpr_f_hex"))]
compile_error!(
    "Feature wedpr_base64 and wedpr_hex can not be enabled at same time!"
);

#[cfg(all(not(feature = "wedpr_f_base64"), not(feature = "wedpr_f_hex")))]
compile_error!("Must use feature wedpr_base64 or wedpr_hex!");

extern crate jni;
#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;
#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_l_macros;
#[allow(unused_imports)]
#[macro_use]
extern crate lazy_static;

mod config;
pub mod ecies;
pub mod hash;
pub mod signature;
pub mod vrf;

#[cfg(feature = "wedpr_f_base64")]
use wedpr_ffi_common_base64::utils::java_new_jobject;

#[cfg(feature = "wedpr_f_hex")]
use wedpr_ffi_common_hex::utils::java_new_jobject;

use jni::{objects::JObject, JNIEnv};

// Java FFI: Java interfaces will be generated under
// package name 'com.webank.wedpr.crypto'.

#[allow(dead_code)]
// Result class name is 'com.webank.wedpr.crypto.CryptoResult'.
const RESULT_CRYPTO_CLASS_NAME: &str = "com/webank/wedpr/crypto/CryptoResult";

#[allow(dead_code)]
fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_CRYPTO_CLASS_NAME)
}
