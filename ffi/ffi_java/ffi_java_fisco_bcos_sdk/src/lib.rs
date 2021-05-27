// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of FFI of wedpr_third_party_fisco_bcos_java_sdk wrapper functions,
//! targeting Java-compatible architectures (including Android), with fast
//! binary interfaces.

extern crate jni;
#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;
#[allow(unused_imports)]
#[macro_use]

pub mod vrf;

const RESULT_JAVA_SDK_CLASS_NAME: &str =
    "com/webank/fisco/bcos/wedpr/sdk/SdkResult";

use jni::{objects::JObject, JNIEnv};
use wedpr_ffi_common::utils::java_new_jobject;

#[allow(dead_code)]
fn get_result_jobject<'a>(_env: &'a JNIEnv) -> JObject<'a> {
    java_new_jobject(_env, RESULT_JAVA_SDK_CLASS_NAME)
}
