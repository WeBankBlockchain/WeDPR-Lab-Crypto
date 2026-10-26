//! Test-only JNI shim for the exported ByteBuffer conversion macro.
use jni::{
    objects::{JClass, JObject, JValue},
    sys::jobject,
    JNIEnv,
};
use wedpr_ffi_common::utils::{
    java_bytes_to_jbyte_array, java_set_error_field_and_extract_jobject,
};
#[macro_use]
extern crate wedpr_ffi_macros;

#[no_mangle]
pub extern "system" fn Java_com_webank_wedpr_crypto_NativeInterface_copyBuffer(
    env: JNIEnv,
    _: JClass,
) -> jobject {
    let mut bytes: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let result = JObject::null();
    let buffer = java_safe_bytes_to_jbytebuffer!(env, result, &mut bytes);
    // Mutation and deallocation must not affect the Java-owned copy.
    bytes.fill(0xee);
    drop(bytes);
    buffer.into_inner()
}
