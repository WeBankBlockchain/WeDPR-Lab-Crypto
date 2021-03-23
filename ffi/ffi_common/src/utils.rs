// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Common utility functions for FFI.

#[cfg(all(feature = "wedpr_f_base64", feature = "wedpr_f_hex"))]
compile_error!(
    "Feature wedpr_f_base64 and wedpr_f_hex can not be enabled at same time!"
);

#[cfg(all(not(feature = "wedpr_f_base64"), not(feature = "wedpr_f_hex")))]
compile_error!("Must use feature wedpr_f_base64 or wedpr_f_hex!");

// From Rust to Java.
extern crate jni;
use jni::{
    objects::{JObject, JString, JValue},
    sys::jobject,
    JNIEnv,
};

// From Rust to C/C++.
use libc::c_char;
use std::ffi::CStr;

use wedpr_l_utils::{error::WedprError, traits::Coder};

#[cfg(feature = "wedpr_f_base64")]
use wedpr_l_common_coder_base64::WedprBase64;

use self::jni::sys::jbyteArray;
#[cfg(feature = "wedpr_f_hex")]
use wedpr_l_common_coder_hex::WedprHex;

#[cfg(feature = "wedpr_f_hex")]
lazy_static! {
    pub static ref CODER: WedprHex = WedprHex::default();
}

#[cfg(feature = "wedpr_f_base64")]
lazy_static! {
    pub static ref CODER: WedprBase64 = WedprBase64::default();
}

// Rust to c/c++
#[repr(C)]
pub struct CPointOutput {
    pub data: *mut c_char,
    pub len: usize,
}

// Rust to c/c++
#[repr(C)]
pub struct CPointInput {
    pub data: *const c_char,
    pub len: usize,
}

// Java FFI functions.

// Default error field name used by WeDPR FFI output data types.
const DEFAULT_ERROR_FIELD: &str = "wedprErrorMessage";

/// Converts bytes to an encoded string.
pub fn bytes_to_string<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    CODER.encode(input)
}

/// Converts an encoded string to a bytes vector.
pub fn string_to_bytes(input: &str) -> Result<Vec<u8>, WedprError> {
    CODER.decode(input)
}

/// Creates a new Java object of a given class specified by java_class_name.
/// Please note that objects::JObject is the wrapper object type used by FFI
/// logic. You will need to later call .into_inner() function to extract the
/// actual object type (sys::jobject), and return it to Java runtime.
pub fn java_new_jobject<'a>(
    _env: &'a JNIEnv,
    java_class_name: &'a str,
) -> JObject<'a> {
    let java_class = _env
        .find_class(java_class_name)
        .expect(&format!("Could not find Java class {}", java_class_name));
    let java_object = _env.alloc_object(java_class).expect(&format!(
        "Could not allocate Java object Ffor class {}",
        java_class_name
    ));
    java_object
}

/// Sets the default error message field and extracts actual java object to
/// return in a erroneous condition.
pub fn java_set_error_field_and_extract_jobject(
    _env: &JNIEnv,
    java_object: &JObject,
    error_message: &str,
) -> jobject {
    let java_string;
    // Error message should not be empty.
    // assert!(!error_message.is_empty());
    java_string = _env
        .new_string(error_message)
        .expect("new_string should not fail");
    _env.set_field(
        *java_object,
        DEFAULT_ERROR_FIELD,
        "Ljava/lang/String;",
        JValue::from(JObject::from(java_string)),
    )
    .expect("set_field should not fail");

    // Extract actual java object.
    java_object.into_inner()
}

// /// Sets the default error message field and extracts actual java object to
// /// return in a erroneous condition.
// pub fn java_set_error_field_and_extract_jobject_binary(
//     _env: &JNIEnv,
//     java_object: &JObject,
//     // error_message: &mut [u8],
// ) -> jobject {
//     let java_bytes_array;
//     // Error message should not be empty.
//     // assert!(!error_message.is_empty());
//     java_bytes_array = _env.new_byte_array(4).expect("new new_bytes should
// not fail");     let rust_bytes_arry = b"0123";
//     let i8slice = unsafe {&*(rust_bytes_arry as *const [u8] as *const [i8])};
//     _env.set_byte_array_region(java_bytes_array, 4, &i8slice);
//     // java_bytes_array = _env
//     //     .new_byte_array(&mut ERROR_MESSAGE_BYTES)
//     //     .expect("new_bytes should not fail");
//     _env.set_field(
//         *java_object,
//         DEFAULT_ERROR_FIELD,
//         "[B",
//         JValue::from(JObject::from(java_bytes_array)),
//     )
//     .expect("set_field should not fail");
//
//     // Extract actual java object.
//     java_object.into_inner()
// }

pub fn java_bytes_to_jbyte_array(
    _env: &JNIEnv,
    rust_bytes_array: &[u8],
) -> Result<jbyteArray, WedprError> {
    return match _env.byte_array_from_slice(rust_bytes_array) {
        Ok(v) => Ok(v),
        Err(_) => Err(WedprError::ArgumentError),
    };

    // let i8slice = unsafe {&*(rust_bytes_array as *const [u8] as *const
    // [i8])}; return match _env.set_byte_array_region(java_bytes_array,
    // bytes_size, &i8slice) {     Ok(_) => Ok(java_bytes_array),
    //     Err(_) => Err(WedprError::FormatError),
    // };
}

/// Converts Java String to Rust bytes.
pub fn java_jstring_to_bytes(
    _env: &JNIEnv,
    java_string: JString,
) -> Result<Vec<u8>, WedprError> {
    let rust_string = java_jstring_to_string(&_env, java_string)?;
    match string_to_bytes(&rust_string) {
        Ok(rust_bytes) => Ok(rust_bytes),
        Err(_) => return Err(WedprError::FormatError),
    }
}

/// Converts Java String to Rust String.
pub fn java_jstring_to_string(
    _env: &JNIEnv,
    java_string: JString,
) -> Result<String, WedprError> {
    match _env.get_string(java_string) {
        Ok(java_string_data) => Ok(java_string_data.into()),
        Err(_) => return Err(WedprError::FormatError),
    }
}

/// Converts Java bytes to Rust bytes.
pub fn java_jbytes_to_bytes(
    _env: &JNIEnv,
    java_bytes: jbyteArray,
) -> Result<Vec<u8>, WedprError> {
    match _env.convert_byte_array(java_bytes) {
        Ok(rust_bytes_array) => Ok(rust_bytes_array.to_vec()),
        Err(_) => return Err(WedprError::FormatError),
    }
}

// C/C++ FFI functions.

/// Default success status return code for C/C++ functions.
pub const SUCCESS: i8 = 0;
/// Default failure status return code for C/C++ functions.
pub const FAILURE: i8 = -1;

/// Converts C char pointer to Rust string.
pub fn c_char_pointer_to_string(
    param: *const c_char,
) -> Result<String, WedprError> {
    let cstr_param = unsafe { CStr::from_ptr(param) };
    match cstr_param.to_str() {
        Ok(v) => Ok(v.to_owned()),
        Err(_) => Err(WedprError::FormatError),
    }
}

/// Converts C char pointer to Rust bytes.
pub fn c_char_pointer_to_bytes(param: *const c_char) -> Vec<u8> {
    let cstr_param = unsafe { CStr::from_ptr(param) };
    cstr_param.to_bytes().to_vec()
}

/// Converts C pointer to Rust bytes.
pub unsafe fn c_pointer_to_rust_bytes(input: &CPointInput) -> Vec<u8> {
    Vec::from_raw_parts(input.data as *mut u8, input.len, input.len)
}

/// Set Rust bytes to C pointer.
pub unsafe fn set_c_pointer<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    output: &mut CPointOutput,
) {
    let data_slice =
        std::slice::from_raw_parts_mut(output.data as *mut u8, output.len);
    data_slice.copy_from_slice(&input.as_ref());
    std::mem::forget(data_slice);
}
