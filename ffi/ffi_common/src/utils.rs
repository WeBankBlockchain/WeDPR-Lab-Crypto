// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Common utility functions for FFI.

#![cfg(not(tarpaulin_include))]

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
    let java_class = match _env.find_class(java_class_name) {
        Ok(class) => class,
        Err(_) => return JObject::null(),
    };
    // Preserve the Java exception on failure instead of unwinding across JNI.
    _env.alloc_object(java_class)
        .unwrap_or_else(|_| JObject::null())
}

/// Sets the default error message field and extracts actual java object to
/// return in a erroneous condition.
pub fn java_set_error_field_and_extract_jobject(
    _env: &JNIEnv,
    java_object: &JObject,
    error_message: &str,
) -> jobject {
    if java_object.into_inner().is_null()
        || _env.exception_check().unwrap_or(true)
    {
        return std::ptr::null_mut();
    }
    let java_string = match _env.new_string(error_message) {
        Ok(value) => value,
        Err(_) => return std::ptr::null_mut(),
    };
    if _env
        .set_field(
            *java_object,
            DEFAULT_ERROR_FIELD,
            "Ljava/lang/String;",
            JValue::from(JObject::from(java_string)),
        )
        .is_err()
    {
        return std::ptr::null_mut();
    }

    // Extract actual java object.
    java_object.into_inner()
}

/// Converts Rust bytes to Java byte array.
pub fn java_bytes_to_jbyte_array(
    _env: &JNIEnv,
    rust_bytes_array: &[u8],
) -> Result<jbyteArray, WedprError> {
    return match _env.byte_array_from_slice(rust_bytes_array) {
        Ok(v) => Ok(v),
        Err(_) => Err(WedprError::ArgumentError),
    };
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

/// Converts Java byte array to Rust bytes.
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

// Input buffer for C/C++ FFI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CInputBuffer {
    pub data: *const c_char,
    pub len: usize,
}

// Output buffer for C/C++ FFI.
#[repr(C)]
pub struct COutputBuffer {
    pub data: *mut c_char,
    pub len: usize,
}

/// Copy a C input descriptor before borrowing its data.
///
/// # Safety
/// A nonnull, aligned pointer must refer to a readable descriptor.
pub unsafe fn c_copy_input_buffer(
    input: *const CInputBuffer,
) -> Result<CInputBuffer, WedprError> {
    if input.is_null()
        || (input as usize) % std::mem::align_of::<CInputBuffer>() != 0
    {
        return Err(WedprError::ArgumentError);
    }
    Ok(input.read())
}

/// Validate a C output descriptor before creating a Rust mutable reference.
///
/// # Safety
/// A nonnull, aligned pointer must refer to an exclusively writable descriptor.
pub unsafe fn c_borrow_output_buffer<'a>(
    output: *mut COutputBuffer,
) -> Result<&'a mut COutputBuffer, WedprError> {
    if output.is_null()
        || (output as usize) % std::mem::align_of::<COutputBuffer>() != 0
    {
        return Err(WedprError::ArgumentError);
    }
    Ok(&mut *output)
}

/// Converts C char pointer to Rust string.
///
/// # Safety
/// A nonnull pointer must refer to a valid NUL-terminated string.
pub unsafe fn c_char_pointer_to_string(
    c_char_pointer: *const c_char,
) -> Result<String, WedprError> {
    if c_char_pointer.is_null() {
        return Err(WedprError::ArgumentError);
    }
    let cstr = unsafe { CStr::from_ptr(c_char_pointer) };
    match cstr.to_str() {
        Ok(v) => Ok(v.to_owned()),
        Err(_) => Err(WedprError::FormatError),
    }
}

/// Converts C char pointer to Rust bytes.
///
/// # Safety
/// A nonnull pointer must refer to a valid NUL-terminated byte string.
pub unsafe fn c_char_pointer_to_bytes(
    c_char_pointer: *const c_char,
) -> Result<Vec<u8>, WedprError> {
    if c_char_pointer.is_null() {
        return Err(WedprError::ArgumentError);
    }
    let cstr = unsafe { CStr::from_ptr(c_char_pointer) };
    Ok(cstr.to_bytes().to_vec())
}

/// Borrow a C buffer without taking ownership or freeing caller memory.
///
/// # Safety
/// A nonempty buffer must point to readable memory valid for the returned
/// borrow. A null pointer is accepted only for an empty buffer.
pub unsafe fn c_read_raw_data_pointer<'a>(
    c_input_data: *const c_char,
    c_input_len: usize,
) -> Result<&'a [u8], WedprError> {
    if c_input_len == 0 {
        return Ok(&[]);
    }
    if c_input_data.is_null() || c_input_len > isize::MAX as usize {
        return Err(WedprError::ArgumentError);
    }
    Ok(std::slice::from_raw_parts(
        c_input_data as *const u8,
        c_input_len,
    ))
}

/// Borrow a caller-owned C input buffer.
///
/// # Safety
/// The declared memory must remain valid and readable for the borrow.
pub unsafe fn c_read_raw_pointer(
    c_input_buffer: &CInputBuffer,
) -> Result<&[u8], WedprError> {
    c_read_raw_data_pointer(c_input_buffer.data, c_input_buffer.len)
}

/// Copy bytes only after checking pointer, length and capacity. Failure writes
/// nothing, and is reported to the caller rather than panicking across FFI.
///
/// # Safety
/// Nonempty output must point to writable memory with the declared capacity;
/// source and destination must not overlap.
pub unsafe fn c_write_data_to_pointer<T: ?Sized + AsRef<[u8]>>(
    rust_bytes: &T,
    c_output_buffer: *mut c_char,
    c_output_len: usize,
) -> Result<usize, WedprError> {
    let bytes = rust_bytes.as_ref();
    if c_output_len > isize::MAX as usize || bytes.len() > c_output_len {
        return Err(WedprError::ArgumentError);
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    if c_output_buffer.is_null() {
        return Err(WedprError::ArgumentError);
    }
    std::ptr::copy_nonoverlapping(
        bytes.as_ptr(),
        c_output_buffer as *mut u8,
        bytes.len(),
    );
    Ok(bytes.len())
}

/// Write an output buffer. On failure, len reports the required capacity and
/// caller memory remains unchanged.
///
/// # Safety
/// The same pointer and non-overlap requirements as c_write_data_to_pointer.
pub unsafe fn c_write_raw_pointer<T: ?Sized + AsRef<[u8]>>(
    rust_bytes: &T,
    c_output_buffer: &mut COutputBuffer,
) -> Result<(), WedprError> {
    let result = c_write_data_to_pointer(
        rust_bytes,
        c_output_buffer.data,
        c_output_buffer.len,
    );
    c_output_buffer.len = rust_bytes.as_ref().len();
    result.map(|_| ())
}

#[cfg(test)]
mod security_tests;
