// for java
extern crate jni;
// for C++
extern crate libc;
use self::jni::objects::JByteBuffer;
use common::{error::WedprError, utils};
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::{jint, jobject, jstring},
    JNIEnv,
};
use libc::c_char;
use regex::RegexSet;
use std::ffi::{CStr, CString};

const FORMAT_ERROR: &str = "#";
pub const SUCCESS: i8 = 0;
pub const FAILURE: i8 = -1;

pub const COMPATIBLE_RESULT_JAVA_PATH: &str = "Lcom/webank/wedpr/common/CompatibleResult;";

pub fn java_ffi_is_compatible(
    _env: &JNIEnv,
    _class: &JClass,
    target_version: &JString,
    regex_whitelist: &[&str],
    regex_blacklist: &[&str],
) -> jobject {
    let jobject_result = new_jobject(&_env, COMPATIBLE_RESULT_JAVA_PATH);
    let r_target_version: String =
        jString_to_string_in_utils!(_env, jobject_result, *target_version);

    let whitelist = match RegexSet::new(regex_whitelist) {
        Ok(v) => v,
        Err(_) => {
            return set_error_jobject(&_env, &jobject_result, "Init whitelist regexSet error.");
        }
    };
    let blacklist = match RegexSet::new(regex_blacklist) {
        Ok(v) => v,
        Err(_) => {
            return set_error_jobject(&_env, &jobject_result, "Init blacklist regexSet error.");
        }
    };
    let mut result = FAILURE;
    if is_compatible(&r_target_version, &whitelist, &blacklist) {
        result = SUCCESS;
    }
    set_byte_field_to_jobject!(_env, jobject_result, result, "result");

    jobject_result.into_inner()
}

pub fn cpp_ffi_is_compatible(
    target_version: *const c_char,
    regex_whitelist: &[&str],
    regex_blacklist: &[&str],
) -> i8 {
    let r_target_version = match c_char_to_string(target_version) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("Convert target version error.");
            return FAILURE;
        }
    };
    let whitelist = match RegexSet::new(regex_whitelist) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("Init whitelist regexSet error.");
            return FAILURE;
        }
    };
    let blacklist = match RegexSet::new(regex_blacklist) {
        Ok(v) => v,
        Err(_) => {
            wedpr_println!("Init blacklist regexSet error.");
            return FAILURE;
        }
    };
    let mut result = FAILURE;
    if is_compatible(&r_target_version, &whitelist, &blacklist) {
        result = SUCCESS;
    }
    result
}

fn is_compatible(target_version: &String, whitelist: &RegexSet, blacklist: &RegexSet) -> bool {
    if whitelist.is_match(target_version.as_str()) && !blacklist.is_match(target_version.as_str()) {
        return true;
    } else {
        return false;
    }
}

pub fn java_ffi_get_version(_env: &JNIEnv, _class: &JClass, version: &str) -> jstring {
    let j_version = _env.new_string(version).unwrap();
    j_version.into_inner()
}

pub fn cpp_ffi_get_version(version: &str) -> *mut c_char {
    let c_version = CString::new(version).unwrap();
    c_version.into_raw()
}

pub fn set_string_field(_env: &JNIEnv, jobject: JObject, field: &str, value: JString) {
    _env.set_field(
        jobject,
        field,
        "Ljava/lang/String;",
        JValue::from(JObject::from(value)),
    )
    .expect(&format!("Could not set {} field", field));
}

pub fn set_int_field(_env: &JNIEnv, jobject: JObject, field: &str, value: jint) {
    _env.set_field(jobject, field, "I", JValue::from(value))
        .expect(&format!("Could not set {} field", field));
}

pub fn new_jobject<'a>(_env: &'a JNIEnv, result_java_path: &'a str) -> JObject<'a> {
    let jclass_transfer_result = _env
        .find_class(result_java_path)
        .expect(&format!("could not find {} class", result_java_path));
    let jobject_transfer_result = _env
        .alloc_object(jclass_transfer_result)
        .expect(&format!("could not allocate {} object", result_java_path));
    jobject_transfer_result
}

pub fn set_jobject_string_field(
    _env: &JNIEnv,
    jobject_result: &JObject,
    field: &str,
    bytes_pb: &Vec<u8>,
) -> Result<(), WedprError> {
    let str_pb = utils::bytes_to_string(&bytes_pb);
    let java_str_pb = match _env.new_string(str_pb) {
        Ok(v) => v,
        Err(_) => return Err(WedprError::FormatError),
    };
    match _env.set_field(
        *jobject_result,
        field,
        "Ljava/lang/String;",
        JValue::from(JObject::from(java_str_pb)),
    ) {
        Ok(v) => v,
        Err(_) => return Err(WedprError::FormatError),
    };

    Ok(())
}

// TODO unwrap
pub fn set_error_jobject(_env: &JNIEnv, jobject_result: &JObject, message: &str) -> jobject {
    let java_str_pb = _env.new_string(message).unwrap();

    _env.set_field(
        *jobject_result,
        "wedprErrorMessage",
        "Ljava/lang/String;",
        JValue::from(JObject::from(java_str_pb)),
    )
    .unwrap();

    jobject_result.into_inner()
}

pub fn jstring_to_bytes(_env: &JNIEnv, param: JString) -> Result<Vec<u8>, WedprError> {
    let param_str = jstring_to_string(&_env, param)?;
    let param_str_bytes = match utils::string_to_bytes(&param_str) {
        Ok(v) => v,
        Err(_) => return Err(WedprError::FormatError),
    };
    Ok(param_str_bytes)
}

pub fn jstring_to_string(_env: &JNIEnv, param: JString) -> Result<String, WedprError> {
    let param_str: String = match _env.get_string(param) {
        Ok(v) => v.into(),
        Err(_) => return Err(WedprError::FormatError),
    };
    Ok(param_str)
}

pub fn jbytes_to_bytes(_env: &JNIEnv, param: JByteBuffer) -> Result<Vec<u8>, WedprError> {
    let param_Bytes = match _env.get_direct_buffer_address(param) {
        Ok(v) => v.to_vec(),
        Err(_) => return Err(WedprError::FormatError),
    };
    Ok(param_Bytes)
}

pub fn cstr_to_bytes(argument_pb: *mut i8) -> Result<Vec<u8>, WedprError> {
    let argument_cstr = unsafe { CStr::from_ptr(argument_pb) };
    let argument_rstr = match argument_cstr.to_str() {
        Ok(v) => v,
        Err(_) => return Err(WedprError::FormatError),
    };
    let argument_bytes = match utils::string_to_bytes(argument_rstr) {
        Ok(v) => v,
        Err(_) => return Err(WedprError::DecodeError),
    };

    Ok(argument_bytes)
}

pub fn c_char_to_string(param: *const c_char) -> Result<String, WedprError> {
    let cstr_param = unsafe { CStr::from_ptr(param) };
    let rstr_param = match cstr_param.to_str() {
        Ok(v) => v.to_owned(),
        Err(_) => return Err(WedprError::FormatError),
    };

    Ok(rstr_param)
}

pub fn bytes_to_cstr(credit_bytes: &Vec<u8>) -> *mut c_char {
    let credit_str = utils::bytes_to_string(&credit_bytes);
    let result = match CString::new(credit_str.as_str()) {
        Ok(v) => v,
        Err(_) => return CString::new(FORMAT_ERROR).unwrap().into_raw(),
    };
    result.into_raw()
}
