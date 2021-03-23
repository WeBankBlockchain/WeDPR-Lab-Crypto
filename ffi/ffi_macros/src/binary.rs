// Field setting section.

/// Sets a field of bytes type, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_set_bytes_binary_field {
    ($_env:expr, $result_jobject:expr, $rust_bytes:expr, $field_name:expr) => {
        java_safe_set_field!(
            $_env,
            $result_jobject,
            java_safe_bytes_to_jbyteArray!($_env, $result_jobject, $rust_bytes),
            $field_name,
            "[B"
        )
    };
}

/// Converts Rust String to Java bytes buffer, and returns an error object if
/// failed.
#[macro_export]
macro_rules! java_safe_bytes_to_jByteBuffer {
    ($_env:expr, $result_jobject:expr, $rust_bytes:expr) => {
        JObject::from(match $_env.new_direct_byte_buffer($rust_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!("java_safe_bytes_to_jByteBuffer failed",),
                )
            },
        })
    };
}

/// Converts Rust String to Java bytes array, and returns an error object if
/// failed.
#[macro_export]
macro_rules! java_safe_bytes_to_jbyteArray {
    ($_env:expr, $result_jobject:expr, $rust_bytes:expr) => {
        JObject::from(match java_bytes_to_jbyte_array(&$_env, $rust_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!("java_safe_bytes_to_jbyteArray failed",),
                )
            },
        })
    };
}

/// Check C pointer input length.
#[macro_export]
macro_rules! check_c_pointer_length {
    ($c_pointer:expr, $c_pointer_expected_length:expr) => {
        if $c_pointer.len < $c_pointer_expected_length {
            return FAILURE;
        }
    };
}
