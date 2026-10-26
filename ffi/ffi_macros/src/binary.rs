// Field setting section.

#![cfg(not(tarpaulin_include))]

/// Sets a field of bytes type, and returns an error object if failed.
#[macro_export]
macro_rules! java_safe_set_byte_array_field {
    ($_env:expr, $result_jobject:expr, $rust_bytes:expr, $field_name:expr) => {
        java_safe_set_field!(
            $_env,
            $result_jobject,
            java_safe_bytes_to_jbyte_array!(
                $_env,
                $result_jobject,
                $rust_bytes
            ),
            $field_name,
            "[B"
        )
    };
}

/// Copies Rust bytes into a Java-owned heap ByteBuffer. Never wrap temporary
/// Rust memory in a direct buffer: Java can retain it after Rust frees it.
#[macro_export]
macro_rules! java_safe_bytes_to_jbytebuffer {
    ($_env:expr, $result_jobject:expr, $rust_bytes:expr) => {{
        let array = java_safe_bytes_to_jbyte_array!(
            $_env,
            $result_jobject,
            $rust_bytes
        );
        match $_env
            .call_static_method(
                "java/nio/ByteBuffer",
                "wrap",
                "([B)Ljava/nio/ByteBuffer;",
                &[JValue::from(array)],
            )
            .and_then(|value| value.l())
        {
            Ok(buffer) => buffer,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    "Java ByteBuffer allocation failed",
                )
            },
        }
    }};
}

/// Converts Rust String to Java byte array, and returns an error object if
/// failed.
#[macro_export]
macro_rules! java_safe_bytes_to_jbyte_array {
    ($_env:expr, $result_jobject:expr, $rust_bytes:expr) => {
        JObject::from(match java_bytes_to_jbyte_array(&$_env, $rust_bytes) {
            Ok(v) => v,
            Err(_) => {
                return java_set_error_field_and_extract_jobject(
                    &$_env,
                    &$result_jobject,
                    &format!("java_safe_bytes_to_jbyte_array failed",),
                )
            },
        })
    };
}

/// Check whether a C buffer pointer has the expected buffer size.
#[macro_export]
macro_rules! c_check_exact_buffer_size {
    ($c_pointer:expr, $c_pointer_expected_length:expr) => {
        if $c_pointer.len != $c_pointer_expected_length {
            return FAILURE;
        }
    };
}

/// Check whether a C buffer pointer has the expected buffer size.
#[macro_export]
macro_rules! c_check_enough_buffer_size {
    ($c_pointer:expr, $c_pointer_min_length:expr) => {
        if $c_pointer.len < $c_pointer_min_length {
            return FAILURE;
        }
    };
}
