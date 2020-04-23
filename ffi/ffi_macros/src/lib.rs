#[macro_export]
macro_rules! c_char_to_pb {
    ($c_char_pb:expr, $type:ty) => {
        match (unsafe { CStr::from_ptr($c_char_pb) }).to_str() {
            Ok(v) => match utils::string_to_bytes(v) {
                Ok(v) => match protobuf::parse_from_bytes::<$type>(&v) {
                    Ok(v) => v,
                    Err(_) => {
                        wedpr_println!(
                            "rstr to bytes error, rstr name: {}",
                            stringify!(v)
                        );
                        return FAILURE;
                    },
                },
                Err(_) => {
                    wedpr_println!(
                        "rstr to bytes error, rstr name: {}",
                        stringify!(v)
                    );
                    return FAILURE;
                },
            },
            Err(_) => {
                wedpr_println!(
                    "c_char to protobuf error, c_char name: {}, type name:
                         {}",
                    stringify!($c_char_pb),
                    stringify!($type)
                );
                return FAILURE;
            },
        }
    };
}

#[macro_export]
macro_rules! c_char_to_pb_with_err {
    ($c_char_pb:expr, $type:ty, $failure:expr) => {
        match (unsafe { CStr::from_ptr($c_char_pb) }).to_str() {
            Ok(v) => match utils::string_to_bytes(v) {
                Ok(v) => match protobuf::parse_from_bytes::<$type>(&v) {
                    Ok(v) => v,
                    Err(_) => {
                        wedpr_println!(
                            "rstr to bytes error, rstr name: {}",
                            stringify!(v)
                        );
                        return $failure;
                    },
                },
                Err(_) => {
                    wedpr_println!(
                        "rstr to bytes error, rstr name: {}",
                        stringify!(v)
                    );
                    return $failure;
                },
            },
            Err(_) => {
                wedpr_println!(
                    "c_char to protobuf error, c_char name: {}, type name:
                         {}",
                    stringify!($c_char_pb),
                    stringify!($type)
                );
                return $failure;
            },
        }
    };
}

/// a JString transferred to a protobuf object
#[macro_export]
macro_rules! jString_to_pb {
    ($_env:expr, $jobject_result:expr, $str:expr, $type:ty) => {
        bytes_to_pb!(
            $_env,
            $jobject_result,
            jString_to_bytes!($_env, $jobject_result, $str),
            $type
        )
    };
}

/// set a protobuf object as a String to a jobject
#[macro_export]
macro_rules! set_pb_field_to_jobject {
    ($_env:expr, $jobject_result:expr, $pb:expr, $field:expr) => {
        add_bytes_to_jobject!(
            $_env,
            &$jobject_result,
            pb_to_bytes!($_env, $jobject_result, $pb),
            $field
        )
    };
}

#[macro_export]
macro_rules! set_long_field_to_jobject {
    ($_env:expr, $jobject_result:expr, $n:expr, $field:expr) => {
        match $_env.set_field($jobject_result, $field, "J", JValue::from($n)) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "i64 to JValue error, field name: {}",
                        stringify!($field)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! set_int_field_to_jobject {
    ($_env:expr, $jobject_result:expr, $n:expr, $field:expr) => {
        match $_env.set_field($jobject_result, $field, "I", JValue::from($n)) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "i32 to JValue error, field name: {}",
                        stringify!($field)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! set_byte_field_to_jobject {
    ($_env:expr, $jobject_result:expr, $n:expr, $field:expr) => {
        match $_env.set_field($jobject_result, $field, "B", JValue::from($n)) {
            Ok(v) => v,
            Err(_) => {
                return set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "i8 to JValue error, field name: {}",
                        stringify!($field)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! jString_to_bytes {
    ($_env:expr, $jobject_result:expr, $str:expr) => {
        match utils::jstring_to_bytes(&$_env, $str) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "JString to bytes error, string name: {}",
                        stringify!($str)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! jBytes_to_bytes {
    ($_env:expr, $jobject_result:expr, $str:expr) => {
        match utils::jbytes_to_bytes(&$_env, $str) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "JBytes to bytes error, bytes name: {}",
                        stringify!($str)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! jString_to_string {
    ($_env:expr, $jobject_result:expr, $str:expr) => {
        match utils::jstring_to_string(&$_env, $str) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "JString to string error, string name: {}",
                        stringify!($str)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! jString_to_string_in_utils {
    ($_env:expr, $jobject_result:expr, $str:expr) => {
        match jstring_to_string(&$_env, $str) {
            Ok(v) => v,
            Err(_) => {
                return set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "JString to string error, string name: {}",
                        stringify!($str)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! bytes_to_pb {
    ($_env:expr, $jobject_result:expr, $bytes:expr, $type:ty) => {
        match protobuf::parse_from_bytes::<$type>(&$bytes) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "Bytes to protobuf error, bytes name: {}, type name: \
                         {}",
                        stringify!($bytes),
                        stringify!($type),
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! pb_to_bytes {
    ($_env:expr, $jobject_result:expr, $proto:expr) => {
        match $proto.write_to_bytes() {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "Protobuf to bytes error, proto name: {}",
                        stringify!($proto)
                    ),
                )
            },
        }
    };
}
#[macro_export]
macro_rules! add_string_to_jobject {
    ($_env:expr, $jobject_result:expr, $str:expr, $field:expr) => {
        match $_env.set_field(
            $jobject_result,
            $field,
            "Ljava/lang/String;",
            JValue::from(JObject::from(match $_env.new_string($str) {
                Ok(v) => v,
                Err(_) => {
                    return utils::set_error_jobject(
                        &$_env,
                        &$jobject_result,
                        &format!(
                            "string to JString error, bytes name: {}",
                            stringify!($str)
                        ),
                    )
                },
            })),
        ) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "JString to JObject error, field name: {}",
                        stringify!($field)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! add_bytes_to_jobject {
    ($_env:expr, $jobject_result:expr, $bytes:expr, $field:expr) => {
        match $_env.set_field(
            *$jobject_result,
            $field,
            "Ljava/lang/String;",
            JValue::from(JObject::from(
                match $_env.new_string(common_utils::bytes_to_string(&$bytes)) {
                    Ok(v) => v,
                    Err(_) => {
                        return utils::set_error_jobject(
                            &$_env,
                            &$jobject_result,
                            &format!(
                                "Bytes to JString error, bytes name: {}",
                                stringify!($bytes)
                            ),
                        )
                    },
                },
            )),
        ) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "JString to JObject error, field name: {}",
                        stringify!($field)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! parsed_owner_state {
    ($_env:expr, $jobject_result:expr, $owner_state:expr) => {
        match owner::ParsedOwnerState::from_owner_state($owner_state) {
            Ok(v) => v,
            Err(_) => {
                return utils::set_error_jobject(
                    &$_env,
                    &$jobject_result,
                    &format!(
                        "Parsed owner state failed, state name: {}",
                        stringify!($owner_state)
                    ),
                )
            },
        }
    };
}

#[macro_export]
macro_rules! pb_to_c_char {
    ($pb:expr, $failure:expr) => {
        match $pb.write_to_bytes() {
            Ok(v) => match CString::new(utils::bytes_to_string(&v)) {
                Ok(v) => v.into_raw(),
                Err(_) => return $failure,
            },
            Err(_) => return $failure,
        };
    };
}
