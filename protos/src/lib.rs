// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of protobuf definitions and their generated code.

use protobuf::Message;

#[cfg(not(tarpaulin_include))]
pub mod generated;

use wedpr_l_utils::error::WedprError;

pub fn proto_to_bytes<T: Message>(proto: &T) -> Result<Vec<u8>, WedprError> {
    return match proto.write_to_bytes() {
        Ok(v) => Ok(v),
        Err(_) => Err(WedprError::DecodeError),
    };
}

pub fn bytes_to_proto<T: Message>(proto_bytes: &[u8]) -> Result<T, WedprError> {
    return match T::parse_from_bytes(proto_bytes) {
        Ok(v) => Ok(v),
        Err(_) => Err(WedprError::DecodeError),
    };
}
