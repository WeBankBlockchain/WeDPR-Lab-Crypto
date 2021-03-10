// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! WeDPR simple tool functions.

/// Decodes an string to a bytes vector without decoding.
pub fn string_to_bytes_utf8(message: &str) -> Vec<u8> {
    message.as_bytes().to_vec()
}
