// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Hex encoding and decoding functions.

#[macro_use]
extern crate wedpr_l_macros;

use wedpr_l_utils::{error::WedprError, traits::Coder};

/// Implements Hex as a Coder instance.
#[derive(Default, Debug, Clone)]
pub struct WedprHex {}

impl Coder for WedprHex {
    fn encode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> String {
        hex::encode(input)
    }

    fn decode(&self, input: &str) -> Result<Vec<u8>, WedprError> {
        match hex::decode(input) {
            Ok(v) => return Ok(v),
            Err(_) => {
                wedpr_println!("Hex decoding failed, input was: {}", input);
                return Err(WedprError::DecodeError);
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        let hex = WedprHex::default();
        let str = "eed91cd0d20db578d8616867edb9678df9787e81da3e92d08a38f23aacdb0003";
        // let str_bytes = "5c74d17c6a".as_bytes();
        // let str_re = String::from_utf8(str_bytes.to_vec());
        let bytes = hex.decode(&str).unwrap();
        // println!("bytes = {:?}", bytes);
        let recovered_str = hex.encode(&bytes);
        assert_eq!(str, recovered_str);
    }
}
