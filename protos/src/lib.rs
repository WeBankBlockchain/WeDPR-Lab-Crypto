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

#[cfg(test)]
mod security_tests {
    use super::*;
    use generated::common::Keypair;

    #[test]
    fn rejects_deep_inputs_without_aborting_the_process() {
        const CHILD: &str = "WEDPR_PROTO_RECURSION_REGRESSION_CHILD";
        if let Ok(mode) = std::env::var(CHILD) {
            if mode == "groups" {
                let mut input = vec![0x7b; 20_000];
                input.extend_from_slice(&vec![0x7c; 20_000]);
                assert!(bytes_to_proto::<Keypair>(&input).is_err());
            } else {
                fn wrap(tag: u8, body: Vec<u8>) -> Vec<u8> {
                    let mut output = vec![tag];
                    let mut length = body.len();
                    while length >= 128 {
                        output.push((length as u8 & 127) | 128);
                        length >>= 7;
                    }
                    output.push(length as u8);
                    output.extend_from_slice(&body);
                    output
                }
                // Value.list_value -> ListValue.values -> Value, repeated.
                let mut shallow = Vec::new();
                for _ in 0..3 {
                    shallow = wrap(0x32, wrap(0x0a, shallow));
                }
                assert!(protobuf::well_known_types::struct_::Value::parse_from_bytes(&shallow).is_ok());
                let mut input = Vec::new();
                for _ in 0..2048 {
                    input = wrap(0x32, wrap(0x0a, input));
                }
                assert!(protobuf::well_known_types::struct_::Value::parse_from_bytes(&input).is_err());
            }
            return;
        }
        for mode in ["groups", "values"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "security_tests::rejects_deep_inputs_without_aborting_the_process", "--nocapture"])
                .env(CHILD, mode).output().unwrap();
            assert!(
                output.status.success(),
                "parser child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn preserves_keypair_wire_encoding() {
        let mut keypair = Keypair::new();
        keypair.set_public_key(vec![1, 2, 3]);
        keypair.set_private_key(vec![4, 5]);
        let wire = vec![10, 3, 1, 2, 3, 18, 2, 4, 5];
        assert_eq!(proto_to_bytes(&keypair).unwrap(), wire);
        assert_eq!(bytes_to_proto::<Keypair>(&wire).unwrap(), keypair);
    }
}
