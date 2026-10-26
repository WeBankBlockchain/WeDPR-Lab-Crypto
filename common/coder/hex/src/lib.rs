// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Hex encoding and decoding functions.

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
                // Encoded inputs may contain private keys or plaintext.
                return Err(WedprError::DecodeError);
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_errors_do_not_log_sensitive_input() {
        const CANARY: &str = "SYNTHETIC_SECRET_CANARY!do-not-log";
        const CHILD: &str = "WEDPR_HEX_LOG_REGRESSION_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(WedprHex::default().decode(CANARY).is_err());
            return;
        }
        let output =
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::decoder_errors_do_not_log_sensitive_input",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(CANARY));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(CANARY));
    }

    #[test]
    fn test_hex() {
        let hex = WedprHex::default();
        let str =
            "eed91cd0d20db578d8616867edb9678df9787e81da3e92d08a38f23aacdb0003";
        // let str_bytes = "5c74d17c6a".as_bytes();
        // let str_re = String::from_utf8(str_bytes.to_vec());
        let bytes = hex.decode(&str).unwrap();
        // println!("bytes = {:?}", bytes);
        let recovered_str = hex.encode(&bytes);
        assert_eq!(str, recovered_str);
    }
}
