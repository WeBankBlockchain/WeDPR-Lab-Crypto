// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! BaseX encoding and decoding functions.

use wedpr_l_utils::{error::WedprError, traits::Coder};

/// Implements Base64 as a Coder instance.
#[derive(Default, Debug, Clone)]
pub struct WedprBase64 {}

impl Coder for WedprBase64 {
    fn encode<T: ?Sized + AsRef<[u8]>>(&self, input: &T) -> String {
        base64::encode(input)
    }

    fn decode(&self, input: &str) -> Result<Vec<u8>, WedprError> {
        match base64::decode(input) {
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
        const CHILD: &str = "WEDPR_BASE64_LOG_REGRESSION_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(WedprBase64::default().decode(CANARY).is_err());
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
    fn test_base64() {
        let base64 = WedprBase64::default();
        let str = "g6sLGLyLvnkmE6V0Ico=";
        let wrong_str = "g6sLGLyLvnkmE6V0Ice=";
        let bytes = base64.decode(&str).unwrap();
        let recovered_str = base64.encode(&bytes);
        assert_eq!(str, recovered_str);
        assert!(wrong_str != recovered_str);
    }
}
