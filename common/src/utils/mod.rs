use crate::error::WedprError;
extern crate base64;



macro_rules! crate_string_to_bytes {
    ($param:expr) => {
        match string_to_bytes($param) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("macro string_to_bytes failed");
                return false;
            },
        }
    };
}

/// Encodes bytes to a base64-encoded string.
/// ?Sized removes the contraints that the slice size need to be known at
/// compilation time. AsRef does automatic reference to reference conversion
/// from &T to &[u8].
pub fn bytes_to_string<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::encode(input)
}

/// Decodes a base64-encoded string to bytes.
pub fn string_to_bytes(input: &str) -> Result<Vec<u8>, WedprError> {
    match base64::decode(input) {
        Ok(v) => return Ok(v),
        Err(_) => {
            wedpr_println!("string_to_bytes decode failed, string: {}", input,);
            return Err(WedprError::DecodeError);
        },
    };
}

