use wasm_bindgen::prelude::*;
extern crate wedpr_bls12_381;


#[wasm_bindgen]
pub fn encrypt_message(message: &str) -> String {
    let message_bytes = match hex::decode(message) {
        Ok(v) => v,
        Err(_) => return "".to_string(),
    };
    let result = wedpr_bls12_381::encrypt_message(&message_bytes);
    hex::encode(result.to_bytes())
}