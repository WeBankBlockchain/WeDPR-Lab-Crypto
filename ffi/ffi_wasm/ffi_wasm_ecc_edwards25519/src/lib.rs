extern crate wasm_bindgen;

use ecc_edwards25519::{hash_to_curve, point_scalar_multi, random_scalar};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub fn wasm_point_scalar_multi(point: &[u8], scalar: &[u8]) -> Vec<u8> {
    point_scalar_multi(point, scalar)
}

#[wasm_bindgen]
pub fn wasm_hash_to_curve(message: &[u8]) -> Vec<u8> {
    hash_to_curve(message)
}

#[wasm_bindgen]
pub fn wasm_random_scalar() -> Vec<u8> {
    random_scalar()
}
