// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! FISCO BCOS Java Sdk specific functions.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::thread_rng;
use sha3::Sha3_512;
use wedpr_l_crypto_hash_keccak256::{self, WedprKeccak256};
use wedpr_l_crypto_zkp_utils::BASEPOINT_G1;
use wedpr_l_utils::{error::WedprError, traits::Hash};
use wedpr_l_common_coder_hex::WedprHex;
use wedpr_l_utils::traits::Coder;

mod tools;

#[derive(PartialEq, Default, Debug, Clone)]
pub struct vrf_proof {
    pub gamma: String,
    pub c: String,
    pub s: String,
}

impl vrf_proof {
    pub fn encode(&self) -> String {
        format!("{}|{}|{}", self.gamma, self.c, self.s)
    }

    pub fn decode(proof: &str) -> Result<vrf_proof, WedprError> {
        let proof_vec: Vec<&str> = proof.split("|").collect();
        if proof_vec.len() != 3 {
            return Err(WedprError::FormatError);
        }
        Ok(vrf_proof {
            gamma: proof_vec[0].to_string(),
            c: proof_vec[1].to_string(),
            s: proof_vec[2].to_string(),
        })
    }
}

pub fn curve25519_vrf_prove(
    x: &str,
    alpha: &str,
) -> Result<vrf_proof, WedprError> {
    let y = curve25519_vrf_gen_pubkey(x);
    // let y_point = tools::string_to_point(&y)?;
    let x_scalar = Scalar::hash_from_bytes::<Sha3_512>(x.as_bytes());
    let h_string = y.clone() + "|" + alpha;
    let h_point =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(h_string.as_bytes());
    let gamma = h_point * x_scalar;
    let blinding_k = Scalar::random(&mut thread_rng());
    let base_k = *BASEPOINT_G1 * blinding_k;
    let point_k = h_point * blinding_k;
    let c_string = h_string
        + "|"
        + &y
        + &tools::point_to_string(&gamma)
        + &tools::point_to_string(&base_k)
        + &tools::point_to_string(&point_k);
    let c_scalar = Scalar::hash_from_bytes::<Sha3_512>(c_string.as_bytes());
    let s = blinding_k - (c_scalar * x_scalar);
    let proof = vrf_proof {
        gamma: tools::point_to_string(&gamma),
        c: tools::scalar_to_string(&c_scalar),
        s: tools::scalar_to_string(&s),
    };
    Ok(proof)
}

pub fn curve25519_vrf_verify(y: &str, alpha: &str, proof: &vrf_proof) -> bool {
    let gamma = &proof.gamma;
    let c = &proof.c;
    let s = &proof.s;
    let gamma_point = match tools::string_to_point(gamma) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let y_point = match tools::string_to_point(y) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let c_scalar = match tools::string_to_scalar(c) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let s_scalar = match tools::string_to_scalar(s) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let u = (y_point * c_scalar) + (*BASEPOINT_G1 * s_scalar);
    let h_string = y.to_string() + "|" + alpha;
    let h_point =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(h_string.as_bytes());
    let v = (gamma_point * c_scalar) + (h_point * s_scalar);
    let expect_c_string = h_string
        + "|"
        + &y
        + &gamma
        + &tools::point_to_string(&u)
        + &tools::point_to_string(&v);
    let expect_c_scalar =
        Scalar::hash_from_bytes::<Sha3_512>(expect_c_string.as_bytes());
    if c_scalar != expect_c_scalar {
        return false;
    }
    true
}

pub fn curve25519_vrf_gen_pubkey(private_message: &str) -> String {
    let private_scalar =
        Scalar::hash_from_bytes::<Sha3_512>(private_message.as_bytes());
    let pubkey = *BASEPOINT_G1 * private_scalar;
    tools::point_to_string(&pubkey)
}

pub fn curve25519_vrf_proof_to_hash(
    proof: &vrf_proof,
) -> Result<String, WedprError> {
    let gamma = &proof.gamma;
    let gamma = tools::string_to_point(gamma)?;
    // order 8
    let base = gamma * Scalar::from(8u8);
    let hash: WedprKeccak256 = WedprKeccak256::default();
    Ok(bytes_to_string(
        &hash.hash(&wedpr_l_crypto_zkp_utils::point_to_bytes(&base)),
    ))
}

pub fn curve25519_vrf_is_valid_pubkey(pubkey: &str) -> bool {
    return match tools::string_to_point(pubkey) {
        Ok(_) => true,
        Err(_) => false,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vrf() {
        //        let x_scalar = Scalar::random(&mut thread_rng());
        let x = "random message";
        let y = curve25519_vrf_gen_pubkey(x);
        let alpha = "test msg";
        assert_eq!(curve25519_vrf_is_valid_pubkey(&y), true);
        assert_eq!(curve25519_vrf_is_valid_pubkey(x), false);

        let proof = curve25519_vrf_prove(x, alpha).unwrap();
        let hash_proof = curve25519_vrf_proof_to_hash(&proof).unwrap();
        let result = curve25519_vrf_verify(&y, alpha, &proof);
        let hash_verify = curve25519_vrf_proof_to_hash(&proof).unwrap();
        println!("hash_proof = {}", hash_proof);
        println!("hash_verify = {}", hash_verify);

        assert_eq!(result, true);
        let proof_err = curve25519_vrf_prove("error x", alpha).unwrap();
        let result_err = curve25519_vrf_verify(&y, alpha, &proof_err);
        assert_eq!(result_err, false);

        let encode = proof.encode();
        println!("encode = {}", encode);
        let decode = vrf_proof::decode(&encode).unwrap();
        let result = curve25519_vrf_verify(&y, alpha, &proof);
        println!("result = {}", result);
    }
}

/// Converts bytes to an encoded string.
fn bytes_to_string<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    let coder = WedprHex::default();
    coder.encode(input)
}

/// Converts an encoded string to a bytes vector.
fn string_to_bytes(input: &str) -> Result<Vec<u8>, WedprError> {
    let coder = WedprHex::default();
    coder.decode(input)
}
