extern crate curve25519_dalek;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::{ristretto, scalar::Scalar};
extern crate rand;
extern crate sha3;
use super::hash::keccak256_hex;
use super::utils as local_utils;
use common::constant::G1_BASEPOINT;
use common::error::WedprError;
use common::utils;
use rand::thread_rng;
use sha3::Sha3_512;

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

pub fn curve25519_vrf_prove(x: &str, alpha: &str) -> Result<vrf_proof, WedprError> {
    let y = curve25519_vrf_gen_pubkey(x);
    let y_point = local_utils::string_to_point(&y)?;
    let x_scalar = Scalar::hash_from_bytes::<Sha3_512>(x.as_bytes());
    let h_string = y.clone() + "|" + alpha;
    let h_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(h_string.as_bytes());
    let gamma = h_point * x_scalar;
    let blinding_k = Scalar::random(&mut thread_rng());
    let base_k = *G1_BASEPOINT * blinding_k;
    let point_k = h_point * blinding_k;
    let c_string = h_string
        + "|"
        + &y
        + &local_utils::point_to_string(&gamma)
        + &local_utils::point_to_string(&base_k)
        + &local_utils::point_to_string(&point_k);
    let c_scalar = Scalar::hash_from_bytes::<Sha3_512>(c_string.as_bytes());
    let s = blinding_k - (c_scalar * x_scalar);
    let proof = vrf_proof {
        gamma: local_utils::point_to_string(&gamma),
        c: local_utils::scalar_to_string(&c_scalar),
        s: local_utils::scalar_to_string(&s),
    };
    Ok(proof)
}

pub fn curve25519_vrf_verify(y: &str, alpha: &str, proof: &vrf_proof) -> bool {
    let gamma = &proof.gamma;
    let c = &proof.c;
    let s = &proof.s;
    let gamma_point = string_to_point!(gamma);
    let y_point = string_to_point!(y);
    let c_scalar = string_to_scalar!(c);
    let s_scalar = string_to_scalar!(s);
    let u = (y_point * c_scalar) + (*G1_BASEPOINT * s_scalar);
    let h_string = y.to_string() + "|" + alpha;
    let h_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(h_string.as_bytes());
    let v = (gamma_point * c_scalar) + (h_point * s_scalar);
    let expect_c_string = h_string
        + "|"
        + &y
        + &gamma
        + &local_utils::point_to_string(&u)
        + &local_utils::point_to_string(&v);
    let expect_c_scalar = Scalar::hash_from_bytes::<Sha3_512>(expect_c_string.as_bytes());
    if c_scalar != expect_c_scalar {
        wedpr_println!("verify failed!");
        return false;
    }
    true
}

pub fn curve25519_vrf_gen_pubkey(private_message: &str) -> String {
    let private_scalar = Scalar::hash_from_bytes::<Sha3_512>(private_message.as_bytes());
    let pubkey = *G1_BASEPOINT * private_scalar;
    local_utils::point_to_string(&pubkey)
}

pub fn curve25519_vrf_proof_to_hash(proof: &vrf_proof) -> Result<String, WedprError> {
    let gamma = &proof.gamma;
    let gamma = local_utils::string_to_point(gamma)?;
    //order 8
    let base = gamma * Scalar::from(8u8);

    keccak256_hex(&local_utils::point_to_string(&base))
}

pub fn curve25519_vrf_is_valid_pubkey(pubkey: &str) -> bool {
    match local_utils::string_to_point(pubkey) {
        Ok(_) => return true,
        Err(_) => return false,
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
