use super::WeDPRSm2p256v1;

use super::Signature;
use common::constant::SM2_CTX;
use common::error::WedprError;
use common::utils;
use libsm::sm2::signature::Signature as sm2Signature;

impl Signature for WeDPRSm2p256v1 {
    fn sign(&self, private_key: &str, msg: &str) -> Result<String, WedprError> {
        let private_key_vec = utils::string_to_bytes(private_key)?;
        let new_sk = match SM2_CTX.load_seckey(&private_key_vec[..]) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!(
                    "load_seckey failed, private_key_vec = {:?}",
                    private_key_vec
                );
                return Err(WedprError::FormatError);
            }
        };
        let pk = SM2_CTX.pk_from_sk(&new_sk);
        // let signature:sm2Signature = SM2_CTX.sign(msg.as_bytes(), &new_sk, &pk);
        let signature: sm2Signature = SM2_CTX.sign(&utils::string_to_bytes(msg)?, &new_sk, &pk);
        let (r, s) = signature.hex_encode();
        if r.len() == 0 {
            return Err(WedprError::FormatError);
        }
        Ok(r + &s)
    }

    fn verify(&self, public_key: &str, msg: &str, signature: &str) -> bool {
        let pk_raw = match utils::string_to_bytes(public_key) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("string_to_bytes failed, public_key = {:?}", public_key);
                return false;
            }
        };
        let new_pk = match SM2_CTX.load_pubkey(&pk_raw[..]) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("load_pubkey failed, pk_raw = {:?}", pk_raw);
                return false;
            }
        };
        if signature.len() != 128 {
            wedpr_println!("signature check failed, signature = {:?}", signature);
            return false;
        }
        let signature_str = signature.clone().to_string();
        let r = signature_str[0..64].to_string().clone();
        let s = signature_str[64..128].to_string().clone();
        let parsed_sig = match sm2Signature::hex_decode(r, s) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("string_to_bytes failed, signature = {:?}", signature_str);
                return false;
            }
        };
        let message_hash_result = match utils::string_to_bytes(&msg) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("load_pubkey failed, pk_raw = {:?}", pk_raw);
                return false;
            }
        };
        SM2_CTX.verify(&message_hash_result, &new_pk, &parsed_sig)
    }

    fn generate_keypair(&self) -> (String, String) {
        let (pk, sk) = SM2_CTX.new_keypair();
        let pk_raw = SM2_CTX.serialize_pubkey(&pk, false);
        let sk_raw = SM2_CTX.serialize_seckey(&sk);

        let pk_str = utils::bytes_to_string(&pk_raw);
        let sk_str = utils::bytes_to_string(&sk_raw);
        (pk_str, sk_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SM2P256V1_TEST_SECRET_KEY: &str = "DSuhTJaEnZcJmPZN4JkpkIhADpT2pw5esjfOxiem8c0=";
    const SM2P256V1_TEST_PUBLIC_KEY: &str = "A16vukzFH4WAINU6RIkRM4fvm47xJNFzkLmNgJFBB7Gp";

    #[test]
    fn test_sm2p256v1() {
        // let pk_str = SM2P256V1_TEST_PUBLIC_KEY;
        // let sk_str = SM2P256V1_TEST_SECRET_KEY;

        for _ in 0..1000 {
            let message = "sm2 test".to_string();
            let signature = WeDPRSm2p256v1::default();
            let (pk_str, sk_str) = signature.generate_keypair();
            let sign = signature.sign(&sk_str, &message).unwrap();
            println!("sign = {}", sign);
            let result = signature.verify(&pk_str, &message, &sign);
            assert_eq!(result, true);
        }
    }
}
