use super::WeDPRSecp256k1;
use super::WeDPRSecp256k1Recover;

use super::Signature;
use crate::hash::keccak256;
use common::constant::{SECP256K1_OBJ, SECP256K1_VERIFY};
use common::error::WedprError;
use common::utils;
use rand;

use secp256k1::{
    recovery::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1, SecretKey, Signature as Secp256k1Signature,
};

macro_rules! crate_string_to_point {
    ($param:expr) => {
        match utils::string_to_point($param) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("macro string_to_point failed");
                return false;
            }
        }
    };
}

macro_rules! crate_string_to_scalar {
    ($param:expr) => {
        match utils::string_to_scalar($param) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("macro string_to_scalar failed");
                return false;
            }
        }
    };
}

macro_rules! crate_string_to_bytes {
    ($param:expr) => {
        match utils::string_to_bytes($param) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("macro string_to_bytes failed");
                return false;
            }
        }
    };
}

impl Signature for WeDPRSecp256k1Recover {
    fn sign(&self, private_key: &str, msg: &str) -> Result<String, WedprError> {
        let msg_hash = keccak256(msg.as_bytes());
        let sk_str_bytes = utils::string_to_bytes(private_key)?;
        let secret_key = match SecretKey::from_slice(&sk_str_bytes) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("get private key failed");
                return Err(WedprError::FormatError);
            }
        };
        let message_send = Message::from_slice(&msg_hash).expect("32 bytes");
        let sig = SECP256K1_OBJ.sign_recoverable(&message_send, &secret_key);
        let (recid, signature_bytes) = &sig.serialize_compact();
        //        let siganture_result = signature_bytes.as_mut_slice();
        let mut vec_sig = signature_bytes.to_vec();
        vec_sig.push(recid.to_i32() as u8);
        Ok(utils::bytes_to_string(&vec_sig))
    }

    fn verify(&self, public_key: &str, msg: &str, signature: &str) -> bool {
        let msg_hash = keccak256(msg.as_bytes());
        let message_receive = Message::from_slice(&msg_hash).expect("32 bytes");
        let pk_str_bytes = crate_string_to_bytes!(&public_key);
        let pub_str_get = match PublicKey::from_slice(&pk_str_bytes) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("parse public key to failed");
                return false;
            }
        };
        let sig_result_hex = crate_string_to_bytes!(signature);
        if sig_result_hex.len() != 65 {
            wedpr_println!("sigature length is not 65!");
            return false;
        };
        let recid = match RecoveryId::from_i32(sig_result_hex[64] as i32) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("parse RecoveryId failed");
                return false;
            }
        };
        let signature_byte = &sig_result_hex[0..64];

        let get_sign_final = match RecoverableSignature::from_compact(signature_byte, recid) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("signature from_compact failed");
                return false;
            }
        };
        let pk_recover_get = match SECP256K1_VERIFY.recover(&message_receive, &get_sign_final) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("signature recover failed");
                return false;
            }
        };
        if pub_str_get != pk_recover_get {
            wedpr_println!("signature recover failed");
            return false;
        }
        return true;
    }

    fn generate_keypair(&self) -> (String, String) {
        let mut rng = rand::thread_rng();
        let secp = secp256k1::Secp256k1::new();
        //        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
//        let mut secret_key: SecretKey = SecretKey::new();
//        let mut public_key: PublicKey = PublicKey::;
        loop {
            let (secret_key, public_key) = SECP256K1_OBJ.generate_keypair(&mut rng);
            if secret_key[0] > 15 {
                return (utils::bytes_to_string(&public_key.serialize_uncompressed().to_vec()),
                secret_key.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_WeDPRSecp256k1_keypair() {
        let signature = WeDPRSecp256k1Recover::default();
        let message = "To Rust";
        for _ in 0..100 {
            let (pk, sk) = signature.generate_keypair();
            println!("pk = {}", pk);
            println!("sk = {}", sk);

        }
//
//        let sign = signature.sign(&sk, message).unwrap();
//
//        let result = signature.verify(&pk, message, &sign);
//        assert_eq!(result, true);
    }

    #[test]
    fn test_WeDPRSecp256k1Recover() {
        let signature = WeDPRSecp256k1Recover::default();
        let message = "847adcf9b24cf0041ddff02ffe324e30b1271c5170086f8ee799dd1123dacb2e";

        //        let sk = "9f523428ae7527d8d279d859eff4d63764e0073bf981e7e06005f0962634242d";
        let pk = "04c7d3781f5708f11d1f4c26499ca909262fde9bfe10959e4f294d51d3de141fce4cb29cb52ae07753488dd7a1460eff2e223d68cb6bf2ffc4b07f6013aa8a06f5";
        let sign = "98e56e60d738e4c848b0384022a4191e1c89075c08a63216659573d4f47d16aa432d57e5cb2c434fa12be13243d8ac8e14d4bc716557f74af69ccc097a0c95f401";
        let result = signature.verify(pk, message, sign);
        assert_eq!(result, true);
    }
}
