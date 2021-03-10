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
        // let msg_hash = keccak256(msg.as_bytes());
        let msg_hash = utils::string_to_bytes(msg)?;
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
        let mut vec_sig = signature_bytes.to_vec();
        vec_sig.push(recid.to_i32() as u8);
        Ok(utils::bytes_to_string(&vec_sig))
    }

    fn sign_with_pub(
        &self,
        private_key: &str,
        public_key: &str,
        msg: &str,
    ) -> Result<String, WedprError> {
        Err(WedprError::VerificationError)
    }

    fn verify(&self, public_key: &str, msg: &str, signature: &str) -> bool {
        let msg_hash = match utils::string_to_bytes(msg) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("msg_hash parser failed");
                return false;
            }
        };
        // let msg_hash = keccak256(msg.as_bytes());
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
        loop {
            // let secp = secp256k1::Secp256k1::new();
            let mut rng = try_generate_seed();
            let (secret_key, public_key) = SECP256K1_OBJ.generate_keypair(&mut rng);
            if secret_key[0] > 15 {
                return (
                    utils::bytes_to_string(&public_key.serialize_uncompressed().to_vec()),
                    secret_key.to_string(),
                );
            }
        }
    }
}

fn try_generate_seed() -> rand::rngs::OsRng {
    loop {
        match rand::rngs::OsRng::new() {
            Ok(v) => return v,
            Err(_) => continue,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_WeDPRSecp256k1_keypair() {
        let signature = WeDPRSecp256k1Recover::default();
        let message = "44DB476208775A0E5DBD7C00D08833A7083E232DFA95788E2EC7CC231772C23A";
        // for _ in 0..100 {
        let (pk, sk) = signature.generate_keypair();
        println!("pk = {}", pk);
        println!("sk = {}", sk);

        // }

        let sign = signature.sign(&sk, message).unwrap();
        println!("sign = {}", sign);

        let result = signature.verify(&pk, message, &sign);
        assert_eq!(result, true);
    }

    #[test]
    fn test_WeDPRSecp256k1Recover() {
        let signature = WeDPRSecp256k1Recover::default();
        let message = "44db476208775a0e5dbd7c00d08833a7083e232dfa95788e2ec7cc231772c23a";

        //        let sk = "9f523428ae7527d8d279d859eff4d63764e0073bf981e7e06005f0962634242d";
        let pk = "04a402d163b2a4606a4ac321bd3ccdd51cb3b8f688948c46115d38bf93f03336578bdb6eb238109d3f1ac68bd59c98e6b9439672f3facb8fa18bb8de70fb357fa9";
        let sign = "9fc3a2361155faa0e0ae91245d15e48b6caed95d3cf3ffd11bf87a54c9e85ff34405ff8fe205a561a7a1fe1c0ca8de3949ceb3bfe9347aae0da6d7c4ce05a9e000";
        let result = signature.verify(pk, message, sign);
        assert_eq!(result, true);
    }
}
