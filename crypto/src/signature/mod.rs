pub mod secp256k1;
pub mod sm2;

use common::error::WedprError;

#[derive(Default, Debug, Clone)]
pub struct WeDPRSecp256k1 {}

#[derive(Default, Debug, Clone)]
pub struct WeDPRSecp256k1Recover {}

#[derive(Default, Debug, Clone)]
pub struct WeDPRSm2p256v1 {}

pub trait Signature {
    fn sign(&self, private_key: &str, msg: &str) -> Result<String, WedprError>;
    fn sign_with_pub(
        &self,
        private_key: &str,
        public_key: &str,
        msg: &str,
    ) -> Result<String, WedprError>;
    fn verify(&self, public_key: &str, msg: &str, signature: &str) -> bool;
    fn generate_keypair(&self) -> (String, String);
}
