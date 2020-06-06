use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use libsm::sm2::signature::SigCtx;
use secp256k1::{All, Secp256k1, VerifyOnly};

lazy_static! {
    pub static ref G1_BASEPOINT: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
    pub static ref SECP256K1_VERIFY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
    pub static ref SM2_CTX: SigCtx = SigCtx::new();
    pub static ref SECP256K1_OBJ: Secp256k1<All> = Secp256k1::new();
}

pub const RISTRETTO_POINT_SIZE_IN_BYTES: usize = 32;
