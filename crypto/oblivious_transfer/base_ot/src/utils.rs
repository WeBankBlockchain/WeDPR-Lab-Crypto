use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

lazy_static! {
    /// A base point used by various crypto algorithms.
    pub static ref BASEPOINT_G1: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
}

pub fn get_random_scalar() -> Scalar {
    let mut csprng = OsRng;
    Scalar::random(&mut csprng)
    // Scalar::random(&mut rand::thread_rng())
}


