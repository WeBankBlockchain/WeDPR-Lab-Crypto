use curve25519_dalek::{
    ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul,
};
use wedpr_l_crypto_zkp_utils::{
    get_random_scalar, point_to_bytes, BASEPOINT_G1,
};