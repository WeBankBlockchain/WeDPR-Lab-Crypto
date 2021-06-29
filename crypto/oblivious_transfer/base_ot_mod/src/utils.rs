use num_bigint::{BigUint, RandBigInt};
use rand;

pub fn get_random_biguint() -> BigUint {
    rand::thread_rng().gen_biguint(2047)
}