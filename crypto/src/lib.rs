#[macro_use]
extern crate wedpr_macros;

pub mod curve_25519_vrf;
pub mod hash;
pub mod signature;
mod utils;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
