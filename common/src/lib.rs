// Increase recursion limit to allow for use of select! macro.
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate wedpr_macros;

pub mod constant;
pub mod error;
pub mod utils;
