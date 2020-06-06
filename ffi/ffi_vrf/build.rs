extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(v) => v,
        Err(_) => return (),
    };

    let write_to_file = match cbindgen::Builder::new().with_crate(crate_dir).generate() {
        Ok(v) => v,
        Err(_) => return (),
    };
    write_to_file.write_to_file("cpp/ffi_vrf.h");
}
