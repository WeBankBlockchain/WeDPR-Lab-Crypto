// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Tool to compile proto files to rust files.

extern crate protobuf_codegen;
use protobuf_codegen::{Codegen, Customize};
use std::env;

/// Uses `cargo run` in this sub crate (wedpr_l_protos) to compile proto files
/// to rust files. You need to update the generated files every time you modify
/// the existing proto files or add new proto files.
#[cfg(not(tarpaulin_include))]
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        generate_proto_for_all();
    } else {
        // TODO: Add more control on compiling proto files to rust files.
    }
}

/// Compiles proto files to rust files.
#[cfg(not(tarpaulin_include))]
fn generate_proto_for_all() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    Codegen::new()
        .pure()
        .out_dir(root.join("src/generated"))
        .include(root)
        // List all used proto files here.
        // You can remove any proto files that are not used by your project.
        .input(root.join("crypto/common.proto"))
        .customize(Customize::default().generate_accessors(true))
        .run()
        .expect("protoc should not fail");
}
