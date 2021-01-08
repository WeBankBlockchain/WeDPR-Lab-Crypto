// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! WeDPR constants definitions (used for testing only).

// IMPORTANT: We should avoid defining constants for non-testing purpose to
// achieve flexible code modularization.

/// Constants only used by tests.
pub mod tests {
    // Test key pair for secp256k1 algorithms.
    pub static SECP256K1_TEST_SECRET_KEY: [u8; 32] = [
        16, 193, 176, 126, 10, 106, 13, 5, 84, 177, 83, 187, 143, 21, 39, 137,
        35, 88, 197, 51, 227, 25, 198, 219, 127, 167, 162, 145, 160, 8, 42,
        136,
    ];
    pub static SECP256K1_TEST_PUBLIC_KEY: [u8; 33] = [
        2, 144, 107, 154, 77, 15, 31, 19, 233, 224, 73, 111, 158, 25, 102, 192,
        72, 128, 146, 85, 93, 13, 181, 254, 50, 39, 42, 48, 190, 125, 213, 224,
        182,
    ];

    // Test string for a base64 encoded message.
    pub static BASE64_ENCODED_TEST_MESSAGE: [u8; 32] = [
        131, 171, 11, 24, 188, 139, 190, 121, 14, 74, 240, 92, 65, 210, 141,
        72, 252, 124, 155, 133, 230, 2, 136, 46, 120, 211, 38, 19, 165, 116,
        33, 202,
    ];
}
