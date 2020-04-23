//! Constants shared by multiple suites.

/// Constants only used by tests.
#[allow(unused_imports)]
pub mod tests {
    // 10c1b07e0a6a0d0554b153bb8f1527892358c533e319c6db7fa7a291a0082a88
    #[allow(dead_code)]
    pub const TEST_SECRET_KEY: &str =
        "EMGwfgpqDQVUsVO7jxUniSNYxTPjGcbbf6eikaAIKog=";
    // 02906b9a4d0f1f13e9e0496f9e1966c0488092555d0db5fe32272a30be7dd5e0b6
    #[allow(dead_code)]
    pub const TEST_PUBLIC_KEY: &str =
        "ApBrmk0PHxPp4ElvnhlmwEiAklVdDbX+MicqML591eC2";

    #[allow(dead_code)]
    pub const JAVA_TEST_SECRET_KEY: &str =
        "LxaIuB6bmZWU8o1mEOVYewOhvWnGjHgH35EUTf+lnuU=";

    #[allow(dead_code)]
    pub const JAVA_TEST_PUBLIC_KEY: &str =
        "BFk8TkL06J3WkopsXPg8RoFVMFfR+2yHIQKbpRnhlGF2+mq2NxMws6Jdt5J+J/\
         JdNM2x8p+4W/OR746rbqrfhGI=";
}
