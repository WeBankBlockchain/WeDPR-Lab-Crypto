// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! WeDPR errors definitions.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WedprError {
    VerificationError,
    ArgumentError,
    FormatError,
    DecodeError,
    IndyCryptoError,
}

impl std::fmt::Display for WedprError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::VerificationError => "Verification failed",
            Self::ArgumentError => "Argument is invalid",
            Self::FormatError => "Data cannot be parsed",
            Self::DecodeError => "Data cannot be decoded",
            Self::IndyCryptoError => "Indy Crypto error",
        })
    }
}

impl std::error::Error for WedprError {}
