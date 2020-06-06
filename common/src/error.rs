//! WeDPR errors definitions.

#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum WedprError {
    #[fail(display = "verification failed.")]
    VerificationError,
    #[fail(display = "data could not be parsed.")]
    FormatError,
    #[fail(display = "data could not be decoded.")]
    DecodeError,
}
