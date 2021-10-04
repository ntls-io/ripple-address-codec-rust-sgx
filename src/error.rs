use std::prelude::v1::*;

use std::{error, fmt};

use Error::DecodeError;

/// Error type with a single DecodeError variant
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Error {
    /// Decoding error
    ///
    /// This error appears in various cases: bad alphabet,
    /// prefix, payload length or bad checksum.
    DecodeError,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError => f.write_str("decode error"),
        }
    }
}

macro_rules! impl_from_error {
    ($t:ty => $m:ident) => {
        #[doc(hidden)]
        impl From<$t> for Error {
            fn from(_: $t) -> Self {
                $m
            }
        }
    };
}

impl_from_error!(base_x::DecodeError => DecodeError);
