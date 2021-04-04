//! Custom error type for all errors types that binsec might encounter
use std::error::Error;
use std::fmt::{self, Display};

pub type BinResult<R> = Result<R, BinError>;

#[derive(Debug)]
pub struct BinError(String);

impl BinError {
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

impl Display for BinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self.0)
    }
}

impl From<std::io::Error> for BinError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<goblin::error::Error> for BinError {
    fn from(error: goblin::error::Error) -> Self {
        Self(error.to_string())
    }
}

impl Error for BinError {}
