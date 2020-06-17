//! Defines the error type used throughout both the library crate
//! and the main command-line application when encountering exceptions.

use std::error::Error;
use std::fmt::{self, Display};

// type alias for a Result that encapsulates a BinError
pub type BinResult<R> = Result<R, BinError>;

/// Defines the error variants that can be encountered when executing.
#[derive(Debug)]
pub enum ErrorKind {
    ParseError,
    BinaryError,
    RuleEngineError,
    FileError,
    DumpError,
}

/// Defines the main error type used for any exception that occurs.
#[derive(Debug)]
pub struct BinError {
    pub kind: ErrorKind,
    pub msg: String,
}

impl Display for BinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:?}: {}", self.kind, self.msg)
    }
}

impl From<std::io::Error> for BinError {
    fn from(error: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::FileError,
            msg: error.to_string(),
        }
    }
}

impl From<goblin::error::Error> for BinError {
    fn from(error: goblin::error::Error) -> Self {
        Self {
            kind: ErrorKind::BinaryError,
            msg: error.to_string(),
        }
    }
}

impl Error for BinError {}
