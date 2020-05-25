//! Defines the error type used throughout both the library crate
//! and the main command-line application when encountering exceptions.

use std::fmt::{self, Display};
use std::error::Error;

// type alias for a Result that encapsulates a BinError
pub type BinResult<R> = Result<R, BinError>;


/// Defines the error variants that can be encountered when executing.
#[derive(Debug)]
pub enum ErrorKind {
    ParseError,
    BinaryError,
    FileError,
    DumpError
}


/// Defines the main error type used for any exception that occurs.
#[derive(Debug)]
pub struct BinError {
    kind: ErrorKind,
    msg: String
}

impl Display for BinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f,"{}: {}", self.kind, self.msg)
    }
}

impl Error for BinError {}
