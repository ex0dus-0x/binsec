//! Library interface for binsec static detection functionality.
//! Implements the deserializable components for output/file IO, and
//! the main detection interface for parsing the binary for features to output.

pub mod check;
pub mod detect;
pub mod errors;
pub mod format;
pub mod rule_engine;
