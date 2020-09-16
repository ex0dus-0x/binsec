//! Defines the checkers that can be used for their binary formats for their respective
//! platforms. Also implements the `Checker` trait, which is used to implement the functionality
//! needed to properly do all security mitigation detections per platform.

pub mod elf;
pub mod kernel;
pub mod mach;
pub mod pe;

use std::collections::HashMap;

/// trait that is implemented in order to extend libgoblin's functionality to detect binary
/// security mitigations either through traditional hardening techniques.
pub trait Checker {
    /// parses out and returns basic binary information for more verbose user output.
    fn bin_info(&self) -> HashMap<String, String>;

    /// defines the function be implemented in order to detect the standard binary hardening
    /// features usually enforced by the compiler.
    fn harden_check(&self) -> HashMap<String, String>;
}
