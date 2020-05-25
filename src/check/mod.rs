//! Defines the checkers that can be used for their binary formats for their respective
//! platforms. Also implements the `Checker` trait, which is used to implement the functionality
//! needed to properly do all security mitigation detections per platform.

pub mod elf;
pub mod pe;
pub mod mach;

use std::collections::BTreeMap;

// type alias for detecting features
type Features = BTreeMap<String, bool>;


pub trait Checker {

    /// parses out and returns basic binary information for more verbose
    /// user output
    fn bin_info(&self) -> Features;

    /// defines the function be implemented in order to detect the
    /// standard binary hardening features usually enforced by the compiler.
    fn harden_check(&self) -> Features;

    /// defines checks that determine security features configured on the kernel that the
    /// binary is running on.
    fn kernel_check(&self) -> Features;

    /// runs the custom set of YARA-based rules against the specific binary. This is
    /// default across all formats, as the rules are built to include cases for all formats.
    fn rule_check(&self) -> Features;
}
