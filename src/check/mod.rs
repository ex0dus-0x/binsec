//! Defines the checkers that can be used for their binary formats for their respective
//! platforms. Also implements the `Checker` trait, which is used to implement the functionality
//! needed to properly do all security mitigation detections per platform.

pub mod elf;
pub mod mach;
pub mod pe;

use std::collections::BTreeMap;
use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

// type alias for detecting features
pub type Features = BTreeMap<&'static str, BTreeMap<&'static str, bool>>;

/// struct defining parsed basic information from any binary to be outputted and deserialized if
/// user chooses to.
pub struct BinInfo {
    pub machine: String,
    pub file_class: String,
    pub bin_type: String,
    pub entry_point: u64,
}

pub trait Checker {

    /// parses out and returns basic binary information for more verbose user output.
    fn bin_info(&self) -> BinInfo;

    /// defines the function be implemented in order to detect the standard binary hardening
    /// features usually enforced by the compiler.
    fn harden_check(&mut self) -> ();

    /// defines checks that determine security features configured on the kernel that the
    /// binary is running on.
    fn kernel_check(&mut self) -> () {
        todo!()
    }

    /// runs the custom set of YARA-based rules against the specific binary. This is
    /// default across all formats, as the rules are built to include cases for all formats.
    fn rule_check(&mut self) -> () {
        todo!()
    }
}
