//! Defines the checkers that can be used for their binary formats for their respective
//! platforms. Also implements the `Checker` trait, which is used to implement the functionality
//! needed to properly do all security mitigation detections per platform.

pub mod elf;
pub mod kernel;
pub mod mach;
pub mod pe;

use std::boxed::Box;

/// trait to genericize associative structs that store information, which can be de/serialized and
/// can also dump out an output with all of its attributes.
#[typetag::serde(tag = "type")]
pub trait FeatureCheck {
    /// generate an output for display given a checked set of features stored
    /// WIP: procedural macro for automatically converting structs to map types
    fn output(&self) -> String;
}

/// trait that is implemented in order to extend libgoblin's functionality to detect binary
/// security mitigations either through traditional hardening techniques.
pub trait Checker {
    /// parses out and returns basic binary information for more verbose user output.
    fn bin_info(&self) -> Box<dyn FeatureCheck>;

    /// defines the function be implemented in order to detect the standard binary hardening
    /// features usually enforced by the compiler.
    fn harden_check(&self) -> Box<dyn FeatureCheck>;
}
