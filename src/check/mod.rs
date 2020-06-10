//! Defines the checkers that can be used for their binary formats for their respective
//! platforms. Also implements the `Checker` trait, which is used to implement the functionality
//! needed to properly do all security mitigation detections per platform.

pub mod elf;
pub mod mach;
pub mod pe;

use std::boxed::Box;
use std::collections::BTreeMap;

// aliases a finalized output type for a detector, storing all the checks that
// were performed and their results.
pub type FeatureMap = BTreeMap<&'static str, serde_json::Value>;

/// trait to genericize basic information structs for binary formats.
pub trait BinInfo {
    /// generate a mapping given a checked set of features stored
    /// WIP: procedural macro for automatically convering structs to map types
    fn dump_mapping(&self) -> FeatureMap;
}

/// trait to genericize associative structs that can be de/serialized, holding features
/// for the specific format.
pub trait BinFeatures {
    /// generate a mapping given a checked set of features stored
    /// WIP: procedural macro for automatically convering structs to map types
    fn dump_mapping(&self) -> FeatureMap;
}

/// trait that is implemented in order to extend libgoblin's functionality to detect binary
/// security mitigations either through traditional hardening techniques.
pub trait Checker {
    /// parses out and returns basic binary information for more verbose user output.
    fn bin_info(&self) -> Box<dyn BinInfo>;

    /// defines the function be implemented in order to detect the standard binary hardening
    /// features usually enforced by the compiler.
    fn harden_check(&self) -> Box<dyn BinFeatures>;
}
