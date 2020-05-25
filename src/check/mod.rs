//! Defines the checkers that can be used for their binary formats for their respective
//! platforms. Also implements the `Checker` trait, which is used to implement the functionality
//! needed to properly do all security mitigation detections per platform.

pub mod elf;
pub mod pe;
pub mod mach;

use std::collections::BTreeMap;

// type alias for detecting features
type Features = BTreeMap<String, bool>>

pub trait Checker {
    fn new(binary: goblin::Object) -> Self;
    fn harden_check(&self) -> Features;
}
