pub mod elf;
pub mod kernel;
pub mod mach;
pub mod pe;

use crate::format::FeatureMap;

/// Trait that is implemented on top of
pub trait Checker {
    fn bin_info(&self) -> FeatureMap;
    fn harden_check(&self) -> FeatureMap;
}
