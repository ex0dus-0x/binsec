pub mod elf;
pub mod mach;
pub mod pe;

use crate::format::FeatureMap;

/// Trait that is implemented on top of
pub trait Checker {
    fn harden_check(&self) -> FeatureMap;
}
