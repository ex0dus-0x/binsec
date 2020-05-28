//! Defines the `Mach` security mitigation checker. Consumes an
//! Mach-O binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit)
//! * Full/Partial RELRO
//! * Position-Independent Executable / ASLR

use serde::{Deserialize, Serialize};

use goblin::mach::MachO;

use crate::check::{BinInfo, Checker, Features};
use crate::errors::{BinError, BinResult};

/// struct defining security features parsed from ELF, and
/// derives serde de/serialize traits for structured output.
#[derive(Serialize, Deserialize)]
pub struct MachChecker;

impl MachChecker {
    pub fn new(mach: MachO) -> Self {
        todo!()
    }
}

impl Checker for MachChecker {
    fn bin_info(&self) -> BinInfo {
        todo!()
    }

    fn harden_check(&self) -> Features {
        todo!()
    }
}