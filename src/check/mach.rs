//! Defines the `Mach` security mitigation checker. Consumes an
//! Mach-O binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit)
//! * Full/Partial RELRO
//! * Position-Independent Executable / ASLR

use serde::{Deserialize, Serialize};

use goblin::mach::MachO;

use crate::check::{Checker, Features};
use crate::errors::{BinError, BinResult};

/// struct defining parsed basic information from ELF binary
/// to be outputted and deserialized if user chooses to.
#[derive(Default, Serialize, Deserialize)]
pub struct BinInfo {
    pub machine: String,
    pub file_class: String,
    pub bin_type: String,
    pub entry_point: u64,
}

/// struct defining security features parsed from ELF, and
/// derives serde de/serialize traits for structured output.
#[derive(Serialize, Deserialize)]
pub struct MachChecker(MachO<'static>);

impl MachChecker {
    pub fn new(mach: MachO) -> Self {
        Self(mach)
    }
}

impl Checker for MachChecker {
    fn bin_info(&self) -> Features {
        todo!()
    }

    fn harden_check(&self) -> Features {
        todo!()
    }
}
