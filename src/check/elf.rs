//! Defines the `Elf` security mitigation detector. Consumes an
//! ELF binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit)
//! * Full/Partial RELRO
//! * Position-Independent Executable / ASLR
//! * Use of stack canaries
//! * (TODO) FORTIFY_SOURCE
//! * (TODO) SELinux
//! * (TODO) Runpath

use serde::{Deserialize, Serialize};

use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::elf::{header, program_header, Elf, ProgramHeader};

use crate::check::{Checker, Features};
use crate::errors::{BinError, BinResult, ErrorKind};

/// specifies type of relocation read-only, which defines how dynamic relocations
/// are resolved as a security feature against GOT/PLT attacks.
#[derive(Serialize, Deserialize)]
pub enum Relro {
    FullRelro,
    PartialRelro,
    NoRelro,
}

/// struct defining parsed basic information from ELF binary to be outputted and deserialized if
/// user chooses to.
#[derive(Default, Serialize, Deserialize)]
pub struct BinInfo {
    pub machine: String,
    pub file_class: String,
    pub bin_type: String,
    pub entry_point: u64,
}

/// struct defining security features parsed from ELF, and derives serde de/serialize traits
/// for structured output.
#[derive(Serialize, Deserialize)]
pub struct ElfChecker {
    elf: Elf
}

impl ElfChecker {
    pub fn new(binary: Elf) -> Self {
        Self(binary)
    }
}

impl Checker for ElfChecker {
    /// parses out basic binary information and stores it into the features mapping for consumption
    fn bin_info(&self) -> Features {

    }

    fn harden_check(&self) -> Features {
        todo!()
    }
}
