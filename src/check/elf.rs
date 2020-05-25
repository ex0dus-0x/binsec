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

#[cfg(target_pointer_width = "64")]
use goblin::elf64 as elf;

#[cfg(target_pointer_width = "32")]
use goblin::elf32 as elf;

use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::elf::{header, program_header, ProgramHeader};

use crate::errors::{BinError, BinResult};

/// specifies type of relocation read-only, which defines how dynamic
/// relocations are resolved as a security feature against GOT/PLT attacks.
#[derive(Serialize, Deserialize)]
pub enum Relro {
    FullRelro,
    PartialRelro,
    NoRelro,
}

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
pub struct ElfChecker {
    pub exec_stack: bool,
    pub stack_canary: bool,
    pub pie: bool,
    pub relro: Relro,
}
