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

use goblin::elf::dynamic::{tag_to_str, Dyn, Dynamic};
use goblin::elf::{header, program_header, Elf, ProgramHeader};
use goblin::strtab::Strtab;

use crate::check::{BinInfo, Checker, Features};
use crate::errors::{BinError, BinResult, ErrorKind};

/// specifies type of relocation read-only, which defines how dynamic relocations
/// are resolved as a security feature against GOT/PLT attacks.
#[derive(Serialize, Deserialize)]
pub enum Relro {
    FullRelro,
    PartialRelro,
    NoRelro,
}

/// encapsulates an ELF object from libgoblin, in order to parse it and dissect out the necessary
/// security mitigation features.
pub struct ElfChecker(Elf<'static>);

impl ElfChecker {
    /// parses and dissects out the necessary components for security feature detection given a
    /// valid ELF binary.
    pub fn new(binary: Elf<'static>) -> Self {
        Self(binary)
    }
}

impl Checker for ElfChecker {
    /// parses out basic binary information and stores it into the features mapping for consumption
    fn bin_info(&self) -> BinInfo {
        let header: header::Header = self.0.header;
        let file_class: &str = match header.e_ident[4] {
            1 => "ELF32",
            2 => "ELF64",
            _ => "unknown",
        };

        BinInfo {
            machine: header::machine_to_str(header.e_machine).to_string(),
            file_class: file_class.to_string(),
            bin_type: header::et_to_str(header.e_type).to_string(),
            entry_point: header.e_entry,
        }
    }

    fn harden_check(&self) -> Features {
        todo!()
    }
}
