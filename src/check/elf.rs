//! Defines the `Elf` security mitigation detector. Consumes an
//! ELF binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit)
//! * Full/Partial RELRO
//! * Position-Independent Executable / ASLR
//! * Use of stack canaries
//! * (TODO) FORTIFY_SOURCE
//! * (TODO) Runpath

use goblin::elf::dynamic::{tag_to_str, Dyn, Dynamic};
use goblin::elf::{header, program_header, Elf, ProgramHeader};
use goblin::strtab::Strtab;

use crate::check::{BinInfo, Checker, Features};
use crate::errors::{BinError, BinResult, ErrorKind};

use std::collections::BTreeMap;

/// specifies type of relocation read-only, which defines how dynamic relocations
/// are resolved as a security feature against GOT/PLT attacks.
pub enum Relro {
    FullRelro,
    PartialRelro,
    NoRelro,
}

/// encapsulates an ELF object from libgoblin, in order to parse it and dissect out the necessary
/// security mitigation features.
pub struct ElfChecker {
    binary: Elf<'static>,
    features: Features
}

impl ElfChecker {
    pub fn new(elf: Elf<'static>) -> Self {
        Self {
            binary: elf,
            features: Features::new()
        }
    }
}


impl Checker for ElfChecker {

    /// parses out basic binary information and stores it into the BinInfo mapping for later
    /// consumption and display.
    fn bin_info(&self) -> BinInfo {
        let header: header::Header = self.binary.header;
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

    /// implements the necesary checks for the security mitigations for the specific file format.
    fn harden_check(&mut self) {

        // initialize a features mapping for binary hardening checks
        let mut features: BTreeMap<&'static str, bool> = BTreeMap::new();

        // non-exec stack: NX bit is set when GNU_STACK is read/write
        let stack_header: Option<ProgramHeader> = self.binary
            .program_headers
            .iter()
            .find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK")
            .cloned();

        if let Some(sh) = stack_header {
            if sh.p_flags == 6 {
                features.insert("Executable Stack", true);
            }
        }

		// check for stack canary
        let strtab = self.binary.strtab.to_vec().unwrap();
        let str_sym: Option<_> = strtab
            .iter()
            .find(|sym| sym.contains("__stack_chk_fail"))
            .cloned();

        if str_sym.is_some() {
            features.insert("Stack Canary", true);
        }

        // check for position-independent executable
        let e_type = self.binary.header.e_type;
        match e_type {
            3 => {
                features.insert("Position-Independent Executable", true);
            }
            _ => {
                features.insert("Position-Independent Executable", false);
            }
        }

        // RELRO
        self.features.insert("Binary Hardening", features);
    }
}
