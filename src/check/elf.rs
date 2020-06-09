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

use serde::{Deserialize, Serialize};

use crate::check::{BinFeatures, BinInfo, Checker};
use crate::errors::{BinError, BinResult, ErrorKind};

use std::boxed::Box;

/// struct defining parsed basic information from any binary to be outputted and deserialized if
/// user chooses to.
#[derive(Serialize, Deserialize, Default)]
pub struct ElfInfo {
    pub machine: String,
    pub file_class: String,
    pub bin_type: String,
    pub entry_point: u64,
}

// extend with empty trait to enable generic return in Checker trait implementation
impl BinInfo for ElfInfo {}

/// encapsulates an ELF object from libgoblin, in order to parse it and dissect out the necessary
/// security mitigation features.
#[derive(Serialize, Deserialize)]
struct ElfChecker {
    pub exec_stack: bool,
    pub stack_canary: bool,
    pub pie: bool,
    pub relro: Relro,
}

/// specifies type of relocation read-only, which defines how dynamic relocations
/// are resolved as a security feature against GOT/PLT attacks.
#[derive(Serialize, Deserialize)]
pub enum Relro {
    FullRelro,
    PartialRelro,
    NoRelro,
}

// extend with empty trait to enable generic return in Checker trait implementation
impl BinFeatures for ElfChecker {}

impl Checker for Elf<'_> {
    /// parses out basic binary information and stores it into the BinInfo mapping for later
    /// consumption and display.
    fn bin_info(&self) -> Box<dyn BinInfo> {
        let header: header::Header = self.header;
        let file_class: &str = match header.e_ident[4] {
            1 => "ELF32",
            2 => "ELF64",
            _ => "unknown",
        };

        Box::new(ElfInfo {
            machine: header::machine_to_str(header.e_machine).to_string(),
            file_class: file_class.to_string(),
            bin_type: header::et_to_str(header.e_type).to_string(),
            entry_point: header.e_entry,
        })
    }

    /// implements the necesary checks for the security mitigations for the specific file format.
    fn harden_check(&self) -> Box<dyn BinFeatures> {
        // non-exec stack: NX bit is set when GNU_STACK is read/write
        let stack_header: Option<ProgramHeader> = self
            .program_headers
            .iter()
            .find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK")
            .cloned();

        let exec_stack: bool = match stack_header {
            Some(sh) => sh.p_flags == 6,
            None => false,
        };

        // check for RELRO
        let relro_header: Option<ProgramHeader> = self
            .program_headers
            .iter()
            .find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_RELRO")
            .cloned();

        // TODO: make functional or get rid of nested bullshit
        let mut relro: Relro = Relro::NoRelro;
        match relro_header {
            Some(rh) => {
                // check for full/partial RELRO support by checking dynamic section for DT_BIND_NOW flag.
                // DT_BIND_NOW takes precedence over lazy binding and processes relocations before actual execution.
                if let Some(segs) = &self.dynamic {
                    let dyn_seg: Option<Dyn> = segs
                        .dyns
                        .iter()
                        .find(|tag| tag_to_str(tag.d_tag) == "DT_BIND_NOW")
                        .cloned();

                    if !dyn_seg.is_none() {
                        relro = Relro::FullRelro;
                    }
                }
                relro = Relro::PartialRelro;
            }
            None => {
                relro = Relro::NoRelro;
            }
        };

        // check for stack canary
        let strtab = self.strtab.to_vec().unwrap();
        let str_sym: Option<_> = strtab
            .iter()
            .find(|sym| sym.contains("__stack_chk_fail"))
            .cloned();

        let stack_canary: bool = str_sym.is_some();

        // check for position-independent executable
        let pie: bool = {
            let e_type = self.header.e_type;
            match e_type {
                3 => true,
                _ => false,
            }
        };

        Box::new(ElfChecker {
            exec_stack,
            stack_canary,
            pie,
            relro,
        })
    }
}
