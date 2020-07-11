//! Defines the `Elf` security mitigation detector. Consumes an
//! ELF binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit) stack
//! * Stack Canaries
//! * FORTIFY_SOURCE
//! * Position-Independent Executable
//! * Full/Partial RELRO
//! * Runpath

use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::elf::{header, program_header, Elf, ProgramHeader};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::check::{Checker, FeatureCheck};
use crate::format::{BinTable, FeatureMap};

use std::boxed::Box;

/// defines basic information parsed out from an ELF binary
#[derive(Deserialize, Serialize, Default)]
pub struct ElfInfo {
    pub machine: String,
    pub file_class: String,
    pub bin_type: String,
    pub entry_point: u64,
}

// extend with trait to enable generic return in Checker trait implementation
#[typetag::serde]
impl FeatureCheck for ElfInfo {
    /// converts the checked security mitigations into an associative container for output
    /// consumption with a specific output format.
    fn output(&self) -> String {
        let mut features: FeatureMap = FeatureMap::new();
        features.insert("Architecture", json!(self.machine));
        features.insert("File Class", json!(self.file_class));
        features.insert("Binary Type", json!(self.bin_type));
        features.insert("Entry Point Address", json!(self.entry_point));
        BinTable::parse("Basic Information", features)
    }
}

/// specifies type of relocation read-only, which defines how dynamic relocations
/// are resolved as a security feature against GOT/PLT attacks.
#[derive(Deserialize, Serialize)]
pub enum Relro {
    FullRelro,
    PartialRelro,
    NoRelro,
}

impl ToString for Relro {
    fn to_string(&self) -> String {
        match self {
            Relro::FullRelro => "Full RELRO".to_string(),
            Relro::PartialRelro => "Partial RELRO".to_string(),
            Relro::NoRelro => "No RELRO".to_string(),
        }
    }
}

/// encapsulates an ELF object from libgoblin, in order to parse it and dissect out the necessary
/// security mitigation features.
#[derive(Deserialize, Serialize)]
struct ElfChecker {
    pub exec_stack: bool,
    pub stack_canary: bool,
    pub fortify_source: bool,
    pub pie: bool,
    pub relro: Relro,
    pub runpath: Vec<String>,
}

// extend with trait to enable generic return in Checker trait implementation, and provide
// facilities for dumping out as a genericized FeatureMap
#[typetag::serde]
impl FeatureCheck for ElfChecker {
    /// converts the checked security mitigations into an associative container for output
    /// consumption with a specific output format
    fn output(&self) -> String {
        let mut features: FeatureMap = FeatureMap::new();
        features.insert("Executable Stack (NX Bit)", json!(self.exec_stack));
        features.insert("Stack Canary", json!(self.stack_canary));
        features.insert("FORTIFY_SOURCE", json!(self.fortify_source));
        features.insert("Position-Independent Executable", json!(self.pie));
        features.insert(
            "Read-Only Relocatables (RELRO)",
            json!(self.relro.to_string()),
        );
        BinTable::parse("Binary Hardening Checks", features)
    }
}

impl Checker for Elf<'_> {
    /// parses out basic binary information and stores for consumption and output.
    fn bin_info(&self) -> Box<dyn FeatureCheck> {
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
    fn harden_check(&self) -> Box<dyn FeatureCheck> {
        // check for executable stack through program headers
        let exec_stack: bool = self
            .program_headers
            .iter()
            .any(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK" && ph.p_flags == 6);

        // check for stack canary
        let stack_canary: bool = self
            .dynsyms
            .iter()
            .filter_map(|sym| self.dynstrtab.get(sym.st_name))
            .any(|name| match name {
                Ok(e) => (e == "__stack_chk_fail"),
                _ => false,
            });

        // check for FORTIFY_SOURCE calls
        let fortify_source: bool = self
            .dynsyms
            .iter()
            .filter_map(|sym| self.dynstrtab.get(sym.st_name))
            .any(|name| match name {
                Ok(e) => e.ends_with("_chk"),
                _ => false,
            });

        // check for position-independent executable
        let pie: bool = match self.header.e_type {
            3 => true,
            _ => false,
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
            Some(_rh) => {
                // check for full/partial RELRO support by checking dynamic section for DT_BIND_NOW flag.
                // DT_BIND_NOW takes precedence over lazy binding and processes relocations before actual execution.
                if let Some(segs) = &self.dynamic {
                    let dyn_seg: Option<Dyn> = segs
                        .dyns
                        .iter()
                        .find(|tag| tag_to_str(tag.d_tag) == "DT_BIND_NOW")
                        .cloned();

                    if dyn_seg.is_some() {
                        relro = Relro::FullRelro;
                    } else {
                        relro = Relro::PartialRelro;
                    }
                }
            }
            None => {
                relro = Relro::NoRelro;
            }
        };

        Box::new(ElfChecker {
            exec_stack,
            stack_canary,
            fortify_source,
            pie,
            relro,
            runpath: Vec::new(),
        })
    }
}
