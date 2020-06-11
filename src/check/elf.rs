//! Defines the `Elf` security mitigation detector. Consumes an
//! ELF binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit)
//! * Full/Partial RELRO
//! * Position-Independent Executable / ASLR
//! * Use of stack canaries
//! * (TODO) FORTIFY_SOURCE
//! * (TODO) Runpath

use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::elf::{header, program_header, Elf, ProgramHeader};

use serde_json::{json, Value};

use crate::check::{BinFeatures, BinInfo, Checker, FeatureMap};

use std::boxed::Box;

/// struct defining parsed basic information from any binary to be outputted and deserialized if
/// user chooses to.
#[derive(Default)]
pub struct ElfInfo {
    pub machine: String,
    pub file_class: String,
    pub bin_type: String,
    pub entry_point: u64,
}

// extend with trait to enable generic return in Checker trait implementation
impl BinInfo for ElfInfo {
    /// converts the checked security mitigations into an associative container for output
    /// consumption with a specific output format
    fn dump_mapping(&self) -> FeatureMap {
        let mut features: FeatureMap = FeatureMap::new();
        features.insert("Architecture", json!(self.machine));
        features.insert("File Class", json!(self.file_class));
        features.insert("Binary Type", json!(self.bin_type));
        features.insert("Entry Point Address", json!(self.entry_point));
        features
    }
}

/// specifies type of relocation read-only, which defines how dynamic relocations
/// are resolved as a security feature against GOT/PLT attacks.
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
struct ElfChecker {
    pub exec_stack: bool,
    pub stack_canary: bool,
    pub pie: bool,
    pub relro: Relro,
}

// extend with trait to enable generic return in Checker trait implementation, and provide
// facilities for dumping out as a genericized FeatureMap
impl BinFeatures for ElfChecker {
    /// converts the checked security mitigations into an associative container for output
    /// consumption with a specific output format
    fn dump_mapping(&self) -> FeatureMap {
        let mut features: FeatureMap = FeatureMap::new();
        features.insert("Executable Stack (NX Bit)", Value::Bool(self.exec_stack));
        features.insert("Stack Canaries", Value::Bool(self.stack_canary));
        features.insert("Position-Independent Executable", Value::Bool(self.pie));
        features.insert(
            "Read-Only Relocatables (RELRO)",
            Value::String(self.relro.to_string()),
        );
        features
    }
}

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
                    } else {
                        relro = Relro::PartialRelro;
                    }
                }
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
