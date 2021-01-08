//! Defines the `Elf` security mitigation detector. Consumes an
//! ELF binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit) stack
//! * Stack Canaries
//! * FORTIFY_SOURCE
//! * Position-Independent Executable / ASLR
//! * Full/Partial RELRO
//! * Runpath
//! * Address Sanitizer
//! * Undefined Behavior Sanitizer

use goblin::elf::dynamic::{tag_to_str, Dyn, DT_RUNPATH};
use goblin::elf::{header, program_header, Elf, ProgramHeader};

use serde::{Deserialize, Serialize};

use structmap::value::Value;
use structmap::ToHashMap;
use structmap_derive::ToHashMap;

use crate::check::Checker;
use crate::format::FeatureMap;

/// Defines basic information parsed out from an ELF binary
#[derive(Deserialize, Serialize, ToHashMap, Default)]
pub struct ElfInfo {
    #[rename(name = "Architecture")]
    pub machine: String,

    #[rename(name = "File Class")]
    pub file_class: String,

    #[rename(name = "Binary Type")]
    pub bin_type: String,

    #[rename(name = "Entry Point Address")]
    pub entry_point: u32,
}

/// Encapsulates an ELF object from libgoblin, in order to parse it and dissect out the necessary
/// security mitigation features.
#[derive(Deserialize, Serialize, ToHashMap)]
struct ElfChecker {
    // Executable stack
    #[rename(name = "Executable Stack (NX Bit)")]
    pub exec_stack: bool,

    // Use of stack canary
    #[rename(name = "Executable Stack (NX Bit)")]
    pub stack_canary: bool,

    // Position Independent Executable
    #[rename(name = "Position Independent Executable / ASLR")]
    pub pie: bool,

    // Read-Only Relocatable
    #[rename(name = "Read-Only Relocatable")]
    pub relro: String,

    // FORTIFY_SOURCE
    #[rename(name = "FORTIFY_SOURCE")]
    pub fortify_source: bool,

    // Runpath
    #[rename(name = "Runpath")]
    pub runpath: Vec<String>,

    // Address Sanitizer
    #[rename(name = "ASan")]
    pub asan: bool,

    // Undefined Behavior Sanitizer
    #[rename(name = "UBSan")]
    pub ubsan: bool,
}

impl Default for ElfChecker {
    fn default() -> Self {
        Self {
            exec_stack: false,
            stack_canary: false,
            pie: false,
            relro: String::new(),
            fortify_source: false,
            runpath: Vec::new(),
            asan: false,
            ubsan: false,
        }
    }
}

impl Checker for Elf<'_> {
    /// Parses out basic binary information and stores for consumption and output.
    fn bin_info(&self) -> FeatureMap {
        let header: header::Header = self.header;
        let file_class: &str = match header.e_ident[4] {
            1 => "ELF32",
            2 => "ELF64",
            _ => "unknown",
        };

        let info: ElfInfo = ElfInfo {
            machine: header::machine_to_str(header.e_machine).to_string(),
            file_class: file_class.to_string(),
            bin_type: header::et_to_str(header.e_type).to_string(),
            entry_point: header.e_entry as u32,
        };
        ElfInfo::to_hashmap(info)
    }

    /// Implements the necesary checks for the security mitigations for the specific file format.
    fn harden_check(&self) -> FeatureMap {
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

        // check for ASan calls
        let asan: bool = self
            .dynsyms
            .iter()
            .filter_map(|sym| self.dynstrtab.get(sym.st_name))
            .any(|name| match name {
                Ok(e) => e.starts_with("__asan"),
                _ => false,
            });

        // check for UBSan calls
        let ubsan: bool = self
            .dynsyms
            .iter()
            .filter_map(|sym| self.dynstrtab.get(sym.st_name))
            .any(|name| match name {
                Ok(e) => e.starts_with("__ubsan"),
                _ => false,
            });

        // check for position-independent executable
        let pie: bool = matches!(self.header.e_type, 3);

        // check for RELRO
        let relro_header: Option<ProgramHeader> = self
            .program_headers
            .iter()
            .find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_RELRO")
            .cloned();

        // check for full or partial RELRO
        let mut relro: String = String::new();
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
                        relro = "FULL".to_string();
                    } else {
                        relro = "PARTIAL".to_string();
                    }
                }
            }
            None => {
                relro = "NONE".to_string();
            }
        };

        // get paths specified in DT_RUNPATH
        let runpath: Vec<String> = match &self.dynamic {
            Some(dynamic) => {
                let mut res_vec: Vec<String> = vec![];
                for dy in &dynamic.dyns {
                    if dy.d_tag == DT_RUNPATH {
                        let val = self.dynstrtab.get(dy.d_val as usize);
                        if let Some(Ok(name)) = val {
                            res_vec = name.split(':').map(|x| x.to_string()).collect();
                        }
                    }
                }
                res_vec
            }
            None => vec![],
        };

        let checker: ElfChecker = ElfChecker {
            exec_stack,
            stack_canary,
            fortify_source,
            pie,
            relro,
            runpath,
            asan,
            ubsan,
        };
        ElfChecker::to_hashmap(checker)
    }
}
