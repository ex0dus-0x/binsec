//! ### ELF-Specific Checks:
//!
//! * Static Compilation
//! * Stripped Executable
//!
//! ### Exploit Mitigations:
//!
//! * NX (Non-eXecutable bit) stack
//! * Stack Canaries
//! * FORTIFY_SOURCE
//! * Position-Independent Executable / ASLR
//! * Full/Partial RELRO
//! * Address Sanitizer
//! * Undefined Behavior Sanitizer

use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::elf::{header, program_header, Elf, ProgramHeader};

use structmap::value::Value;
use structmap::ToHashMap;
use structmap_derive::ToHashMap;

use crate::check::{Analyze, Detection};

#[derive(serde::Serialize, ToHashMap, Default)]
pub struct ElfBasic {
    #[rename(name = "Statically Compiled")]
    static_comp: bool,

    #[rename(name = "Stripped Binary")]
    stripped: bool,
}

impl Detection for ElfBasic {}

/// Encapsulates an ELF object from libgoblin, in order to parse it and dissect out the necessary
/// security mitigation features.
#[derive(serde::Serialize, ToHashMap, Default)]
pub struct ElfHarden {
    #[rename(name = "Executable Stack (NX Bit)")]
    pub exec_stack: bool,

    #[rename(name = "Position Independent Executable / ASLR")]
    pub pie: bool,

    #[rename(name = "Read-Only Relocatable")]
    pub relro: String,

    #[rename(name = "Stack Canary")]
    pub stack_canary: bool,

    #[rename(name = "FORTIFY_SOURCE")]
    pub fortify_source: bool,
}

impl Detection for ElfHarden {}

impl Analyze for Elf<'_> {
    fn get_architecture(&self) -> String {
        header::machine_to_str(self.header.e_machine).to_string()
    }

    fn get_entry_point(&self) -> String {
        format!("{:x}", self.header.e_entry)
    }

    fn symbol_match(&self, cb: fn(&str) -> bool) -> bool {
        self.dynsyms
            .iter()
            .filter_map(|sym| self.dynstrtab.get(sym.st_name))
            .any(|name| match name {
                Ok(e) => cb(e),
                _ => false,
            })
    }
}

/// Custom trait implemented to support ELF-specific static checks that can't be handled by
/// using exposed methods through the `Analyze` trait.
pub trait ElfChecks {
    fn exec_stack(&self) -> bool;
    fn aslr(&self) -> bool;
    fn relro(&self) -> String;
}

impl ElfChecks for Elf<'_> {
    fn exec_stack(&self) -> bool {
        self.program_headers
            .iter()
            .any(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK" && ph.p_flags == 6)
    }

    fn aslr(&self) -> bool {
        matches!(self.header.e_type, 3)
    }

    fn relro(&self) -> String {
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
        }
        relro
    }
}
