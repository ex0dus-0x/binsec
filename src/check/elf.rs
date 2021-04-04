//! Check for the following exploit mitigations:
//!
//! * NX (Non-eXecutable bit) stack
//! * Stack Canaries
//! * FORTIFY_SOURCE
//! * Position-Independent Executable / ASLR
//! * Full/Partial RELRO
//! * Address Sanitizer
//! * Undefined Behavior Sanitizer

use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::elf::{program_header, Elf, ProgramHeader};

use structmap::value::Value;
use structmap::ToHashMap;
use structmap_derive::ToHashMap;

use crate::check::{Analyze, BasicInfo, Detection};

/// Encapsulates an ELF object from libgoblin, in order to parse it and dissect out the necessary
/// security mitigation features.
#[derive(serde::Serialize, ToHashMap, Default)]
struct ElfHarden {
    #[rename(name = "Executable Stack (NX Bit)")]
    pub exec_stack: bool,

    #[rename(name = "Executable Stack (NX Bit)")]
    pub stack_canary: bool,

    #[rename(name = "Position Independent Executable / ASLR")]
    pub pie: bool,

    #[rename(name = "Read-Only Relocatable")]
    pub relro: String,

    #[rename(name = "FORTIFY_SOURCE")]
    pub fortify_source: bool,

    #[rename(name = "ASan")]
    pub asan: bool,

    #[rename(name = "UBSan")]
    pub ubsan: bool,
}

impl Detection for ElfHarden {}

impl Analyze for Elf<'_> {

    fn run_basic_checks(&self) -> BasicInfo {
        todo!()
    }

    fn run_specific_checks(&self) -> Box<dyn Detection> {
        todo!()
    }

    fn run_harden_checks(&self) -> Box<dyn Detection> {
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

        /*
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
        */

        Box::new(ElfHarden {
            exec_stack,
            stack_canary,
            fortify_source,
            pie,
            relro,
            asan,
            ubsan,
        })
    }
}
