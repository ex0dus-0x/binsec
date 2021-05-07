//! ### ELF-Specific Compilation Checks:
//!
//! * Compiler Runtime
//! * Linker Path
//! * Glibc Version
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

use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::elf::{program_header, Elf};
use serde_json::json;

use crate::check::{Analyze, GenericMap};

impl Analyze for Elf<'_> {
    fn run_compilation_checks(&self) -> GenericMap {
        let mut comp_map: GenericMap = GenericMap::new();

        // check if PT_INTERP segment exists
        let static_exec: bool = !self
            .program_headers
            .iter()
            .any(|ph| program_header::pt_to_str(ph.p_type) == "PT_INTERP");

        comp_map.insert("Statically Compiled", json!(static_exec));
        comp_map.insert("Stripped Executable", json!(self.syms.is_empty()));
        comp_map
    }

    fn run_mitigation_checks(&self) -> GenericMap {
        let mut mitigate_map: GenericMap = GenericMap::new();

        // features we are checking for
        let mut nx_bit: bool = false;
        let mut relro: String = "NONE".to_string();
        let mut stack_canary: bool = false;
        let mut fortify_source: bool = false;

        // iterate over program headers for exploit mitigation fingerprints
        for ph in self.program_headers.iter() {
            // check for NX bit
            if program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK" && ph.p_flags == 6 {
                nx_bit = true;
            }

            // check for RELRO
            if program_header::pt_to_str(ph.p_type) == "PT_GNU_RELRO" {
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
        }
        mitigate_map.insert("Executable Stack (NX Bit)", json!(nx_bit));
        mitigate_map.insert("Read-Only Relocatable (RELRO)", json!(relro));
        mitigate_map.insert(
            "Position Independent Executable / ASLR",
            json!(matches!(self.header.e_type, 3)),
        );

        // find symbols for stack canary and FORTIFY_SOURCE
        for _sym in self.syms.iter() {
            let _symbol = self.strtab.get(_sym.st_name);
            if let Some(Ok(symbol)) = _symbol {
                if symbol == "__stack_chk_fail" {
                    stack_canary = true;
                } else if symbol.ends_with("_chk") {
                    fortify_source = true;
                }
            }
        }
        mitigate_map.insert("Stack Canary", json!(stack_canary));
        mitigate_map.insert("FORTIFY_SOURCE", json!(fortify_source));
        mitigate_map
    }

    fn run_instrumentation_checks(&self) -> Option<GenericMap> {
        let mut inst_map = GenericMap::new();

        // find symbols for stack canary and FORTIFY_SOURCE
        for _sym in self.syms.iter() {
            let _symbol = self.strtab.get(_sym.st_name);
            if let Some(Ok(symbol)) = _symbol {
                if symbol.starts_with("__afl") {
                    inst_map.insert("AFL Instrumentation", json!(true));
                } else if symbol.starts_with("__asan") {
                    inst_map.insert("Address Sanitizer", json!(true));
                } else if symbol.starts_with("__ubsan") {
                    inst_map.insert("Undefined Behavior Sanitizer", json!(true));
                } else if symbol.starts_with("__llvm") {
                    inst_map.insert("LLVM Code Coverage", json!(true));
                }
            }
        }

        if inst_map.is_empty() {
            None
        } else {
            Some(inst_map)
        }
    }
}
