//! ### ELF-Specific Compilation Checks:
//!
//! * Binary Type
//! * Static Compilation
//! * Stripped Executable
//! * Compiler Runtime (TODO)
//! * Linker Path
//! * Minimum glibc Version
//!
//! ### Exploit Mitigations:
//!
//! * NX (Non-eXecutable bit) stack
//! * Stack Canaries
//! * FORTIFY_SOURCE
//! * Position-Independent Executable / ASLR
//! * Full/Partial RELRO

use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::elf::{header, program_header, Elf};
use serde_json::json;

use crate::check::{Analyze, GenericMap};
use crate::errors::BinResult;
use crate::rules;

const GLIBC: &str = "GLIBC_2.";

impl Analyze for Elf<'_> {
    fn compilation(&self, bytes: &[u8]) -> BinResult<GenericMap> {
        let mut comp_map: GenericMap = GenericMap::new();

        // supported: shared object (pie exec or .so) or executable
        comp_map.insert(
            "Binary Type".to_string(),
            json!(header::et_to_str(self.header.e_type)),
        );

        // pattern match for compilers
        let runtime = self.detect_compiler_runtime(rules::ELF_COMPILER_RULES, bytes)?;
        comp_map.insert("Compiler Runtime".to_string(), json!(runtime));

        // static executable: check if PT_INTERP segment exists
        let static_exec: bool = !self
            .program_headers
            .iter()
            .any(|ph| program_header::pt_to_str(ph.p_type) == "PT_INTERP");
        comp_map.insert("Statically Compiled".to_string(), json!(static_exec));

        // path to linker if dynamic linking enabled
        if let Some(linker) = self.interpreter {
            comp_map.insert("Linker Path".to_string(), json!(linker));
        }

        // parse minimum glibc version needed
        let mut glibcs: Vec<f64> = vec![];
        for sym in self.dynstrtab.to_vec().unwrap() {
            if sym.starts_with(GLIBC) {
                let ver_str: &str = sym.strip_prefix(GLIBC).unwrap();
                let version: f64 = ver_str.parse::<f64>().unwrap();
                glibcs.push(version);
            }
        }
        let min_ver = glibcs.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        comp_map.insert(
            "Minimum Libc Version".to_string(),
            json!(format!("2.{:?}", min_ver)),
        );
        comp_map.insert(
            "Stripped Executable".to_string(),
            json!(self.syms.is_empty()),
        );
        Ok(comp_map)
    }

    fn mitigations(&self) -> GenericMap {
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
        mitigate_map.insert("Executable Stack (NX Bit)".to_string(), json!(nx_bit));
        mitigate_map.insert("Read-Only Relocatable (RELRO)".to_string(), json!(relro));
        mitigate_map.insert(
            "Position Independent Executable / ASLR".to_string(),
            json!(matches!(self.header.e_type, 3)),
        );

        // find symbols for stack canary and FORTIFY_SOURCE
        for _sym in self.syms.iter() {
            let _symbol = self.strtab.get_at(_sym.st_name);
            if let Some(symbol) = _symbol {
                if symbol == "__stack_chk_fail" {
                    stack_canary = true;
                
                // TODO: make tighter
                } else if symbol.ends_with("_chk") {
                    fortify_source = true;
                }
            }
        }
        mitigate_map.insert("Stack Canary".to_string(), json!(stack_canary));
        mitigate_map.insert("FORTIFY_SOURCE".to_string(), json!(fortify_source));
        mitigate_map
    }

    fn instrumentation(&self) -> GenericMap {
        let mut instr_map: GenericMap = GenericMap::new();
        for _sym in self.syms.iter() {
            let _symbol = self.strtab.get_at(_sym.st_name);
            if let Some(symbol) = _symbol {

                // /__ubsan\w+\d+/
                if symbol.starts_with("__ubsan") {
                    instr_map.insert("Undefined Behavior Sanitizer (UBSAN)".to_string(), json!(true));
                
                // /_ZN\w+__asan\w+\d+/
                } else if symbol.starts_with("__asan") {
                    instr_map.insert("Address Sanitizer (ASAN)".to_string(), json!(true));
                
                // /__afl\w+\d+/
                } else if symbol.starts_with("__afl") {
                    instr_map.insert("AFL Instrumentation".to_string(), json!(true));
                
                // /__llvm\w+\d+/
                } else if symbol.starts_with("__llvm") {
                    instr_map.insert("LLVM Code Coverage".to_string(), json!(true));
                }
            }
        }
        instr_map
    }
}
