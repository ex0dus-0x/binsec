//! ### PE-Specific Compilation Checks:
//!
//! * Binary Type
//! * Compiler Runtime
//! * Debug Info Stripped
//!
//! ### Exploit Mitigations:
//!
//! * Data Execution Prevention
//! * Code Integrity
//! * Control Flow Guard

use crate::check::{Analyze, GenericMap};
use goblin::pe::PE;
use serde_json::json;

impl Analyze for PE<'_> {
    fn run_compilation_checks(&self) -> GenericMap {
        use goblin::pe::characteristic::*;

        let mut comp_map = GenericMap::new();

        // supported: DLL or EXE
        let bintype: &str = match self.is_lib {
            true => "DLL",
            false => "EXE",
        };
        comp_map.insert("Binary Type", json!(bintype));

        // debug info stripped
        let debug_stripped: bool = matches!(
            self.header.coff_header.characteristics & IMAGE_FILE_DEBUG_STRIPPED,
            0
        );
        comp_map.insert("Debug Stripped", json!(debug_stripped));

        // pattern match for compilers
        comp_map.insert("Compiler Runtime", json!("N/A"));
        comp_map
    }

    fn run_mitigation_checks(&self) -> GenericMap {
        let mut mitigation_checks: GenericMap = GenericMap::new();

        let mut dep: bool = false;
        let mut cfg: bool = false;
        let mut code_integrity: bool = false;

        if let Some(optional_header) = self.header.optional_header {
            dep = matches!(
                optional_header.windows_fields.dll_characteristics & 0x0100,
                0
            );
            cfg = matches!(
                optional_header.windows_fields.dll_characteristics & 0x4000,
                0
            );
            code_integrity = matches!(
                optional_header.windows_fields.dll_characteristics & 0x0080,
                0
            );
        }
        mitigation_checks.insert("Data Execution Protection (DEP)", json!(dep));
        mitigation_checks.insert("Control Flow Guard (CFG)", json!(cfg));
        mitigation_checks.insert("Code Integrity", json!(code_integrity));
        mitigation_checks
    }

    fn run_instrumentation_checks(&self) -> Option<GenericMap> {
        let mut inst_map = GenericMap::new();

        // find symbols for stack canary and FORTIFY_SOURCE
        for _sym in self.imports.iter() {
            let symbol = &_sym.name;
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

        if inst_map.is_empty() {
            None
        } else {
            Some(inst_map)
        }
    }
}
