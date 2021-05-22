//! ### PE-Specific Compilation Checks:
//!
//! * Binary Type
//! * Compiler Runtime
//! * Debug Info Stripped
//!
//! ### Exploit Mitigations:
//!
//! * Data Execution Prevention (DEP / NX)
//! * Dynamic Base
//! * Structured Exception Handling (SEH)
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

        if let Some(optional_header) = self.header.optional_header {
            let dll_chars: u16 = optional_header.windows_fields.dll_characteristics;

            // context independent mitigations
            let dep: bool = matches!(dll_chars & 0x0100, 0);
            mitigation_checks.insert("Data Execution Protection (DEP)", json!(dep));

            let dynamic_base: bool = matches!(dll_chars & 0x0040, 0);
            mitigation_checks.insert("Dynamic Base", json!(dynamic_base));

            let seh: bool = matches!(dll_chars & 0x0400, 0);
            mitigation_checks.insert("Structured Exception Handling (SEH)", json!(!seh));

            let isolation_aware: bool = matches!(dll_chars & 0x0200, 0);
            mitigation_checks.insert("Isolation-Aware Execution", json!(!isolation_aware));

            // context dependent mitigations: some don't work without existence of other checks
            let cfg: bool = matches!(dll_chars & 0x4000, 0);
            mitigation_checks.insert("Control Flow Guard (CFG)", json!(cfg));

            let code_integrity: bool = matches!(dll_chars & 0x0080, 0);
            mitigation_checks.insert("Code Integrity", json!(code_integrity));
        }
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
