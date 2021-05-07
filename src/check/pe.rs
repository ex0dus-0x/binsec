//! ### PE-Specific Compilation Checks:
//!
//! * Compiler Runtime
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
        todo!()
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
        todo!()
    }
}
