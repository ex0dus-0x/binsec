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

use goblin::pe::characteristic::*;
use goblin::pe::PE;
use serde_json::json;

use crate::check::{Analyze, GenericMap};
use crate::errors::BinResult;
use crate::rules;

impl Analyze for PE<'_> {
    fn compilation(&self, bytes: &[u8]) -> BinResult<GenericMap> {
        let mut comp_map = GenericMap::new();

        // supported: DLL or EXE
        let bintype: &str = match self.is_lib {
            true => "DLL",
            false => "EXE",
        };
        comp_map.insert("Binary Type".to_string(), json!(bintype));

        // debug info stripped
        let debug_stripped: bool = matches!(
            self.header.coff_header.characteristics & IMAGE_FILE_DEBUG_STRIPPED,
            0
        );
        comp_map.insert("Debug Stripped".to_string(), json!(debug_stripped));

        // pattern match for compilers
        let runtime = self.detect_compiler_runtime(rules::PE_COMPILER_RULES, bytes)?;
        comp_map.insert("Compiler Runtime".to_string(), json!(runtime));
        Ok(comp_map)
    }

    fn mitigations(&self) -> GenericMap {
        let mut mitigation_checks: GenericMap = GenericMap::new();

        if let Some(optional_header) = self.header.optional_header {
            let dll_chars: u16 = optional_header.windows_fields.dll_characteristics;
            let image_chars: u16 = self.header.coff_header.characteristics;

            // context independent mitigations
            let dep: bool = matches!(dll_chars & 0x0100, 0);
            mitigation_checks.insert("Data Execution Protection (DEP)".to_string(), json!(dep));

            let dynamic_base: bool = matches!(dll_chars & 0x0040, 0);
            mitigation_checks.insert("Dynamic Base".to_string(), json!(dynamic_base));

            let seh: bool = matches!(dll_chars & 0x0400, 0);
            mitigation_checks.insert(
                "Structured Exception Handling (SEH)".to_string(),
                json!(!seh),
            );

            let isolation_aware: bool = matches!(dll_chars & 0x0200, 0);
            mitigation_checks.insert(
                "Isolation-Aware Execution".to_string(),
                json!(!isolation_aware),
            );

            // context dependent mitigations: some don't work without existence of other checks

            let aslr: bool = dynamic_base && matches!(image_chars & IMAGE_FILE_RELOCS_STRIPPED, 0);
            mitigation_checks.insert(
                "Address Space Layout Randomization (ASLR)".to_string(),
                json!(aslr),
            );

            let high_entropy: bool = aslr && matches!(dll_chars & 0x0020, 0);
            mitigation_checks.insert("High Entropy".to_string(), json!(high_entropy));

            let cfg: bool = aslr && matches!(dll_chars & 0x4000, 0);
            mitigation_checks.insert("Control Flow Guard (CFG)".to_string(), json!(cfg));

            let code_integrity: bool = aslr && matches!(dll_chars & 0x0080, 0);
            mitigation_checks.insert("Code Integrity".to_string(), json!(code_integrity));
        }
        mitigation_checks
    }

    fn instrumentation(&self) -> Option<GenericMap> {
        unimplemented!();
    }
}
