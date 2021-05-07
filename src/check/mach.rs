//! Checks for following exploit mitigations:
//!
//! * NX (Non-eXecutable bit) stack
//! * NX (Non-eXecutable bit) heap
//! * Position-Independent Executable
//! * Stack Canaries
//! * Restricted segment

use goblin::mach::MachO;
use crate::check::{Analyze, GenericMap};
use serde_json::json;

const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

impl Analyze for MachO<'_> {

    /*
    fn run_mitigation_checks(&self) -> GenericMap {
        let nx_stack: bool = matches!(self.header.flags & MH_ALLOW_STACK_EXECUTION, 0);
        let nx_heap: bool = matches!(self.header.flags & MH_NO_HEAP_EXECUTION, 0);

        // check for stack canary by finding canary functions in imports
        let stack_canary: bool = match self.imports() {
            Ok(imports) => imports
                .iter()
                .any(|x| x.name == "__stack_chk_fail" || x.name == "__stack_chk_guard"),
            Err(_) => false,
        };

        // check for __RESTRICT section for stopping dynlib injection
        let restrict: bool = self
            .segments
            .iter()
            .filter_map(|s| {
                if let Ok(name) = s.name() {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .any(|s| s.to_lowercase() == "__restrict");
    }
    */
}
