//! Checks for following exploit mitigations:
//!
//! * NX (Non-eXecutable bit) stack
//! * NX (Non-eXecutable bit) heap
//! * Position-Independent Executable
//! * Stack Canaries
//! * Restricted segment
use goblin::mach::MachO;
use serde_json::json;

use crate::check::{Analyze, GenericMap};
use crate::errors::BinResult;


const MH_PIE: u32 = 0x200000;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;
const MH_NO_HEAP_EXECUTION: u32 = 0x1000000;

impl Analyze for MachO<'_> {
    fn run_compilation_checks(&self) -> BinResult<GenericMap> {
        todo!()
    }

    fn run_mitigation_checks(&self) -> GenericMap {
        let mut mitigate_map: GenericMap = GenericMap::new();

        let nx_stack: bool = matches!(self.header.flags & MH_ALLOW_STACK_EXECUTION, 0);
        mitigate_map.insert("Executable Stack".to_string(), json!(nx_stack));

        let nx_heap: bool = matches!(self.header.flags & MH_NO_HEAP_EXECUTION, 0);
        mitigate_map.insert("Executable Heap".to_string(), json!(nx_heap));

        let aslr: bool = matches!(self.header.flags & MH_PIE, 0);
        mitigate_map.insert(
            "Position Independent Executable / ASLR".to_string(),
            json!(aslr),
        );

        // check for stack canary by finding canary functions in imports
        let stack_canary: bool = match self.imports() {
            Ok(imports) => imports
                .iter()
                .any(|x| x.name == "__stack_chk_fail" || x.name == "__stack_chk_guard"),
            Err(_) => false,
        };
        mitigate_map.insert("Stack Canary".to_string(), json!(stack_canary));

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
        mitigate_map.insert("__RESTRICT segment".to_string(), json!(restrict));
        mitigate_map
    }
}
