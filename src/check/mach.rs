//! Defines the `Mach` security mitigation checker. Consumes an
//! Mach-O binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit) stack
//! * NX (Non-eXecutable bit) heap
//! * Position-Independent Executable
//! * Use of stack canaries

use goblin::mach::constants::cputype;
use goblin::mach::header;
use goblin::mach::MachO;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::check::{BinFeatures, Checker, FeatureMap};

use std::boxed::Box;

const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

/// struct defining parsed info given a Mach-O binary format
#[derive(Deserialize, Serialize, Default)]
pub struct MachInfo {
    pub machine: String,
    pub filetype: String,
    pub flags: String,
    pub num_cmds: usize,
}

#[typetag::serde]
impl BinFeatures for MachInfo {
    fn dump_mapping(&self) -> FeatureMap {
        let mut features: FeatureMap = FeatureMap::new();
        features.insert("Machine", json!(self.machine));
        features.insert("Filetype", json!(self.filetype));
        features.insert("Flags", json!(self.flags));
        features.insert("Number of Load Commands", json!(self.num_cmds));
        features
    }
}

/// struct defining security features parsed from PE, and
/// derives serde de/serialize traits for structured output.
#[derive(Deserialize, Serialize)]
pub struct MachChecker {
    pub nx_stack: bool,
    pub nx_heap: bool,
    pub stack_canary: bool,
    pub restrict: bool,
}

#[typetag::serde]
impl BinFeatures for MachChecker {
    fn dump_mapping(&self) -> FeatureMap {
        let mut features: FeatureMap = FeatureMap::new();
        features.insert("Non-Executable Stack", json!(self.nx_stack));
        features.insert("Non-Executable Heap", json!(self.nx_heap));
        features.insert("Stack Canary", json!(self.stack_canary));
        features.insert("Restrict Code Injection", json!(self.restrict));
        features
    }
}

impl Checker for MachO<'_> {
    /// parses out basic binary information and stores for consumption and output.
    fn bin_info(&self) -> Box<dyn BinFeatures> {
        // parse out machine architecture given cpu type and subtype
        let machine: String =
            cputype::get_arch_name_from_types(self.header.cputype(), self.header.cpusubtype())
                .unwrap()
                .to_string();

        // parse out flag
        let flags: String = header::flag_to_str(self.header.flags).to_string();

        // parse out filetype
        let filetype: String = header::filetype_to_str(self.header.filetype).to_string();

        Box::new(MachInfo {
            machine,
            flags,
            filetype,
            num_cmds: self.header.ncmds,
        })
    }

    /// implements the necesary checks for the security mitigations for the specific file format.
    fn harden_check(&self) -> Box<dyn BinFeatures> {
        // check for non-executable stack
        let nx_stack: bool = match self.header.flags & MH_ALLOW_STACK_EXECUTION {
            0 => true,
            _ => false,
        };

        // check for non-executable heap
        let nx_heap: bool = match self.header.flags & MH_NO_HEAP_EXECUTION {
            0 => true,
            _ => false,
        };

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

        Box::new(MachChecker {
            nx_stack,
            nx_heap,
            stack_canary,
            restrict,
        })
    }
}
