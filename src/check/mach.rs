//! Defines the `Mach` security mitigation checker. Consumes an
//! Mach-O binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit) stack
//! * NX (Non-eXecutable bit) heap
//! * Position-Independent Executable
//! * Use of stack canaries

use goblin::mach::MachO;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::check::{BinFeatures, Checker, FeatureMap};

use std::boxed::Box;

/// struct defining parsed info given a Mach-O binary format
#[derive(Deserialize, Serialize, Default)]
pub struct MachInfo {
    pub machine: String,
    pub filetype: String,
    pub ncmds: usize,
}

#[typetag::serde]
impl BinFeatures for MachInfo {
    fn dump_mapping(&self) -> FeatureMap {
        let mut features: FeatureMap = FeatureMap::new();
        features
    }
}

/// struct defining security features parsed from PE, and
/// derives serde de/serialize traits for structured output.
#[derive(Deserialize, Serialize)]
pub struct MachChecker {}

#[typetag::serde]
impl BinFeatures for MachChecker {
    fn dump_mapping(&self) -> FeatureMap {
        let mut features: FeatureMap = FeatureMap::new();
        features
    }
}

impl Checker for MachO<'_> {
    /// parses out basic binary information and stores for consumption and output.
    fn bin_info(&self) -> Box<dyn BinFeatures> {
        Box::new(MachInfo {})
    }

    /// implements the necesary checks for the security mitigations for the specific file format.
    fn harden_check(&self) -> Box<dyn BinFeatures> {
        Box::new(MachChecker {})
    }
}
