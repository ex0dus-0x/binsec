//! Defines the `PE` security mitigation checker. Consumes an
//! PE binary, parses it, and checks for the following features:
//!
//! * DEP (Data Execution Prevention)
//! * Authenticode

use goblin::pe::PE;

use serde_json::{json, Value};

use crate::check::{BinFeatures, BinInfo, Checker, FeatureMap};

use std::boxed::Box;

/// defines the executable format
enum PeExecutable {
    Net,
    VB,
}

/// defines the basic information that can be parsed out from a PE file format's
/// header when asked by user.
pub struct PeInfo {
    pub machine: String,
    pub exec_type: PeExecutable,
    pub timestamp: u32,
}

impl BinInfo for PeInfo {
    fn dump_mapping(&self) -> FeatureMap {
        let mut features: FeatureMap = FeatureMap::new();
        features.insert("Architecture", json!(self.machine));
        features.insert("Executable Type", json!(self.exec_type.to_string()));
        features.insert("Time Stamp", json!(self.timestamp));
        features
    }
}

/// struct defining security features parsed from ELF, and
/// derives serde de/serialize traits for structured output.
pub struct PEChecker {
    pub authenticode: bool,
    pub dep: bool,
}
