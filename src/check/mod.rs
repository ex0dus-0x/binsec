pub mod elf;
pub mod mach;
pub mod pe;

use std::collections::BTreeMap;

// represents map used to store tabulated results
pub type GenericMap = BTreeMap<String, serde_json::Value>;

/// Defines trait implemented by each supported libgoblin binary format to expose common and
/// reusable functions for parsing out features and doing static analysis.
pub trait Analyze {
    fn run_compilation_checks(&self) -> GenericMap;
    fn run_mitigation_checks(&self) -> GenericMap;
}
