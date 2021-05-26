pub mod elf;
pub mod mach;
pub mod pe;

use yara::Compiler;

use crate::rules::UNIVERSAL_COMPILER_RULES;
use crate::errors::BinResult;

// represents map used to store tabulated results
pub type GenericMap = std::collections::BTreeMap<String, serde_json::Value>;

/// Defines trait implemented by each supported libgoblin binary format to expose common and
/// reusable functions for parsing out features and doing static analysis.
pub trait Analyze {

    fn detect_compiler_runtime(&self, os_specific: &str) -> BinResult<String> {
        // initialize with universal compiler runtime rules first, then add os_specific ones
        let mut compiler = Compiler::new()?;
        compiler.add_rules_str(UNIVERSAL_COMPILER_RULES)?;
        compiler.add_rules_str(os_specific)?;
        let rules = compiler.compile_rules()?;

        // parse out matches against

        todo!()
    }


    /// To be implemented for each specific binary format
    fn run_compilation_checks(&self) -> BinResult<GenericMap>;
    fn run_mitigation_checks(&self) -> GenericMap;
}
