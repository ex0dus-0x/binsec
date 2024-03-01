pub mod elf;
pub mod mach;
pub mod pe;

//use yara::{Compiler, MetadataValue};

use crate::errors::BinResult;
use crate::rules::UNIVERSAL_COMPILER_RULES;

// represents map used to store tabulated results
pub type GenericMap = std::collections::BTreeMap<String, serde_json::Value>;

/// Defines trait implemented by each supported libgoblin binary format to expose common and
/// reusable functions for parsing out features and doing static analysis.
pub trait Analyze {
    fn detect_compiler_runtime(&self, os_specific: &str, bytes: &[u8]) -> BinResult<String> {
        /*
        // initialize with universal compiler runtime rules first, then add os_specific ones
        let mut compiler = Compiler::new()?;
        compiler.add_rules_str(UNIVERSAL_COMPILER_RULES)?;
        compiler.add_rules_str(os_specific)?;

        // compile rules and match
        let rules = compiler.compile_rules()?;
        let matches = rules.scan_mem(&bytes, 5)?;
        if matches.is_empty() {
            return Ok("N/A".to_string());
        }

        if let MetadataValue::String(name) = matches[0].metadatas[0].value {
            Ok(name.to_string())
        } else {
            Ok("N/A".to_string())
        }*/
        Ok("N/A".to_string())
    }

    /// To be implemented for each specific binary format
    fn compilation(&self, bytes: &[u8]) -> BinResult<GenericMap>;
    fn mitigations(&self) -> GenericMap;
    fn instrumentation(&self) -> Option<GenericMap>;
}
