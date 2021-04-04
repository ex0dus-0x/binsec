//! * Data Execution Prevention
//! * Code Integrity
//! * Control Flow Guard
use goblin::pe::PE;

use structmap::value::Value;
use structmap::ToHashMap;
use structmap_derive::ToHashMap;

use crate::check::Analyze;
use crate::format::FeatureMap;

/// Struct defining security features parsed from PE, and
/// derives serde de/serialize traits for structured output.
#[derive(serde::Serialize, ToHashMap, Default)]
pub struct PeAnalyze {
    #[rename(name = "Data Execution Prevention (DEP)")]
    pub dep: bool,

    #[rename(name = "Control Flow Guard (CFG)")]
    pub cfg: bool,

    #[rename(name = "Code Integrity")]
    pub code_integrity: bool,
}

impl Analyze for PE<'_> {
    fn run_harden_check(&self) -> FeatureMap {
        // check for DEP aka stack exec protection by checking the DLL characteristics
        let dep: bool = match self.header.optional_header {
            Some(optional_header) => {
                optional_header.windows_fields.dll_characteristics & 0x0100 == 0
            }
            None => false,
        };

        // Check for control flow guard
        let cfg: bool = match self.header.optional_header {
            Some(optional_header) => {
                optional_header.windows_fields.dll_characteristics & 0x4000 == 0
            }
            None => false,
        };

        // Code integrity enabled
        let code_integrity: bool = match self.header.optional_header {
            Some(optional_header) => {
                optional_header.windows_fields.dll_characteristics & 0x0080 == 0
            }
            None => false,
        };

        let pechecker = PeAnalyze {
            dep,
            cfg,
            code_integrity,
        };
        PeAnalyze::to_hashmap(pechecker)
    }
}
