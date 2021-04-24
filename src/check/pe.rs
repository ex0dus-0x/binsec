//! * Data Execution Prevention
//! * Code Integrity
//! * Control Flow Guard
use goblin::pe::PE;

use structmap::value::Value;
use structmap::{ToMap, GenericMap, StringMap};
use structmap_derive::ToMap;

use crate::check::{Analyze, Detection};

/// Struct defining security features parsed from PE, and
/// derives serde de/serialize traits for structured output.
#[derive(serde::Serialize, ToMap, Default)]
pub struct PeHarden {
    #[rename(name = "Data Execution Prevention (DEP)")]
    pub dep: bool,

    #[rename(name = "Control Flow Guard (CFG)")]
    pub cfg: bool,

    #[rename(name = "Code Integrity")]
    pub code_integrity: bool,
}

impl Detection for PeHarden {}

impl Analyze for PE<'_> {
    fn get_architecture(&self) -> String {
        if self.is_64 {
            String::from("PE32+")
        } else {
            String::from("PE32")
        }
    }

    fn get_entry_point(&self) -> String {
        format!("{}", self.entry)
    }

    fn symbol_match(&self, cb: fn(&str) -> bool) -> bool {
        todo!()
    }
}

/// Custom trait implemented to support PE-specific static checks that can't be handled by
/// using exposed methods through the `Analyze` trait.
pub trait PeChecks {
    fn parse_opt_header(&self, magic: u16) -> bool;
}

impl PeChecks for PE<'_> {
    fn parse_opt_header(&self, magic: u16) -> bool {
        match self.header.optional_header {
            Some(optional_header) => {
                optional_header.windows_fields.dll_characteristics & magic == 0
            }
            None => false,
        }
    }
}
