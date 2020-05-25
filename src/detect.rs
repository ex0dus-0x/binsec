//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.

use std::fs;
use std::boxed::Box;
use std::path::PathBuf;
use std::collections::BTreeMap;

use goblin::{error, Object};

use crate::check::{Checker, elf, mach, pe};
use crate::errors::BinResult;


/// Defines the output format variants that are supported by binsec. Enforces a uniform `dump()`
/// function to perform serialization to the respective format when outputting back to user.
pub enum BinFormat {
    Normal,
    Table,
    Json,
    Csv,
    Protobuf
}

impl BinFormat {
    /// constructs a printable string for respective output format for display or persistent
    /// storage by consuming a ``.
    pub fn dump(&self, input: _) -> BinResult<String> {
        match self {
            BinFormat::Normal => Ok(input.to_string()),
            BinFormat::Table => {
                use term_table::{
                    row::Row,
                    table_cell::{Alignment, TableCell},
                };
                use term_table::{Table, TableStyle};

            },
            BinFormat::Json => Ok(serde_json::to_string_pretty(input)),
            BinFormat::Csv => Ok(),
            BinFormat::Protobuf => Ok(),
        }
    }
}

/// Defines the main interface `Detector` struct, which is instantiated to consume and handle
/// execution for a single binary input. It detects the checker for the specific binary format,
/// and executes a check when called.
pub struct Detector {
    path: PathBuf,
    checker: Box<dyn Checker>,
    features: Option<Features>,
    out_format: BinFormat,
    out_path: Option<PathBuf>
}

impl Detector {
    /// given a path to a binary and format for output, instantiate the checker for the specific
    /// platform and other attributes necessary for runtime.
    pub fn new(path: PathBuf, out_format: BinFormat, out_path: Option<PathBuf>) -> BinResult<Self> {

        // read from input path and instantiate checker based on binary format
        let buffer = fs::read(path)?;
        let checker: Box<dyn Checker + 'static> = match Object::parse(&buffer)? {
            Object::Elf(elf) => Box::new(elf::ElfChecker::new(elf)),
            Object::Mach(mach) => Box::new(mach::MachChecker::new(mach)),
            Object::PE(pe) => Box::new(pe::PEChecker::new(pe))
        };

        Self {
            path: fs::canonicalize(path)?,
            checker,
            out_format,
            out_path,
        }
    }
}
