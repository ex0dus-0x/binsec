//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.

use std::boxed::Box;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use goblin::{error, Object};
use goblin::mach::Mach::{Binary, Fat};

use crate::check::{elf, mach, pe, Checker, Features};
use crate::errors::{BinError, BinResult, ErrorKind};

/// Defines the output format variants that are supported by binsec. Enforces a uniform `dump()`
/// function to perform serialization to the respective format when outputting back to user.
pub enum BinFormat {
    Normal,
    Table,
    Json,
    Protobuf,
}

impl BinFormat {
    /// constructs a printable string for respective output format for display or persistent
    /// storage by consuming a ``.
    pub fn dump(&self, input: Features) -> BinResult<String> {
        match self {
            BinFormat::Normal => Ok(input.to_string()),
            BinFormat::Table => {
                use term_table::{
                    row::Row,
                    table_cell::{Alignment, TableCell},
                };
                use term_table::{Table, TableStyle};

                todo!()
            }
            BinFormat::Json => Ok(serde_json::to_string_pretty(&input).unwrap()),
            BinFormat::Protobuf => todo!(),
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
    out_path: Option<PathBuf>,
}

impl Detector {
    /// given a path to a binary and format for output, instantiate the checker for the specific
    /// platform and other attributes necessary for runtime.
    pub fn new(path: PathBuf, out_format: BinFormat, out_path: Option<PathBuf>) -> BinResult<Self> {
        // read from input path and instantiate checker based on binary format
        let buffer = fs::read(path)?;
        let checker: Box<dyn Checker + 'static> = match Object::parse(&buffer)? {
            Object::Elf(elf) => Box::new(elf::ElfChecker::new(elf)),
            Object::PE(pe) => Box::new(pe::PEChecker::new(pe)),
            Object::Mach(_mach) => {
                match _mach {
                    Binary(mach) =>  Box::new(mach::MachChecker::new(mach)),
                    Fat(fat) => {
                        return Err(BinError {
                           kind: ErrorKind::BinaryError,
                           msg: "does not support multiarch FAT binary containers".to_string()
                        });
                    }
                }
            }
        };

        Ok(Self {
            path: fs::canonicalize(path)?,
            checker,
            features: None,
            out_format,
            out_path,
        })
    }
}
