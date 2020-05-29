//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.

use std::boxed::Box;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;

use goblin::mach::Mach::{Binary, Fat};
use goblin::Object;

use crate::check::{elf, mach, pe, Checker, Features};
use crate::errors::{BinError, BinResult, ErrorKind};
use crate::format::BinFormat;

/// defines the different execution modes that can be utilized for mitigation detection.
pub enum ExecMode {
    All,
    Harden,
    Kernel,
    Yara
}

/// Defines the main interface `Detector` struct, which is instantiated to consume and handle
/// execution for a single binary input. It detects the checker for the specific binary format,
/// and executes a check when called.
pub struct Detector<'a> {
    path: PathBuf,
    checker: Box<dyn Checker + 'a>,
    features: Option<Features>,
}

impl<'a> Detector<'a> {
    /// given a path to a binary and format for output, instantiate the checker for the specific
    /// platform and other attributes necessary for runtime.
    pub fn new(path: PathBuf) -> BinResult<Self> {

        // read from input path and instantiate checker based on binary format
        let mut fd = File::open(path.clone())?;
        let buffer = {
            let mut v = Vec::new();
            fd.read_exact(&mut v)?;
            v
        };

        // initialize trait object from given arbitrary file format
        let checker: Box<dyn Checker + 'a> = match Object::parse(&buffer)? {
            Object::Elf(elf) => Box::new(elf::ElfChecker::new(elf)),
            Object::PE(pe) => Box::new(pe::PEChecker::new(pe)),
            Object::Mach(_mach) => match _mach {
                Binary(mach) => Box::new(mach::MachChecker::new(mach)),
                Fat(_) => {
                    return Err(BinError {
                        kind: ErrorKind::BinaryError,
                        msg: "does not support multiarch FAT binary containers".to_string(),
                    });
                }
            },
            _ => {
                return Err(BinError {
                    kind: ErrorKind::BinaryError,
                    msg: "unsupported filetype for analysis".to_string(),
                });
            }
        };

        Ok(Self {
            path: fs::canonicalize(path)?,
            checker,
            features: None
        })
    }

    /// implements the actual detection routine that executes the checks necessary and emits a
    /// `Features` BTreeMap mapping with security mitigations for display.
    pub fn detect(&self, mode: &ExecMode, basic_info: bool) -> BinResult<()> {
        todo!();
    }

    /// interfaces the routines within the `BinFormat` given and emit a string that can be
    /// displayed back to the end user.
    pub fn output(&self, format: &BinFormat) -> BinResult<String> {
        if let Some(features) = &self.features {
            format.dump(features)
        } else {
            Err(BinError {
                kind: ErrorKind::DumpError,
                msg: "cannot output without calling `detect()` \
                     and giving it a mode of operation.".to_string()
            })
        }
    }
}
