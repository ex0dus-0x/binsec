//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.
#![allow(clippy::match_bool)]

use crate::check::Checker;
use crate::errors::{BinError, BinResult, ErrorKind};
use crate::format::FeatureMap;

use goblin::Object;
use goblin::mach::Mach;

use std::fs;
use std::path::PathBuf;

/// Wraps over an executable and implements checks configured by the user, returning a
/// a map denoting presence of features checked for.
pub struct Detector(Vec<u8>);

impl Detector {
    pub fn new(path: PathBuf) -> BinResult<Self> {
        Ok(Self(fs::read(path.as_path())?))
    }

    /// Detects exploit mitigations present in the parsed binary format.
    pub fn harden(&self) -> BinResult<FeatureMap> {
       match Object::parse(&self.0)? {
            Object::Elf(elf) => Ok(elf.harden_check()),
            Object::PE(pe) => Ok(pe.harden_check()),
            Object::Mach(_mach) => match _mach {
                Mach::Binary(mach) => Ok(mach.harden_check()),
                Mach::Fat(_) => Err(BinError {
                        kind: ErrorKind::BinaryError,
                        msg: "does not support multiarch FAT binary containers yet".to_string(),
                    })
                },
            _ => {
                Err(BinError {
                    kind: ErrorKind::BinaryError,
                    msg: "unsupported filetype for analysis".to_string(),
                })
            }
        }
    }
}
