//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.

use std::boxed::Box;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use goblin::mach::Mach::{Binary, Fat};
use goblin::Object;

use crate::check::{BinFeatures, BinInfo, Checker, FeatureMap};
use crate::errors::{BinError, BinResult, ErrorKind};
use crate::format::BinFormat;

/// defines the different execution modes that can be utilized for mitigation detection.
pub enum ExecMode {
    All,
    Harden,
    Kernel,
    Yara,
}

/// Defines the main interface `Detector` struct, which is instantiated to consume and handle
/// execution for a single binary input. It detects the checker for the specific binary format,
/// and executes a check when called.
pub struct Detector {
    bin_info: Option<Box<dyn BinInfo>>,
    harden_features: Box<dyn BinFeatures>,
}

impl Detector {
    /// run the detector given the instantiated configuration options, and stores results for later
    /// output and consumption.
    pub fn detect(path: PathBuf, exec_mode: &ExecMode, _bin_info: bool) -> BinResult<Self> {
        // read from input path and instantiate checker based on binary format
        let buffer = fs::read(path.as_path())?;

        // do format-specific hardening check by default
        let (bin_info, harden_features): (Option<Box<dyn BinInfo>>, Box<dyn BinFeatures>) =
            match Object::parse(&buffer)? {
                Object::Elf(elf) => {
                    // get basic binary information if argument is specified
                    let bin_info: Option<Box<dyn BinInfo>> = match _bin_info {
                        true => Some(elf.bin_info()),
                        false => None,
                    };
                    (bin_info, elf.harden_check())
                }
                Object::PE(pe) => todo!(),
                Object::Mach(_mach) => match _mach {
                    Binary(mach) => todo!(),
                    Fat(_) => {
                        return Err(BinError {
                            kind: ErrorKind::BinaryError,
                            msg: "does not support multiarch FAT binary containers yet".to_string(),
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

        // TODO: handle checks for other stuff

        Ok(Self {
            bin_info,
            harden_features,
        })
    }

    /// interfaces the routines within the `BinFormat` given and emit a string that can be
    /// displayed back to the end user.
    pub fn output(&self, format: &BinFormat) -> BinResult<String> {
        // aggregates all of the features that were parsed out as a result of the execution mode
        let mut features: BTreeMap<&str, FeatureMap> = BTreeMap::new();

        // append basic binary information first if available
        if let Some(info) = &self.bin_info {
            features.insert("Basic Information", info.dump_mapping());
        }

        // append basic hardening checks for the binary format
        features.insert("Hardening Checks", self.harden_features.dump_mapping());

        // return output result
        format.dump(&features)
    }
}
