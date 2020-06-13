//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.

use crate::check::{BinFeatures, Checker};
use crate::errors::{BinError, BinResult, ErrorKind};
use crate::format::BinFormat;

use goblin::mach::Mach::{Binary, Fat};
use goblin::Object;

use serde::{Deserialize, Serialize};

use std::boxed::Box;
use std::fs;
use std::path::PathBuf;

/// defines auxiliary execution modes that can be utilized for mitigation detection.
pub enum ExecMode {
    All,
    Harden,
    Kernel,
    Yara,
}

/// Defines the main interface `Detector` struct, which is instantiated to consume and handle
/// storing all internally parsed checks in a genericized manner, such that it is much easier
/// for serialization and output.
#[derive(Serialize, Deserialize)]
pub struct Detector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin_info: Option<Box<dyn BinFeatures>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_features: Option<Box<dyn BinFeatures>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_features: Option<Box<dyn BinFeatures>>,

    pub harden_features: Box<dyn BinFeatures>,
}

impl Detector {
    /// run the detector given the instantiated configuration options, and stores results for later
    /// output and consumption.
    pub fn detect(path: PathBuf, exec_mode: &ExecMode, _bin_info: bool) -> BinResult<Self> {
        // read from input path and instantiate checker based on binary format
        let buffer = fs::read(path.as_path())?;

        // do format-specific hardening check by default
        let (bin_info, harden_features): (Option<Box<dyn BinFeatures>>, Box<dyn BinFeatures>) =
            match Object::parse(&buffer)? {
                Object::Elf(elf) => {
                    let bin_info: Option<Box<dyn BinFeatures>> = match _bin_info {
                        true => Some(elf.bin_info()),
                        false => None,
                    };
                    (bin_info, elf.harden_check())
                }
                Object::PE(pe) => {
                    let bin_info: Option<Box<dyn BinFeatures>> = match _bin_info {
                        true => Some(pe.bin_info()),
                        false => None,
                    };
                    (bin_info, pe.harden_check())
                }
                Object::Mach(_mach) => match _mach {
                    Binary(mach) => {
                        let bin_info: Option<Box<dyn BinFeatures>> = match _bin_info {
                            true => Some(mach.bin_info()),
                            false => None,
                        };
                        (bin_info, mach.harden_check())
                    }
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

        // detect kernel mitigations features if set
        let kernel_features: Option<Box<dyn BinFeatures>> = match exec_mode {
            ExecMode::Kernel => Some(Detector::kernel_check()?),
            _ => None,
        };

        Ok(Self {
            bin_info,
            kernel_features,
            rule_features: None,
            harden_features,
        })
    }

    /// executes a kernel-specific check upon the current system that's performing the detection,
    /// and stores it in state for later output.
    #[inline]
    fn kernel_check() -> BinResult<Box<dyn BinFeatures>> {
        todo!()
    }

    /// interfaces the routines within the `BinFormat` given and emit a string that can be
    /// displayed back to the end user.
    pub fn output(self, format: &BinFormat) -> BinResult<String> {
        format.dump(self)
    }
}
