//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.
#![allow(clippy::match_bool)]

use crate::check::kernel::KernelChecker;
use crate::check::Checker;
use crate::errors::{BinError, BinResult, ErrorKind};
use crate::format::{BinFormat, FeatureMap};
use crate::rule_engine::YaraExecutor;

use goblin::mach::Mach::{Binary, Fat};
use goblin::Object;

use serde::{Deserialize, Serialize};

use std::boxed::Box;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

/// Defines the main interface `Detector` struct, which is instantiated to consume and handle
/// storing all internally parsed checks in a genericized manner, such that it is much easier
/// for serialization and output.
#[derive(Serialize, Deserialize)]
pub struct Detector {
    /// If set, returns any basic binary information that may be useful for the user
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bin_info: Option<FeatureMap>,

    /// Runs the standard binary hardening checks against the input binary
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harden_features: Option<FeatureMap>,

    /// Performs checks for the host kernel running the binary provided
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_features: Option<FeatureMap>,

    /// Executes a set of YARA-based "enhanced" rules to detect deeper features
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_features: Option<FeatureMap>,
}

impl Detector {
    /// Run the detector given the instantiated configuration options, and stores results for later
    /// output and consumption.
    /// TODO: simplify parameters to builder-like pattern
    pub fn detect(
        path: PathBuf,
        basic_info: bool,
        harden: bool,
        kernel: bool,
        rules: bool,
    ) -> BinResult<Self> {
        // read from input path and instantiate checker based on binary format
        let buffer = fs::read(path.as_path())?;

        // is set when parsing each specific binary format type
        let mut bin_info: Option<Box<dyn FeatureCheck>> = None;

        // do format-specific hardening check if set
        let harden_features: Option<Box<dyn FeatureCheck>> = match harden {
            true => match Object::parse(&buffer)? {
                Object::Elf(elf) => {
                    bin_info = match basic_info {
                        true => Some(elf.bin_info()),
                        false => None,
                    };
                    Some(elf.harden_check())
                }
                Object::PE(pe) => {
                    bin_info = match basic_info {
                        true => Some(pe.bin_info()),
                        false => None,
                    };
                    Some(pe.harden_check())
                }
                Object::Mach(_mach) => match _mach {
                    Binary(mach) => {
                        bin_info = match basic_info {
                            true => Some(mach.bin_info()),
                            false => None,
                        };
                        Some(mach.harden_check())
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
            },
            false => None,
        };

        // detect kernel mitigations features if set for the current host's operating system
        let kernel_features: Option<Box<dyn FeatureCheck>> = match kernel {
            true => Some(KernelChecker::detect()?),
            false => None,
        };

        // run the enhanced set of rules against the binary if set
        let rule_features: Option<Box<dyn FeatureCheck>> = match rules {
            true => {
                // initialize YARA executor
                let mut rule_exec: YaraExecutor = YaraExecutor::new(path);

                // add rules from crate directory to executor
                let paths = fs::read_dir("rules")?;
                for _path in paths {
                    let path: PathBuf = _path?.path();

                    // only parse YARA files
                    let path_ext: Option<&str> = path.as_path().extension().and_then(OsStr::to_str);
                    if path_ext != Some("yara") {
                        continue;
                    }

                    // add rule to executor for parsing and bootstrapping a command
                    rule_exec.add_rule(path)?;
                }

                // execute them against the target, and store results
                rule_exec.execute()?;

                // return back the matches for display
                Some(Box::new(rule_exec.matches))
            }
            false => None,
        };

        Ok(Self {
            bin_info,
            kernel_features,
            rule_features,
            harden_features,
        })
    }

    /// interfaces the routines within the `BinFormat` given and emit a string that can be
    /// displayed back to the end user.
    pub fn output(self, format: &BinFormat) -> BinResult<String> {
        format.dump(self)
    }
}
