//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.
#![allow(clippy::match_bool)]

use crate::check::Checker;
use crate::errors::{BinError, BinResult, ErrorKind};
use crate::format::FeatureMap;
use crate::rule_engine::YaraExecutor;

use goblin::mach::Mach;
use goblin::Object;

use serde::{Deserialize, Serialize};

use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

/// Wraps over an executable and implements checks configured by the user, returning a
/// a map denoting presence of features checked for.
pub struct Detector(Vec<u8>)

impl Detector {
    pub fn new(path: PathBuf) -> BinResult<Self> {
        Self(fs::read(path.as_path())?)
    }

    pub fn harden_checks(&self) -> BinResult<FeatureMap> {
       match Object::parse(self.0)? {
            Object::Elf(elf) => Ok(elf.harden_check())
            Object::PE(pe) => Ok(pe.harden_check())
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

    pub fn rule_check(&self) -> BinResult<FeatureMap> {
        let mut rule_exec: YaraExecutor = YaraExecutor::new(path);

        let paths = fs::read_dir("rules")?;
        for name in paths {
            let path: PathBuf = name?.path();

            // only parse YARA files
            let path_ext: Option<&str> = path.as_path().extension().and_then(OsStr::to_str);
            if path_ext != Some("yara") {
                continue;
            }

            // add rule to executor for parsing and bootstrapping a command
            rule_exec.add_rule(path)?;
        }
        rule_exec.execute()?;
        Some(rule_exec.matches)
    }

    pub fn output(self, format: &BinFormat) -> BinResult<String> {
        format.dump(self)
    }
}
