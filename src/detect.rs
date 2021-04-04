//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.
#![allow(clippy::match_bool)]

use crate::check::{BasicInfo, Analyze};
use crate::errors::{BinError, BinResult};
use crate::format::FeatureMap;

use goblin::mach::Mach;
use goblin::Object;

use std::fs;
use std::path::PathBuf;


/// Interfaces static analysis and wraps around parsed information for serialization.
#[derive(serde::Serialize)]
pub struct Detector {
    basic: BasicInfo,
    //specific:
    //harden:
}

impl Detector {
    pub fn run(binpath: PathBuf) -> BinResult<Self> {
        let data: Vec<u8> = std::fs::read(binpath.as_path())?;
        match Object::parse(&data)? {
            Object::Elf(elf) => {
                let _ = elf.run_harden_check();
                todo!()
            },
            Object::PE(pe) => {
                let _ = pe.run_harden_check();
                todo!()
            }
            Object::Mach(_mach) => match _mach {
                Mach::Binary(mach) => {
                    let _ = mach.run_harden_check();
                    todo!()
                },
                Mach::Fat(_) => {
                    return Err(BinError::new("does not support multiarch FAT binary containers yet"));
                }
            },
            _ => {
                return Err(BinError::new("unsupported filetype for analysis")); 
            }
        }
    }

    pub fn output(&self, json: Option<PathBuf>) {
        todo!()
    }
}
