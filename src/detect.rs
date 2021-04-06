//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.
#![allow(clippy::match_bool)]

use crate::check::{BasicInfo, Analyze, Detection};
use crate::errors::{BinError, BinResult};
use crate::format::FeatureMap;

use goblin::mach::Mach;
use goblin::Object;

use std::path::PathBuf;


/// Interfaces static analysis and wraps around parsed information for serialization.
//#[derive(serde::Serialize)]
pub struct Detector {
    basic: BasicInfo,
    harden: Box<dyn Detection>,
}

impl Detector {
    pub fn run(binpath: PathBuf) -> BinResult<Self> {
        let data: Vec<u8> = std::fs::read(binpath.as_path())?;
        match Object::parse(&data)? {
            Object::Elf(elf) => {
                let _ = elf.run_harden_checks();
                todo!()
            },
            Object::PE(pe) => {
                let _ = pe.run_harden_checks();
                todo!()
            }
            Object::Mach(Mach::binary(mach)) => {
                let _ = mach.run_harden_checks();
                todo!()
            },
            _ => {
                return Err(BinError::new("unsupported filetype for analysis")); 
            }
        }
    }

    /// If JSON path is specified, location will
    pub fn output(&self, json: Option<PathBuf>) {
        todo!()
    }
}
