//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.
#![allow(clippy::match_bool)]

use crate::check::{BasicInfo, Analyze, Detection};
use crate::check::elf::ElfHarden;
use crate::check::pe::PeHarden;
use crate::errors::{BinError, BinResult};
use crate::format::FeatureMap;

use goblin::mach::Mach;
use goblin::Object;

use byte_unit::{Byte, ByteUnit};

use std::fs;
use std::path::PathBuf;


/// Interfaces static analysis and wraps around parsed information for serialization.
//#[derive(serde::Serialize)]
pub struct Detector {
    basic: BasicInfo,
    /*
    compilation: Box<dyn Detection>,
    */
    harden: Box<dyn Detection>,
    /*
    instrumentation: Box<dyn Detection>,
    matches: Box<dyn Detection>,
    */
}

impl Detector {
    pub fn run(binpath: PathBuf) -> BinResult<Self> {
        let _abspath: PathBuf = fs::canonicalize(&binpath)?;
        let abspath = _abspath.to_str().unwrap().to_string();

        // parse out initial metadata used in all binary fomrats
        let metadata: fs::Metadata = fs::metadata(&binpath)?;

        // filesize with readable byte unit
        let size: u128 = metadata.len() as u128;
        let byte = Byte::from_bytes(size);
        let filesize: String = byte.get_appropriate_unit(false).to_string();

        // parse out readable modified timestamp
        let timestamp: Option<String> = match metadata.accessed() {
            Ok(time) => Some(String::new()),
            Err(_) => None,
        };

        let data: Vec<u8> = std::fs::read(&binpath)?;
        match Object::parse(&data)? {
            Object::Elf(elf) => {
                Ok(Self {
                    basic: BasicInfo {
                        abspath,
                        format: String::from("ELF"),
                        arch: elf.get_architecture(),
                        timestamp,
                        filesize,
                        entry_point: elf.get_entry_point(),
                    },
                    harden: Box::new(ElfHarden {
                        exec_stack: elf.exec_stack(),
                        pie: elf.aslr(),
                        relro: String::new(),
                        stack_canary: elf.symbol_match(|x| { x == "__stack_chk_fail" }),
                        fortify_source: elf.symbol_match(|x| { x.ends_with("_chk") }),
                    }),
                })
            },
            Object::PE(pe) => {
                Ok(Self {
                    basic: BasicInfo {
                        abspath,
                        format: String::from("PE/EXE"),
                        arch: pe.get_architecture(),
                        timestamp,
                        filesize,
                        entry_point: pe.get_entry_point(),
                    },
                    harden: Box::new(PeHarden {
                        dep: pe.exec_stack(),
                        cfg: true,
                        code_integrity: true,
                    }),
                })
            }
            Object::Mach(Mach::Binary(mach)) => {
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
