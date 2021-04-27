//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.
#![allow(clippy::match_bool)]

use crate::check::elf::{ElfChecks, ElfHarden};
use crate::check::pe::{PeChecks, PeHarden};
use crate::check::{Analyze, BasicInfo, Detection, Instrumentation};
use crate::errors::{BinError, BinResult};
use crate::format::{self, FeatureMap};

use goblin::mach::Mach;
use goblin::Object;

use byte_unit::Byte;
use chrono::prelude::*;

use structmap::ToMap;

use std::fs;
use std::path::PathBuf;

/// Interfaces static analysis and wraps around parsed information for serialization.
//#[derive(serde::Serialize)]
pub struct Detector {
    basic: BasicInfo,
    //compilation: Box<dyn Detection>,
    harden: Box<dyn Detection>,
    instrumentation: Option<Instrumentation>,
    //matches: Box<dyn Detection>,
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
        let timestamp: String = match metadata.accessed() {
            Ok(time) => {
                let datetime: DateTime<Utc> = time.into();
                datetime.format("%Y-%m-%d %H:%M:%S").to_string()
            }
            Err(_) => String::from(""),
        };

        let data: Vec<u8> = std::fs::read(&binpath)?;
        match Object::parse(&data)? {
            Object::Elf(elf) => Ok(Self {
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
                    relro: elf.relro(),
                    stack_canary: elf.symbol_match(|x| x == "__stack_chk_fail"),
                    fortify_source: elf.symbol_match(|x| x.ends_with("_chk")),
                }),
                instrumentation: Some(Instrumentation {
                    afl: elf.symbol_match(|x| x.starts_with("__afl")),
                    asan: elf.symbol_match(|x| x.starts_with("__asan")),
                    ubsan: elf.symbol_match(|x| x.starts_with("__ubsan")),
                    llvm: elf.symbol_match(|x| x.starts_with("__llvm")),
                }),
            }),
            Object::PE(pe) => Ok(Self {
                basic: BasicInfo {
                    abspath,
                    format: String::from("PE/EXE"),
                    arch: pe.get_architecture(),
                    timestamp,
                    filesize,
                    entry_point: pe.get_entry_point(),
                },
                harden: Box::new(PeHarden {
                    dep: pe.parse_opt_header(0x0100),
                    cfg: pe.parse_opt_header(0x4000),
                    code_integrity: pe.parse_opt_header(0x0080),
                }),
                instrumentation: Some(Instrumentation {
                    afl: pe.symbol_match(|x| x.starts_with("__afl")),
                    asan: pe.symbol_match(|x| x.starts_with("__asan")),
                    ubsan: pe.symbol_match(|x| x.starts_with("__ubsan")),
                    llvm: pe.symbol_match(|x| x.starts_with("__llvm")),
                }),
            }),
            Object::Mach(Mach::Binary(_mach)) => todo!(),
            _ => {
                return Err(BinError::new("unsupported filetype for analysis"));
            }
        }
    }

    /// If JSON path is specified, location will
    pub fn output(&self, json: Option<PathBuf>) {
        if let Some(path) = json {
            return ();
        }

        // get basic information first
        let basic_table: FeatureMap = BasicInfo::to_genericmap(self.basic.clone());
        println!("{}", format::generate_table("BASIC", basic_table));

        // exploit mitigations
        let mitigations: FeatureMap =
            if let Some(harden) = self.harden.as_any().downcast_ref::<ElfHarden>() {
                ElfHarden::to_genericmap(harden.clone())
            } else if let Some(harden) = self.harden.as_any().downcast_ref::<PeHarden>() {
                PeHarden::to_genericmap(harden.clone())
            } else {
                todo!()
            };
        println!(
            "{}",
            format::generate_table("EXPLOIT MITIGATIONS", mitigations)
        );

        // get instrumentation is
        if let Some(inst) = &self.instrumentation {
            let inst_table: FeatureMap = Instrumentation::to_genericmap(inst.clone());
            println!("{}", format::generate_table("INSTRUMENTATION", inst_table));
        }
    }
}
