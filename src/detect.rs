//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.
#![allow(clippy::match_bool)]

use crate::check::common::{BasicInfo, Instrumentation};
use crate::check::elf::{ElfChecks, ElfCompilation, ElfHarden};
use crate::check::pe::{PeChecks, PeCompilation, PeHarden};
use crate::check::{Analyze, Detection};
use crate::errors::{BinError, BinResult};

use structmap::value::Value;
use structmap::{GenericMap, ToMap};

use goblin::mach::Mach;
use goblin::Object;

use byte_unit::Byte;
use chrono::prelude::*;

use std::fs;
use std::path::PathBuf;

/// Interfaces static analysis and wraps around parsed information for serialization.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Detector {
    basic: BasicInfo,
    compilation: Box<dyn Detection>,
    mitigations: Box<dyn Detection>,
    instrumentation: Instrumentation,
    //anti_analysis: AntiAnalysis,
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
            Err(_) => String::from("N/A"),
        };

        // universal compilation checks: pattern-match for compilers

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
                compilation: Box::new(ElfCompilation::default()),
                mitigations: Box::new(ElfHarden {
                    exec_stack: elf.exec_stack(),
                    pie: elf.aslr(),
                    relro: elf.relro(),
                    stack_canary: elf.symbol_match(|x| x == "__stack_chk_fail"),
                    fortify_source: elf.symbol_match(|x| x.ends_with("_chk")),
                }),
                instrumentation: Instrumentation {
                    afl: elf.symbol_match(|x| x.starts_with("__afl")),
                    asan: elf.symbol_match(|x| x.starts_with("__asan")),
                    ubsan: elf.symbol_match(|x| x.starts_with("__ubsan")),
                    llvm: elf.symbol_match(|x| x.starts_with("__llvm")),
                },
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
                compilation: Box::new(PeCompilation::default()),
                mitigations: Box::new(PeHarden {
                    dep: pe.parse_opt_header(0x0100),
                    cfg: pe.parse_opt_header(0x4000),
                    code_integrity: pe.parse_opt_header(0x0080),
                }),
                instrumentation: Instrumentation {
                    afl: pe.symbol_match(|x| x.starts_with("__afl")),
                    asan: pe.symbol_match(|x| x.starts_with("__asan")),
                    ubsan: pe.symbol_match(|x| x.starts_with("__ubsan")),
                    llvm: pe.symbol_match(|x| x.starts_with("__llvm")),
                },
            }),
            Object::Mach(Mach::Binary(_mach)) => todo!(),
            _ => Err(BinError::new("unsupported filetype for analysis")),
        }
    }

    /// Output all the finalized report collected on the specific executable, writing to
    /// JSON path if specificed not as `-`.
    pub fn output(&self, json: Option<&str>) -> serde_json::Result<()> {
        if let Some(_path) = json {
            let output: &str = &serde_json::to_string_pretty(self)?;
            if _path == "-" {
                println!("{}", output);
                return Ok(());
            } else {
                todo!()
            }
        }

        // get basic information first
        let basic_table: GenericMap = BasicInfo::to_genericmap(self.basic.clone());
        Detector::table("BASIC", basic_table);

        // get compilation-related information
        let compilation_table: GenericMap =
            if let Some(compilation) = self.compilation.as_any().downcast_ref::<ElfCompilation>() {
                ElfCompilation::to_genericmap(compilation.clone())
            } else {
                unreachable!()
            };
        Detector::table("COMPILATION", compilation_table);

        // exploit mitigations
        let mitigations_table: GenericMap =
            if let Some(mitigations) = self.mitigations.as_any().downcast_ref::<ElfHarden>() {
                ElfHarden::to_genericmap(mitigations.clone())
            } else if let Some(mitigations) = self.mitigations.as_any().downcast_ref::<PeHarden>() {
                PeHarden::to_genericmap(mitigations.clone())
            } else {
                unreachable!()
            };
        Detector::table("EXPLOIT MITIGATIONS", mitigations_table);

        // get instrumentation
        let inst_table: GenericMap = Instrumentation::to_genericmap(self.instrumentation.clone());
        Detector::table("INSTRUMENTATION", inst_table);
        Ok(())
    }

    #[inline]
    pub fn table(name: &str, mapping: GenericMap) {
        println!("-----------------------------------------------");
        println!("{}", name);
        println!("-----------------------------------------------\n");
        for (name, feature) in mapping {
            let value: String = match feature {
                Value::Bool(true) => String::from("\x1b[0;32m✔️\x1b[0m"),
                Value::Bool(false) => String::from("\x1b[0;31m✖️\x1b[0m"),
                Value::String(val) => val,
                _ => unimplemented!(),
            };
            println!("{0: <45} {1}", name, value);
        }
        println!();
    }
}
