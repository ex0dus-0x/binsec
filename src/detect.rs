//! Implements the main interface struct necessary in order to consume, parse and detect binary
//! inputs. Should be used to detect format and security mitigations for a singular binary.
#![allow(clippy::match_bool)]

use crate::check::{Analyze, GenericMap};
use crate::errors::{BinError, BinResult};
use crate::rules;

use goblin::mach::Mach;
use goblin::Object;

use yara::Compiler;

use byte_unit::Byte;
use chrono::prelude::*;
use serde_json::{json, Value};

use std::fs;
use std::path::PathBuf;

/// Interfaces static analysis and wraps around parsed information for serialization.
#[derive(serde::Serialize)]
pub struct Detector {
    basic: GenericMap,
    compilation: GenericMap,
    mitigations: GenericMap,
    instrumentation: Option<GenericMap>,
    //anti_analysis: AntiAnalysis,
}

impl Detector {
    pub fn run(binpath: PathBuf) -> BinResult<Self> {
        let mut basic_map = GenericMap::new();

        // get absolute path to executable
        let _abspath: PathBuf = fs::canonicalize(&binpath)?;
        let abspath = _abspath.to_str().unwrap().to_string();
        basic_map.insert("Absolute Path".to_string(), json!(abspath));

        // parse out initial metadata used in all binary fomrats
        let metadata: fs::Metadata = fs::metadata(&binpath)?;

        // filesize with readable byte unit
        let size: u128 = metadata.len() as u128;
        let byte = Byte::from_bytes(size);
        let filesize: String = byte.get_appropriate_unit(false).to_string();
        basic_map.insert("File Size".to_string(), json!(filesize));

        // parse out readable modified timestamp
        if let Ok(time) = metadata.accessed() {
            let datetime: DateTime<Utc> = time.into();
            let stamp: String = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
            basic_map.insert("Last Modified".to_string(), json!(stamp));
        }

        // read raw binary from path
        let data: Vec<u8> = std::fs::read(&binpath)?;

        // detect presence of dynamic instrumentation frameworks
        let instrumentation = Detector::detect_instrumentation(&data)?;

        // parse executable as format and run format-specific mitigation checks
        match Object::parse(&data)? {
            Object::Elf(elf) => Ok(Self {
                basic: {
                    use goblin::elf::header;

                    basic_map.insert("Binary Format".to_string(), json!("ELF"));

                    // get architecture
                    let arch: String = header::machine_to_str(elf.header.e_machine).to_string();
                    basic_map.insert("Architecture".to_string(), json!(arch));

                    // get entry point
                    let entry_point: String = format!("0x{:x}", elf.header.e_entry);
                    basic_map.insert("Entry Point Address".to_string(), json!(entry_point));
                    basic_map
                },
                compilation: elf.run_compilation_checks(),
                mitigations: elf.run_mitigation_checks(),
                instrumentation,
            }),
            Object::PE(pe) => Ok(Self {
                basic: {
                    basic_map.insert("Binary Format".to_string(), json!("PE/EXE"));

                    // get architecture
                    let arch: String = if pe.is_64 {
                        String::from("PE32+")
                    } else {
                        String::from("PE32")
                    };
                    basic_map.insert("Architecture".to_string(), json!(arch));

                    // get entry point
                    let entry_point: String = format!("0x{:x}", pe.entry);
                    basic_map.insert("Entry Point Address".to_string(), json!(entry_point));
                    basic_map
                },
                compilation: pe.run_compilation_checks(),
                mitigations: pe.run_mitigation_checks(),
                instrumentation,
            }),
            Object::Mach(Mach::Binary(mach)) => Ok(Self {
                basic: {
                    basic_map.insert("Binary Format".to_string(), json!("Mach-O"));
                    basic_map
                },
                compilation: mach.run_compilation_checks(),
                mitigations: mach.run_mitigation_checks(),
                instrumentation,
            }),
            _ => Err(BinError::new("unsupported filetype for analysis")),
        }
    }

    #[inline]
    fn detect_instrumentation(data: &[u8]) -> BinResult<Option<GenericMap>> {
        use yara::MetadataValue;

        // execute YARA rules for instrumentation frameworks
        let mut compiler = Compiler::new()?;
        compiler.add_rules_str(rules::INSTRUMENTATION_RULES)?;
        let rules = compiler.compile_rules()?;

        // parse out matches into genericmap
        let inst_matches = rules.scan_mem(&data, 5)?;
        let mut instrumentation = GenericMap::new();
        for rule in inst_matches.iter() {
            if let MetadataValue::String(name) = rule.metadatas[0].value {
                instrumentation.insert(String::from(name), json!(true));
            }
        }

        if instrumentation.is_empty() {
            Ok(None)
        } else {
            Ok(Some(instrumentation))
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

        // will always be printed
        Detector::table("BASIC", self.basic.clone());
        Detector::table("COMPILATION", self.compilation.clone());
        Detector::table("EXPLOIT MITIGATIONS", self.mitigations.clone());

        // get instrumentation if any are set
        if let Some(instrumentation) = &self.instrumentation {
            Detector::table("INSTRUMENTATION", instrumentation.clone());
        }
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
