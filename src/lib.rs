//! Library interface for binsec static detection functionality.
//! Implements the deserializable components for output/file IO, and
//! the main detection interface for parsing the binary for features to output.

pub mod check;
pub mod detect;
pub mod errors;

/*
#![allow(unused_imports)]

use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

impl Default for Binsec {
    fn default() -> Self {
        Self {
            exec_stack: false,
            stack_canary: false,
            pie: false,
            relro: Relro::NoRelro,
        }
    }
}

/// `Detector` defines the main interface struct for CLI. Used to store parsed cli opts
/// generate a Binsec struct, and output accordingly using a builder pattern.
pub struct Detector {
    path: PathBuf,
    pub basic_info: Option<BinInfo>,
    pub features: Binsec,
}

impl Default for Detector {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            basic_info: None,
            features: Binsec::default(),
        }
    }
}

impl Detector {
    /// `new()` initializes a binsec detector by setting necessary output options,
    /// and initializing a default Binsec struct.
    pub fn new(_binary: String) -> io::Result<Self> {
        // initialize absolute path and parse binary
        let _path = Path::new(_binary.as_str());

        // get full absolute path to binary
        let path = fs::canonicalize(_path.to_path_buf())?;
        Ok(Self {
            path,
            ..Detector::default()
       })
    }

    /// `basic_info()` is a helper method that parses out basic ELF binary information and
    /// returns it in a de/serializable BinInfo object.
    #[inline]
    fn basic_info(header: header::Header) -> BinInfo {
        // TODO: detect other non-Linux file types
        let file_class: &str = match header.e_ident[4] {
            1 => "ELF32",
            2 => "ELF64",
            _ => "unknown",
        };

        // build up `basic_info` attribute with binary information
        BinInfo {
            machine: header::machine_to_str(header.e_machine).to_string(),
            file_class: file_class.to_string(),
            bin_type: header::et_to_str(header.e_type).to_string(),
            entry_point: header.e_entry,
        }
    }

    /// `detect()` statically checks for security features for instantiated binary,
    /// and updates default instantiated features attribute.
    pub fn detect(&mut self, basic_info: bool) -> io::Result<&Self> {
        let mut fd = File::open(self.path.clone())?;

        // read file to buffer and parse (continue only if ELF32/64)
        let buffer = {
            let mut v = Vec::new();
            fd.read_exact(&mut v)?;
            v
        };
        let elf = match Object::parse(&buffer).unwrap() {
            Object::Elf(elf) => elf,
            _ => {
                panic!("unsupported binary format");
            }
        };

        // check if flag is configured, and build up BinInfo from ELF header
        if basic_info {
            let header: header::Header = elf.header;
            self.basic_info = Some(Detector::basic_info(header));
        }

        // non-exec stack: NX bit is set when GNU_STACK is read/write
        let stack_header: Option<ProgramHeader> = elf
            .program_headers
            .iter()
            .find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK")
            .cloned();

        if let Some(sh) = stack_header {
            if sh.p_flags == 6 {
                self.features.exec_stack = true
            }
        }

        // check for RELRO
        let relro_header: Option<ProgramHeader> = elf
            .program_headers
            .iter()
            .find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_RELRO")
            .cloned();

        if let Some(rh) = relro_header {
            if rh.p_flags == 4 {
                // check for full/partial RELRO support by checking dynamic section for DT_BIND_NOW flag.
                // DT_BIND_NOW takes precedence over lazy binding and processes relocations before actual execution.
                if let Some(segs) = &elf.dynamic {
                    let dyn_seg: Option<Dyn> = segs
                        .dyns
                        .iter()
                        .find(|tag| tag_to_str(tag.d_tag) == "DT_BIND_NOW")
                        .cloned();

                    if dyn_seg.is_none() {
                        self.features.relro = Relro::PartialRelro;
                    } else {
                        self.features.relro = Relro::FullRelro;
                    }
                }
            }
        }

        // check for stack canary
        let strtab = elf.strtab.to_vec().unwrap();
        let str_sym: Option<_> = strtab
            .iter()
            .find(|sym| sym.contains("__stack_chk_fail"))
            .cloned();

        if str_sym.is_some() {
            self.features.stack_canary = true;
        }

        // check for position-independent executable
        let e_type = elf.header.e_type;
        match e_type {
            3 => {
                self.features.pie = true;
            }
            _ => {
                self.features.pie = false;
            }
        }
        Ok(self)
    }

    /// `output()` takes a configuration of a format in order to properly display serializable or raw out.
    /// If set to output raw data, an ASCII terminal table is also used for visual display.
    pub fn output(&self, format: &Format) {
        if let Some(elf_info) = &self.basic_info {
            match format {
                Format::Normal => {
                    // initialize blank style term table
                    let mut basic_table = Table::new();
                    basic_table.max_column_width = 60;
                    basic_table.style = TableStyle::blank();

                    // main header
                    basic_table.add_row(Row::new(vec![TableCell::new_with_alignment(
                        "BASIC BINARY INFORMATION".underline(),
                        2,
                        Alignment::Center,
                    )]));

                    // path
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Binary Path:"),
                        TableCell::new_with_alignment(
                            self.path.to_str().unwrap(),
                            1,
                            Alignment::Right,
                        ),
                    ]));

                    // machine type
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Machine:"),
                        TableCell::new_with_alignment(&elf_info.machine, 1, Alignment::Right),
                    ]));

                    // file class
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Class:"),
                        TableCell::new_with_alignment(&elf_info.file_class, 1, Alignment::Right),
                    ]));

                    // binary type
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Binary Type:"),
                        TableCell::new_with_alignment(&elf_info.bin_type, 1, Alignment::Right),
                    ]));

                    // program entry point
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Entry Point:"),
                        TableCell::new_with_alignment(
                            &format_args!("0x{:x}", elf_info.entry_point),
                            1,
                            Alignment::Right,
                        ),
                    ]));
                    println!("{}", basic_table.render());
                }
                Format::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&self.basic_info).unwrap()
                    );
                }
                Format::Toml => {
                    println!("{}", toml::to_string(&self.features).unwrap());
                }
            }
        }

        // output security features
        match format {
            Format::Normal => {
                // initialize ASCII terminal table
                let mut table = Table::new();
                table.max_column_width = 60;
                table.style = TableStyle::blank();

                // header row
                table.add_row(Row::new(vec![TableCell::new_with_alignment(
                    "KERNEL SECURITY FEATURES".underline(),
                    2,
                    Alignment::Center,
                )]));

                // NX row
                let mut nx_row = vec![TableCell::new("NX bit")];
                if self.features.exec_stack {
                    nx_row.push(TableCell::new_with_alignment(
                        "Enabled".green(),
                        1,
                        Alignment::Right,
                    ));
                } else {
                    nx_row.push(TableCell::new_with_alignment(
                        "Disabled".red(),
                        1,
                        Alignment::Right,
                    ));
                }
                table.add_row(Row::new(nx_row));

                // RELRO row
                let mut relro_row = vec![TableCell::new("RELRO")];
                match self.features.relro {
                    Relro::PartialRelro => {
                        relro_row.push(TableCell::new_with_alignment(
                            "Partial RELRO enabled".yellow(),
                            1,
                            Alignment::Right,
                        ));
                    }
                    Relro::FullRelro => {
                        relro_row.push(TableCell::new_with_alignment(
                            "Full RELRO enabled".green(),
                            1,
                            Alignment::Right,
                        ));
                    }
                    Relro::NoRelro => {
                        relro_row.push(TableCell::new_with_alignment(
                            "No RELRO enabled".red(),
                            1,
                            Alignment::Right,
                        ));
                    }
                }
                table.add_row(Row::new(relro_row));

                // stack canary row
                let mut sc_row = vec![TableCell::new("Stack Canary")];
                if self.features.stack_canary {
                    sc_row.push(TableCell::new_with_alignment(
                        "Enabled".green(),
                        1,
                        Alignment::Right,
                    ));
                } else {
                    sc_row.push(TableCell::new_with_alignment(
                        "Not Enabled".red(),
                        1,
                        Alignment::Right,
                    ));
                }
                table.add_row(Row::new(sc_row));

                // PIE row
                let mut pie_row = vec![TableCell::new("PIE")];
                if self.features.pie {
                    pie_row.push(TableCell::new_with_alignment(
                        "PIE enabled (PIE executable)".green(),
                        1,
                        Alignment::Right,
                    ));
                } else {
                    //pie_row.push(TableCell::new_with_alignment("Unknown (unknown filetype)", 1, Alignment::Right));
                    pie_row.push(TableCell::new_with_alignment(
                        "PIE disabled (executable)".red(),
                        1,
                        Alignment::Right,
                    ));
                }
                table.add_row(Row::new(pie_row));
                println!("{}", table.render());
            }
            Format::Json => {
                println!("{}", serde_json::to_string_pretty(&self.features).unwrap());
            }
            Format::Toml => {
                println!("{}", toml::to_string(&self.features).unwrap());
            }
        }
    }
}
*/
