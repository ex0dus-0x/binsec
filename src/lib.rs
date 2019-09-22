//! lib.rs
//!
//!		Library interface for binsec static detection functionality

use std::fs;
use std::io;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::prelude::*;

use serde::{Serialize, Deserialize};

use colored::*;

use term_table::{
    row::Row,
    table_cell::{Alignment, TableCell},
};
use term_table::{Table, TableStyle};

#[cfg(target_pointer_width = "64")]
use goblin::elf64 as elf;

#[cfg(target_pointer_width = "32")]
use goblin::elf32 as elf;

use goblin::Object;
use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::elf::{header, program_header, ProgramHeader};


#[derive(Serialize, Deserialize)]
pub enum Relro {
    FullRelro,
    PartialRelro,
    NoRelro
}

pub enum Format {
	Normal,
	Json,
	Toml
}


/// struct defining parsed basic information from ELF binary
/// to be outputted and deserialized if user chooses to.
#[derive(Default, Serialize, Deserialize)]
pub struct BinInfo {
	pub path: PathBuf,
	pub machine: String,
	pub file_class: String,
	pub bin_type: String,
	pub entry_point: u64
}


/// struct defining security features parsed from ELF, and
/// derives serde de/serialize traits for structured output.
/// TODO: SELinux, fortify-source, runpath
#[derive(Serialize, Deserialize)]
pub struct Binsec {
    pub exec_stack: bool,
    pub stack_canary: bool,
    pub pie: bool,
    pub relro: Relro,
}

impl Default for Binsec {
    fn default () -> Self {
        Self {
            exec_stack: false,
            stack_canary: false,
            pie: false,
            relro: Relro::NoRelro
        }
    }
}


/// main interface struct for CLI. Used to store parsed cli opts
/// generate a Binsec struct, and output accordingly using a builder pattern.
pub struct Detector {
	binary: String,
	pub basic_info: Option<BinInfo>,
	pub features: Binsec,
}

impl Default for Detector {
	fn default() -> Self {
		Self {
            binary: String::new(),
			basic_info: None,
			features: Binsec::default()
		}
	}
}

impl Detector {

	/// `new` initializes a binsec detector by setting necessary output options,
	/// and initializing a default Binsec struct.
	pub fn new(binary: String, info_flag: bool) -> Self {
		if info_flag {
			let basic_info = Some(BinInfo::default());
			Self { binary, basic_info, ..Detector::default() }
		} else {
			Self { binary, ..Detector::default() }
		}
	}


	/// `detect()` statically checks for security features for instantiated binary,
	/// and updates defaultly instantiated features attribute.
	pub fn detect(&mut self) -> io::Result<&Self> {

        // initialize path and file
		let path = Path::new(&self.binary);
		let mut fd = File::open(path)?;

        // read file to buffer and parse (continue only if ELF32/64)
		let buffer = { let mut v = Vec::new(); fd.read_to_end(&mut v)?; v};
		let elf = match Object::parse(&buffer).unwrap() {
			Object::Elf(elf) => elf,
			_	=> { panic!("unsupported binary format"); }
		};

        // first, detect basic features if set and build BinInfo struct
        if let Some(_) = self.basic_info {

            let bin_path = fs::canonicalize(path.to_path_buf())?;

            let file_class: &str = match elf.header.e_ident[4] {
                1 => "ELF32",
                2 => "ELF64",
                _ => "unknown"
            };

            self.basic_info = Some(BinInfo {
                path: bin_path,
                machine: header::machine_to_str(elf.header.e_machine).to_string(),
                file_class: file_class.to_string(),
                bin_type: header::et_to_str(elf.header.e_type).to_string(),
                entry_point: elf.header.e_entry,
            });
        }

        // now check for actual security features

		// non-exec stack: NX bit is set when GNU_STACK is read/write
		let stack_header: Option<ProgramHeader> = elf.program_headers
			.iter()
			.find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK")
			.cloned();

		if let Some(sh) = stack_header {
			if sh.p_flags == 6 {
				self.features.exec_stack = true
			}
		}

		// check for RELRO
		let relro_header: Option<ProgramHeader> = elf.program_headers
			.iter()
			.find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_RELRO")
			.cloned();

		if let Some(rh) = relro_header {
			if rh.p_flags == 4 {

				// check for full/partial RELRO support by checking dynamic section for DT_BIND_NOW flag.
				// DT_BIND_NOW takes precedence over lazy binding and processes relocations before actual execution.
				if let Some(segs) = elf.dynamic {
					let dyn_seg: Option<Dyn> = segs.dyns
						.iter()
						.find(|tag| tag_to_str(tag.d_tag) == "DT_BIND_NOW")
						.cloned();

					if let None = dyn_seg {
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

		if let Some(_) = str_sym {
			self.features.stack_canary = true;
		}

		// check for position-independent executable
		let e_type = elf.header.e_type;
		match e_type {
			3 	  => { self.features.pie = true; },
			2 | _ => { self.features.pie = false; }
		}
		Ok(self)
	}

    /// `output` takes a configuration of a format in order to
    /// properly display serializable or raw out.
	pub fn output(&self, format: &Format) -> () {
		if let Some(elf_info) = &self.basic_info {

            // output table
            match format {
                Format::Normal => {

                    // initialize blank style term table
                    let mut basic_table = Table::new();
                    basic_table.max_column_width = 60;
                    basic_table.style = TableStyle::blank();

                    // main header
                    basic_table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("BASIC BINARY INFORMATION".underline(), 2, Alignment::Center)
                    ]));

                    // path
                    let path = elf_info.path.to_str().unwrap();
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Binary Path:"),
                        TableCell::new_with_alignment(path, 1, Alignment::Right)
                    ]));

                    // machine type
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Machine:"),
                        TableCell::new_with_alignment(&elf_info.machine, 1, Alignment::Right)
                    ]));

                    // file class
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Class:"),
                        TableCell::new_with_alignment(&elf_info.file_class, 1, Alignment::Right)
                    ]));

                    // binary type
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Binary Type:"),
                        TableCell::new_with_alignment(&elf_info.bin_type, 1, Alignment::Right)
                    ]));

                    // program entry point
                    basic_table.add_row(Row::new(vec![
                        TableCell::new("Entry Point:"),
                        TableCell::new_with_alignment(&format_args!("0x{:x}", elf_info.entry_point), 1, Alignment::Right)
                    ]));
                    println!("{}", basic_table.render());
                },
                Format::Json => {
                    println!("{}", serde_json::to_string_pretty(&self.basic_info).unwrap());
                },
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
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment("KERNEL SECURITY FEATURES".underline(), 2, Alignment::Center)
                ]));

                // NX row
                let mut nx_row = vec![TableCell::new("NX bit")];
                if self.features.exec_stack {
                    nx_row.push(TableCell::new_with_alignment("Enabled".green(), 1, Alignment::Right));
                } else {
                    nx_row.push(TableCell::new_with_alignment("Disabled".red(), 1, Alignment::Right));
                }
                table.add_row(Row::new(nx_row));

                // RELRO row
                let mut relro_row = vec![TableCell::new("RELRO")];
                match self.features.relro {
                    Relro::PartialRelro => {
                        relro_row.push(TableCell::new_with_alignment("Partial RELRO enabled".yellow(), 1, Alignment::Right));
                    },
                    Relro::FullRelro => {
                        relro_row.push(TableCell::new_with_alignment("Full RELRO enabled".green(), 1, Alignment::Right));
                    },
                    Relro::NoRelro => {
                        relro_row.push(TableCell::new_with_alignment("No RELRO enabled".red(), 1, Alignment::Right));
                    }
                }
                table.add_row(Row::new(relro_row));

                // stack canary row
                let mut sc_row = vec![TableCell::new("Stack Canary")];
                if self.features.stack_canary {
                    sc_row.push(TableCell::new_with_alignment("Enabled".green(), 1, Alignment::Right));
                } else {
                    sc_row.push(TableCell::new_with_alignment("Not Enabled".red(), 1, Alignment::Right));
                }
                table.add_row(Row::new(sc_row));

                // PIE row
                let mut pie_row = vec![TableCell::new("PIE")];
                if self.features.pie {
                    pie_row.push(TableCell::new_with_alignment("PIE enabled (PIE executable)".green(), 1, Alignment::Right));
                } else {
                    //pie_row.push(TableCell::new_with_alignment("Unknown (unknown filetype)", 1, Alignment::Right));
                    pie_row.push(TableCell::new_with_alignment("PIE disabled (executable)".red(), 1, Alignment::Right));
                }
                table.add_row(Row::new(pie_row));
                println!("{}", table.render());
            },
            Format::Json => {
                println!("{}", serde_json::to_string_pretty(&self.features).unwrap());
            },
            Format::Toml => {
                println!("{}", toml::to_string(&self.features).unwrap());
            }
	    }
    }
}
