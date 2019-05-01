//!
//! main.rs
//!
//!     main cli entry point to binsec
//!
extern crate clap;
extern crate term_table;
extern crate goblin;
extern crate serde;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::iter::Iterator;

use clap::{Arg, App};

use term_table::{
    row::Row,
    table_cell::{Alignment, TableCell},
};
use term_table::{Table, TableStyle};

#[cfg(target_pointer_width = "64")]
use goblin::elf64 as elf;

#[cfg(target_pointer_width = "32")]
use goblin::elf32 as elf;

use goblin::elf::{header, program_header, ProgramHeader};
use goblin::elf::dynamic::{tag_to_str, Dyn};
use goblin::Object;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
enum Relro {
    FullRelro,
    PartialRelro,
    NoRelro
}

/// struct that derives serde_json::Deserialize in order to properly
/// output JSON to stdout or file descriptor
#[derive(Serialize, Deserialize)]
struct Binsec {
    exec_stack:     bool,
    stack_canary:   bool,
    pie:            bool,
    relro:          Relro,
}

impl Default for Binsec {
    fn default () -> Binsec {
        Binsec {
            exec_stack: false,
            stack_canary: false,
            pie: false,
            relro: Relro::NoRelro
        }
    }
}


/// TODO(alan): parse with struct type attributes
/// parses an element within an ELF header / table / section based on a given predicate. Also
/// applies a user input function to elements of a vector before parsing out the element
#[allow(dead_code)]
fn parse_elem<'a, I: PartialEq<str> + Clone>(vec: Vec<I>, apply: &Fn(I) -> &'a str, predicate: &'a str) -> Option<&'a str> {
    vec.iter()
       .map(|num| apply(num.clone()))
       .find(|elem| *elem == predicate)
}


fn main () {
    let matches = App::new("binsec")
        .version("1.0")
        .author("Alan")
        .about("security features checker for ELF binaries")

        // general config flags
        .arg(Arg::with_name("BINARY")
             .help("sets binary to analyze")
             .index(1)
             .required(false))
        .arg(Arg::with_name("info")
             .help("outputs other binary info")
             .short("i")
             .long("info")
             .takes_value(false)
             .required(false))

        // deserialization option
        .arg(Arg::with_name("out_format")
             .help("sets serialization format for output")
             .short("f")
             .long("format")
             .takes_value(true)
             .value_name("FORMAT")
             .possible_values(&["raw", "json"])
             .required(false))
        .get_matches();


    // retrieve binary arg
    let binary = matches.value_of("BINARY").unwrap();

    // initialize path and file
    let path = Path::new(binary);
    let mut fd = File::open(path).unwrap();

    // read file to buffer and parse (continue only if ELF32/64)
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer).unwrap();
    let elf = match Object::parse(&buffer).unwrap() {
        Object::Elf(elf)    => elf,
        _                   => { panic!("unsupported binary format"); }
    };

    // output basic binary info if set
    // TODO: include to deserialized if flag set
    if matches.is_present("info") {

        // initialize blank style term table
        let mut basic_table = Table::new();
        basic_table.max_column_width = 60;
        basic_table.style = TableStyle::blank();

        // main header
        basic_table.add_row(Row::new(vec![
            TableCell::new_with_alignment("BASIC BINARY INFORMATION", 2, Alignment::Center)
        ]));

        // name
        basic_table.add_row(Row::new(vec![
            TableCell::new("Binary Name:"),
            TableCell::new_with_alignment(binary, 1, Alignment::Right)
        ]));

        // machine type
        basic_table.add_row(Row::new(vec![
            TableCell::new("Machine:"),
            TableCell::new_with_alignment(header::machine_to_str(elf.header.e_machine), 1, Alignment::Right)
        ]));

        // file class
        let file_class: &str = match elf.header.e_ident[4] {
            1 => "ELF32",
            2 => "ELF64",
            _ => "unknown"
        };
        basic_table.add_row(Row::new(vec![
            TableCell::new("Class:"),
            TableCell::new_with_alignment(file_class, 1, Alignment::Right)
        ]));

        // binary type
        basic_table.add_row(Row::new(vec![
            TableCell::new("Binary Type:"),
            TableCell::new_with_alignment(&header::et_to_str(elf.header.e_type), 1, Alignment::Right)
        ]));

        // program entry point
        basic_table.add_row(Row::new(vec![
            TableCell::new("Entry Point:"),
            TableCell::new_with_alignment(&format_args!("0x{:x}", elf.header.e_entry), 1, Alignment::Right)
        ]));

        // render table
        println!("{}", basic_table.render());
    }

    // initialize ASCII terminal table
    let mut table = Table::new();
    table.max_column_width = 60;
    table.style = TableStyle::extended();

    // header row
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("KERNEL SECURITY FEATURES", 2, Alignment::Center)
    ]));

    // initialize default binsec struct
    let mut binsec = Binsec::default();

    // check for non-executable stack
    // NX bit is set when GNU_STACK is read/write only (RW)
    let stack_header: Option<ProgramHeader> = elf.program_headers
        .iter()
        .find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK")
        .cloned();
    let mut nx_row = vec![TableCell::new("NX bit")];

    if let Some(sh) = stack_header {
        if sh.p_flags == 6 {
            binsec.exec_stack = true;
            nx_row.push(TableCell::new_with_alignment("Enabled", 1, Alignment::Right));
        }
    } else {
        binsec.exec_stack = false;
        nx_row.push(TableCell::new_with_alignment("Not Enabled", 1, Alignment::Right));
    }
    table.add_row(Row::new(nx_row));



    // check for RELRO
    let relro_header: Option<ProgramHeader> = elf.program_headers
        .iter()
        .find(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_RELRO")
        .cloned();
    let mut relro_row = vec![TableCell::new("RELRO")];

    if let Some(rh) = relro_header {
        if rh.p_flags == 4 {

            // check for full/partial RELRO support
            if let Some(segs) = elf.dynamic {
                let dyn_seg: Option<Dyn> = segs.dyns
                    .iter()
                    .find(|tag| tag_to_str(tag.d_tag) == "DT_BIND_NOW")
                    .cloned();

                if let None = dyn_seg {
                    binsec.relro = Relro::PartialRelro;
                    relro_row.push(TableCell::new_with_alignment("Partial RELRO enabled", 1, Alignment::Right));
                } else {
                    binsec.relro = Relro::FullRelro;
                    relro_row.push(TableCell::new_with_alignment("Full RELRO enabled", 1, Alignment::Right));
                }
            }
        }
    } else {
        binsec.relro = Relro::NoRelro;
        relro_row.push(TableCell::new_with_alignment("No RELRO enabled", 1, Alignment::Right));
    }
    table.add_row(Row::new(relro_row));


    // check for stack canary
    let strtab = elf.strtab.to_vec().unwrap();
    let str_sym: Option<_> = strtab
        .iter()
        .find(|sym| sym.contains("__stack_chk_fail"))
        .cloned();
    let mut sc_row = vec![TableCell::new("Stack Canary")];

    if let None = str_sym {
        binsec.stack_canary = false;
        sc_row.push(TableCell::new_with_alignment("Not Enabled", 1, Alignment::Right));
    } else {
        binsec.stack_canary = true;
        sc_row.push(TableCell::new_with_alignment("Enabled", 1, Alignment::Right));
    }
    table.add_row(Row::new(sc_row));


    // check if position-independent executable
    let e_type = elf.header.e_type;
    let mut pie_row = vec![TableCell::new("PIE")];
    match e_type {

        // ET_EXEC
        2 => {
            binsec.pie = false;
            pie_row.push(TableCell::new_with_alignment("PIE disabled (executable)", 1, Alignment::Right));
        }

        // ET_DYN
        3 => {
            // TODO: check if shared object
            binsec.pie = true;
            pie_row.push(TableCell::new_with_alignment("PIE enabled (PIE executable)", 1, Alignment::Right));
        },

        // ET_*
        _                  => {
            binsec.pie = false;
            pie_row.push(TableCell::new_with_alignment("Unknown (unknown filetype)", 1, Alignment::Right));
        }
    }
    table.add_row(Row::new(pie_row));

    // TODO: SELinux, fortify-source, runpath

    // render and output based on out_format
    match matches.value_of("out_format") {
        Some("json")                    => {
            println!("{}", serde_json::to_string_pretty(&binsec).unwrap());
        },
        Some("raw") | Some(&_) | None   => {
            println!("{}", table.render());
        }
    }
}
