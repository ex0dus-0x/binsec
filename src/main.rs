extern crate clap;
extern crate term_table;
extern crate goblin;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

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

use goblin::elf::{program_header, ProgramHeader};
use goblin::Object;


fn main() {

    // TODO: emit json or protobuf
    // TODO: additional info
    let matches = App::new("binsec")
        .version("1.0")
        .author("Alan")
        .about("security features checker for ELF binaries")
        .arg(Arg::with_name("BINARY")
             .help("sets binary to analyze")
             .required(true)
             .index(1))
        .get_matches();

    // parse binary (only if ELF32/64)
    let binary = matches.value_of("BINARY").unwrap();

    // initialize path and file
    let path = Path::new(binary);
    let mut fd = File::open(path).unwrap();

    // read file to buffer and parse
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer).unwrap();
    let elf = match Object::parse(&buffer).unwrap() {
        Object::Elf(elf)    => elf,
        _                   => { panic!("unsupported binary format"); }
    };

    // initialize ASCII terminal table
    let mut table = Table::new();
    table.max_column_width = 40;
    table.style = TableStyle::extended();

    // header row
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Security Features", 2, Alignment::Center)
    ])); 

    // check for RELRO
    let relro_headers: Vec<ProgramHeader> = elf.program_headers
        .iter()
        .filter(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_RELRO")
        .cloned()
        .collect();

    table.add_row(Row::new(vec![
        TableCell::new("RELRO"),
        TableCell::new_with_alignment("This is right aligned text", 1, Alignment::Right)
    ]));


    // check for non-executable stack
    let nx_headers: Vec<ProgramHeader> = elf.program_headers
        .iter()
        .filter(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK")
        .cloned()
        .collect();

    table.add_row(Row::new(vec![
        TableCell::new("NX"),
        TableCell::new_with_alignment("This is right aligned text", 1, Alignment::Right)
    ]));


    // check for stack canary
    let strtab = elf.strtab.to_vec().unwrap();
    for sym in strtab.iter() {
        if sym == &"__stack_chk_fail" {
            println!("stack canary enabled");
        }
    }

    println!("{}", table.render());
}
