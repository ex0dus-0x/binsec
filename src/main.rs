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
use goblin::elf::dynamic::{tag_to_str, Dyn};
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
        TableCell::new_with_alignment("KERNEL SECURITY FEATURES", 2, Alignment::Center)
    ]));

    // check for RELRO
    let relro_headers: Vec<ProgramHeader> = elf.program_headers
        .iter()
        .filter(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_RELRO")
        .cloned()
        .collect();
    let mut relro_row = vec![TableCell::new("RELRO")];

    // RELRO is enabled
    if (relro_headers.len() >= 1) && (relro_headers[0].p_flags == 4) {

        // check for full/partial RELRO support
        if let Some(segs) = elf.dynamic {
            let dyn_segs: Vec<Dyn> = segs.dyns
                .iter()
                .filter(|tag| tag_to_str(tag.d_tag) == "DT_BIND_NOW")
                .cloned()
                .collect();
 
            if dyn_segs.len() == 0 {
                relro_row.push(TableCell::new_with_alignment("Partial RELRO enabled", 1, Alignment::Right));
            } else {
                relro_row.push(TableCell::new_with_alignment("Full RELRO enabled", 1, Alignment::Right));
            }
        }
    }
    // RELRO is not enabled
    else { 
        relro_row.push(TableCell::new_with_alignment("No RELRO enabled", 1, Alignment::Right));
    }
    table.add_row(Row::new(relro_row));


    // check for non-executable stack
    let stack_headers: Vec<ProgramHeader> = elf.program_headers
        .iter()
        .filter(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK")
        .cloned()
        .collect();
    let mut nx_row = vec![TableCell::new("NX bit")];

    // NX bit is set when GNU_STACK is read/write only (RW)
    if (stack_headers.len() >= 1) && (stack_headers[0].p_flags == 6) {
        nx_row.push(TableCell::new_with_alignment("Enabled", 1, Alignment::Right));
    } else {
        nx_row.push(TableCell::new_with_alignment("Not Enabled", 1, Alignment::Right));
    }
    table.add_row(Row::new(nx_row));


    // check for stack canary
    let strtab = elf.strtab.to_vec().unwrap();
    let str_sym: Vec<&str> = strtab
        .iter()
        .filter(|sym| *sym == &"__stack_chk_fail") // TODO: regex?
        .cloned()
        .collect();
    let mut sc_row = vec![TableCell::new("Stack Canary")];
   
    // stack canary not enabled
    if str_sym.len() == 0 { 
        sc_row.push(TableCell::new_with_alignment("Not Enabled", 1, Alignment::Right));
    }
    // stack canary enabled
    else {
        sc_row.push(TableCell::new_with_alignment("Enabled", 1, Alignment::Right));
    }
    table.add_row(Row::new(sc_row));

    // render and output table
    println!("{}", table.render());
}
