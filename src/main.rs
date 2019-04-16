extern crate clap;
extern crate goblin;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use clap::{Arg, App};

#[cfg(target_pointer_width = "64")]
use goblin::elf64 as elf;

#[cfg(target_pointer_width = "32")]
use goblin::elf32 as elf;

use goblin::elf::{program_header, ProgramHeader};
use goblin::Object;


fn main() {

    // TODO: logging ??
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

    // check for RELRO
    let relro_headers: Vec<ProgramHeader> = elf.program_headers
        .iter()
        .filter(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_RELRO")
        .cloned()
        .collect();
    println!("{:?}", relro_headers[0]);

    // check for non-executable stack
    let nx_headers: Vec<ProgramHeader> = elf.program_headers
        .iter()
        .filter(|ph| program_header::pt_to_str(ph.p_type) == "PT_GNU_STACK")
        .cloned()
        .collect();
    println!("{:?}", nx_headers[0]);

    // check for stack canary
    let strtab = elf.strtab.to_vec().unwrap();
    for sym in strtab.iter() {
        if sym == &"__stack_chk_fail" {
            println!("stack canary enabled");
        }
    }


}
