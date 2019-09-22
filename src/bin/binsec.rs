//! binsec.rs
//!
//!     main cli entry point to binsec application.
//!
extern crate clap;
extern crate term_table;
extern crate colored;
extern crate goblin;
extern crate serde;
extern crate binsec;

use std::iter::Iterator;

use clap::{Arg, App, AppSettings};
use colored::*;
use binsec::{Detector, Format};


/// TODO(alan): parse with struct type attributes
/// parses an element within an ELF header / table / section based on a given predicate. Also
/// applies a user input function to elements of a vector before parsing out the element
#[allow(dead_code)]
fn parse_elem<'a, I: PartialEq<str> + Clone>(vec: Vec<I>, apply: &Fn(I) -> &'a str, predicate: &'a str) -> Option<&'a str> {
    vec.iter()
       .map(|num| apply(num.clone()))
       .find(|elem| *elem == predicate)
}


fn main() {
    let matches = App::new("binsec")
        .version("1.0")
        .author("ex0dus <ex0dus at codemuch.tech>")
        .about("static Linux security feature detection tool")
        .setting(AppSettings::ArgRequiredElseHelp)

        .arg(Arg::with_name("BINARY")
             .help("sets binar(ies) to analyze")
             .index(1)
             .multiple(true)
             .required(true)
        )

        .arg(Arg::with_name("info")
             .help("outputs other binary info")
             .short("i")
             .long("info")
             .takes_value(false)
             .required(false)
        )

        .arg(Arg::with_name("out_format")
             .help("sets output format (available: normal, json, toml)")
             .short("f")
             .long("format")
             .takes_value(true)
             .value_name("FORMAT")
             .possible_values(&["normal", "json", "toml"])
             .required(false)
        )
        .get_matches();


    // retrieve binaries for analysis
    let binaries: Vec<&str> = matches.values_of("BINARY")
                                     .unwrap().collect();
    
    // set flags to be used for detection output
    let basic_info: bool = matches.is_present("info");
    
    // render and output based on out_format
    let format = match matches.value_of("out_format") {
        Some("json") => Format::Json,
        Some("toml") => Format::Toml,
        Some("raw") | Some(&_) | None => Format::Normal
    };

    // initialize binsec detector
    for binary in binaries {
        let mut detector = Detector::new(binary.to_string(), basic_info);
        if let Ok(d) = detector.detect() {
            println!("[{}] {}", "*".cyan(), binary.bold());
            d.output(&format);
        }
    }
}
