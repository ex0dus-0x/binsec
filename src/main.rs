//! Main cli entry point to binsec application.

use clap::{App, AppSettings, Arg, ArgMatches};
use colored::*;

use binsec::errors::{BinResult, BinError};
use binsec::detect::{Detector, Format};


fn parse_args<'a>() -> ArgMatches<'a> {
    App::new("binsec")
        .version("0.3.0")
        .author("ex0dus <ex0dus at codemuch.tech>")
        .about("Swiss Army Knife for Binary (In)security")
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(
            Arg::with_name("BINARY")
                .help("Path to binary or binaries to analyze.")
                .index(1)
                .multiple(true)
                .required(true),
        )
        .arg(
            Arg::with_name("check")
                .help("Sets the type of check to run (available: all, harden (default), \
                      kernel, yara).")
                .short("check")
                .long("check")
                .takes_value(true)
                .value_name("DETECTOR")
                .possible_values(&["all", "harden", "kernel", "yara"])
                .required(false)
        )
        .arg(
            Arg::with_name("info")
                .help("Include output on basic binary information and metadata.")
                .short("i")
                .long("info")
                .takes_value(false)
                .required(false)
        )
        .arg(
            Arg::with_name("out_format")
                .help("Sets output format (available: normal (default), json, csv, protobuf).")
                .short("f")
                .long("format")
                .takes_value(true)
                .value_name("FORMAT")
                .possible_values(&["normal", "json", "csv", "protobuf"])
                .required(false),
        )
        .get_matches()
}


fn run(args: ArgMatches) -> BinResult<()> {

    // retrieve binaries for analysis
    let binaries: Vec<&str> = args.values_of("BINARY").unwrap().collect();

    // set flags to be used for detection output
    let basic_info: bool = args.is_present("info");

    // render and output based on out_format
    let format = match args.value_of("out_format") {
        Some("json") => Format::Json,
        Some("csv") => Format::Csv,
        Some("protobuf") => Format::Protobuf,
        Some("normal") | Some(&_) | None => Format::Normal,
    };

    // initialize binsec detector
    for binary in binaries {
        let mut detector =
            Detector::new(binary.to_string()).expect("could not initialize feature detector");
        if let Ok(d) = detector.detect(basic_info) {
            println!("[{}] {}", "*".cyan(), binary.bold());
            d.output(&format);
        }
    }

    Ok(())
}


fn main() {
    let cli_args: ArgMatches = parse_args();
    match run(cli_args) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("binsec error: {}", e);
        }
    }
}
