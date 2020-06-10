//! Main cli entry point to binsec application.

use clap::{App, AppSettings, Arg, ArgMatches};
use colored::*;

use binsec::detect::{Detector, ExecMode};
use binsec::errors::BinResult;
use binsec::format::BinFormat;

use std::path::PathBuf;

fn parse_args<'a>() -> ArgMatches<'a> {
    App::new("binsec")
        .version("1.0.0")
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
                .help(
                    "Sets the type of check to run (available: all, harden (default), \
                      kernel, yara).",
                )
                .short("check")
                .long("check")
                .takes_value(true)
                .value_name("DETECTOR")
                .possible_values(&["all", "harden", "kernel", "yara"])
                .multiple(true)
                .required(false),
        )
        .arg(
            Arg::with_name("info")
                .help("Include output on basic binary information and metadata.")
                .short("i")
                .long("info")
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("out_format")
                .help("Sets output format (available: normal (default), table, json, protobuf).")
                .short("f")
                .long("format")
                .takes_value(true)
                .value_name("FORMAT")
                .possible_values(&["normal", "table", "json", "protobuf"])
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
    let format: BinFormat = match args.value_of("out_format") {
        Some("json") => BinFormat::Json,
        Some("protobuf") => BinFormat::Protobuf,
        Some("table") => BinFormat::Table,
        Some("normal") | Some(&_) | None => BinFormat::Normal,
    };

    // parse out the mode of execution we are using for checks
    let check: ExecMode = match args.value_of("check") {
        Some("all") => ExecMode::All,
        Some("kernel") => ExecMode::Kernel,
        Some("yara") => ExecMode::Yara,
        Some("harden") | Some(&_) | None => ExecMode::Harden,
    };

    // initialize binsec detector
    for binary in binaries {
        // initialize binary path
        let binpath: PathBuf = PathBuf::from(binary.to_string());

        // initialize detector for the binary
        let detector = Detector::detect(binpath, &check, basic_info)?;

        // dump and output results given a format
        // TODO: deal with if given an output path
        println!("\n[{}] {}", "*".cyan(), binary.bold());
        println!("{}", detector.output(&format)?);
    }
    Ok(())
}

fn main() {
    let cli_args: ArgMatches = parse_args();
    match run(cli_args) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("binsec error: {}", e);
        }
    }
}
