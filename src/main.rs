use clap::{App, AppSettings, Arg, ArgMatches};
use colored::*;

use binsec::detect::Detector;
use binsec::errors::BinResult;

use std::path::PathBuf;

pub enum Format {
    Normal,
    Json,
    Csv,
}

fn main() {
    let cli_args: ArgMatches = parse_args();
    match run(cli_args) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("binsec failed with: {}", e);
        }
    }
}

fn parse_args<'a>() -> ArgMatches<'a> {
    App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
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
                    "Sets the type of checks to run. Available: all, basic (default), \
                      harden, or behavior.",
                )
                .short("c")
                .long("check")
                .takes_value(true)
                .value_name("CHECK_NAME")
                .possible_values(&["all", "basic", "harden", "behavior"])
                .required(false),
        )
        .arg(
            Arg::with_name("out_format")
                .help("Sets output format (available: normal (default), json, csv).")
                .short("f")
                .long("format")
                .takes_value(true)
                .value_name("FORMAT")
                .possible_values(&["normal", "json", "csv"])
                .required(false),
        )
        // TODO: output path
        .get_matches()
}

fn run(args: ArgMatches) -> BinResult<()> {
    let binaries: Vec<&str> = args.values_of("BINARY").unwrap().collect();
    let check: &str = args.value_of("check").unwrap();

    // render and output based on out_format
    let format: BinFormat = match args.value_of("out_format") {
        Some("json") => BinFormat::Json,
        Some("csv") => BinFormat::Toml,
        Some("normal") | Some(&_) | None => BinFormat::Normal,
    };

    for binary in binaries {
        let binpath: PathBuf = PathBuf::from(binary.to_string());
        let detector = Detector::run(binpath)?;

        // TODO: deal with if given an output path
        println!(
            "\n[{}] {} {}\n",
            "*".cyan(),
            "Name:".bold().underline(),
            binary
        );
        println!("{}", detector.output(&format)?);
    }
    Ok(())
}
