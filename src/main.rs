
mod check;
mod detect;
mod errors;
mod format;

use crate::errors::BinResult;
use clap::{App, AppSettings, Arg, ArgMatches};
use std::path::PathBuf;

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
                .takes_value(true)
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
            Arg::with_name("json")
                .help("Output results in JSON format.")
                .short("j")
                .long("json")
                .takes_value(false)
                .required(false),
        )
        // TODO: output path
        .get_matches()
}

fn run(args: ArgMatches) -> BinResult<()> {
    let binary: &str = args.value_of("BINARY").unwrap();
    let json: bool = args.is_present("json");

    /*
    let detector = Detector::run(binary)?;
    detector.output();
    */
    Ok(())
}
