mod check;
mod detect;
mod errors;

use crate::detect::Detector;
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
            Arg::with_name("json")
                .help("Output results in JSON format.")
                .short("j")
                .long("json")
                .takes_value(false)
                .required(false),
        )
        .get_matches()
}

fn run(args: ArgMatches) -> BinResult<()> {
    let binary: &str = args.value_of("BINARY").unwrap();
    let _json: bool = args.is_present("json");
    let detector = Detector::run(PathBuf::from(binary))?;
    detector.output(None);
    Ok(())
}
