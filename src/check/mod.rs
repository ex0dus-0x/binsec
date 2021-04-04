pub mod elf;
pub mod mach;
pub mod pe;

use serde::Serialize;

#[derive(Serialize)]
enum Arch {
    X86,
    X8664,
} 

#[derive(Serialize)]
enum Runtime {
    Golang,
    Rustc,
    Python,
    MinGw,
    Dotnet,
    VisualBasic,
    Gcc,
}

/// Basic information every binary format will return back for insight.
#[derive(Serialize)]
pub struct BasicInfo {
    // resolves the absolute path, if symlinked, to the target input
    abspath: String,

    // which architecture the binary runs on
    arch: Arch,

    // compiler/language used to compile executable
    runtime: Runtime,

    // detects if compression/packing based on entropy
    compression: bool,
    
    // TODO
    entry_point: String,
}

/// Blanket trait implemented by structs that all store parsed info from running a static analysis
/// on top the given executable format.
pub trait Detection {}

/// Defines trait implemented by each supported libgoblin binary format to facilitate static checks.
pub trait Analyze {
    // General checks used across all binary formats
    fn run_basic_checks(&self) -> BasicInfo;

    // Runs specific checks only for the binary format
    fn run_specific_checks(&self) -> Box<dyn Detection>;

    // Parses executable for supported security mitigations
    fn run_harden_checks(&self) -> Box<dyn Detection>;
}
