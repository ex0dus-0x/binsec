pub mod elf;
pub mod mach;
pub mod pe;

use serde::Serialize;

/// Basic information every binary format will return back for insight.
#[derive(Serialize)]
pub struct BasicInfo {
    abspath: String,
    format: String,
    arch: String,
    timestamp: String,
    filesize: String,
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
