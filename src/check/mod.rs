pub mod elf;
//pub mod mach;
pub mod pe;

use serde::Serialize;

/// Blanket trait implemented by structs that all store parsed info from running a static analysis
/// on top the given executable format.
pub trait Detection {}

/// Basic information every binary format will return back for insight.
#[derive(Serialize)]
pub struct BasicInfo {
    pub abspath: String,
    pub format: String,
    pub arch: String,
    pub timestamp: Option<String>,
    pub filesize: String,
    pub entry_point: String,
}

/// Defines instrumentation routines found in the executable, used for every binary format.
#[derive(Serialize)]
pub struct Instrumentation {
    pub afl: bool,
    pub asan: bool,
    pub ubsan: bool,
    pub llvm: bool,
}

impl Detection for Instrumentation {}

/// Defines trait implemented by each supported libgoblin binary format to expose common and
/// reusable functions for parsing out features and doing static analysis.
pub trait Analyze {
    // parses out the architecture as a readable string
    fn get_architecture(&self) -> String;

    // parses out the entry point readable hex address
    fn get_entry_point(&self) -> String;

    // facilitates static pattern match of string in binary sample
    fn symbol_match(&self, cb: fn(&str) -> bool) -> bool;
}
