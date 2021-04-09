pub mod elf;
//pub mod mach;
pub mod pe;

use serde::Serialize;

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

/// Blanket trait implemented by structs that all store parsed info from running a static analysis
/// on top the given executable format.
pub trait Detection {}

/// Defines trait implemented by each supported libgoblin binary format to expose reusable functionality
/// for parsing out features and doing static analysis.
pub trait Analyze {

    // parses out the architecture as a readable string
    fn get_architecture(&self) -> String;

    // parses out the entry point readable hex address
    fn get_entry_point(&self) -> String;

    // facilitates static pattern match of string in binary sample
    fn symbol_match(&self, cb: fn(&str) -> bool) -> bool;

    // GENERAL HARDENING CHECKS

    fn exec_stack(&self) -> bool;
    fn aslr(&self) -> bool;
}
