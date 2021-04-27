pub mod elf;
//pub mod mach;
pub mod pe;

use serde::Serialize;

use structmap::value::Value;
use structmap::{GenericMap, StringMap, ToMap};
use structmap_derive::ToMap;

/// Blanket trait implemented by structs that all store parsed info from running a static analysis
/// on top the given executable format.
pub trait Detection {
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Basic information every binary format will return back for insight.
#[derive(Serialize, ToMap, Default, Clone)]
pub struct BasicInfo {
    #[rename(name = "Absolute Path")]
    pub abspath: String,

    #[rename(name = "Binary Format")]
    pub format: String,

    #[rename(name = "Architecture")]
    pub arch: String,

    #[rename(name = "Last Modified")]
    pub timestamp: String,

    #[rename(name = "File Size")]
    pub filesize: String,

    #[rename(name = "Entry Point Address")]
    pub entry_point: String,
}

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

/// Defines instrumentation routines found in the executable, used for every binary format.
#[derive(Serialize, ToMap, Default, Clone)]
pub struct Instrumentation {
    #[rename(name = "AFL")]
    pub afl: bool,

    #[rename(name = "Address Sanitizer")]
    pub asan: bool,

    #[rename(name = "Undefined Behavior Sanitizer")]
    pub ubsan: bool,

    #[rename(name = "Clang/LLVM Coverage")]
    pub llvm: bool,
}
