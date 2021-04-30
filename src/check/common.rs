//! Defines common checks that are deployed across any binary format.
use serde::Serialize;

use structmap::value::Value;
use structmap::{GenericMap, StringMap, ToMap};
use structmap_derive::ToMap;

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


#[derive(Serialize, ToMap, Default, Clone)]
pub struct AntiAnalysis {
}
