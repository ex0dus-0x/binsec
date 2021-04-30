pub mod elf;
//pub mod mach;
pub mod pe;
pub mod common;

/// Blanket trait implemented by structs that all store parsed info from running a static analysis
/// on top the given executable format.
pub trait Detection {
    fn as_any(&self) -> &dyn std::any::Any;
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
