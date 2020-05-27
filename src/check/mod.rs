//! Defines the checkers that can be used for their binary formats for their respective
//! platforms. Also implements the `Checker` trait, which is used to implement the functionality
//! needed to properly do all security mitigation detections per platform.

pub mod elf;
pub mod mach;
pub mod pe;

use std::fmt::{self, Display};
use std::collections::BTreeMap;

// type alias for detecting features
pub type Features = BTreeMap<String, BTreeMap<String, bool>>;

// implement how we want to output features normally
impl Display for Features {
    fn fmt(&self, f: fmt::Formatter) -> fmt::Result {
        let out_string: String = String::new();
        for (key, features) in self.iter() {

            // append title with newline
            out_string.push(key);
            out_string.push("\n");

            // print feature name and config with equidistance
            for (name, config) in features {
                let feature_line: String = format!("{}\t\t{}", name, config);
                out_string.push(feature_line);
            }
        }
        write!(f, "{}", out_string.as_str())
    }
}


pub trait Checker {
    /// parses out and returns basic binary information for more verbose
    /// user output
    fn bin_info(&self) -> Features;

    /// defines the function be implemented in order to detect the
    /// standard binary hardening features usually enforced by the compiler.
    fn harden_check(&self) -> Features;

    /// defines checks that determine security features configured on the kernel that the
    /// binary is running on.
    fn kernel_check(&self) -> Features {
        todo!()
    }

    /// runs the custom set of YARA-based rules against the specific binary. This is
    /// default across all formats, as the rules are built to include cases for all formats.
    fn rule_check(&self) -> Features {
        todo!()
    }
}
