//! Implements a YARA-based interface for deploying rule checks against a binary. While this does not
//! implement a foreign function interface directly with the system-installed YARA library component,
//! this is used instead since the currently available Rust bindings to YARA only support up to 3.11.

use crate::errors::{BinError, BinResult, ErrorKind};

use std::path::Path;
use std::process::Command;


#[derive(Serialize, Deserialize)]
struct YaraMatches {
}


//! defines a builder executor that calls yara directly through the command line rather than bindings,
//! and is able to consume rules and executables to match those rules against. The output format
//! that is generated is a `YaraMatches` -typed mapping.
pub struct YaraExecutor {
    rules: Vec<Path>
}

impl YaraExecutor {

    /// instantiates a new executor with no rules and executable to match against.
    pub fn new_executor() -> Self {
        Self {
            rules: Vec::new(),
        }
    }

    /// add a rule to test against an executable. TODO: parse a rule
    pub fn add_rule(mut self, rule: Path) -> Self {
        self.rules.push(rule);
        self
    }

    /// given a set of rules, test them against the path to an executable and store their
    /// results for return and later consumption in a `YaraMatches` structure.
    pub fn execute(&self, exec_name: Path) -> BinResult<YaraMatches> {
        // if empty ruleset, return error
        if self.rules.len() == 0 {
            return Err(BinError {
                kind: ErrorKind::RuleEngineError,
                msg: "no rules found to test against binary".to_string(),
            }
        }
        Ok(())
    }
}
