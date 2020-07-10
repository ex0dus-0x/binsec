//! Implements a YARA-based interface for deploying rule checks against a binary. While this does not
//! implement a foreign function interface directly with the system-installed YARA library component,
//! this is used instead since the currently available Rust bindings to YARA only support up to 3.11.

use crate::errors::{BinError, BinResult, ErrorKind};

use serde::{Serialize, Deserialize};

use std::path::PathBuf;
use std::process::Command;


#[derive(Serialize, Deserialize)]
pub struct YaraMatches {
    name: String,
    collection: String,
    detected: bool,
}


/// defines a builder executor that calls yara directly through the command line rather than bindings,
/// and is able to consume rules and executables to match those rules against. The output format
/// that is generated is a `YaraMatches` -typed mapping.
pub struct YaraExecutor {
    pub rules: Vec<PathBuf>,
    matches: Vec<YaraMatches>,
}

impl YaraExecutor {

    /// instantiates a new executor with no rules and executable to match against.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            matches: Vec::new(),
        }
    }

    /// add a rule to test against an executable. TODO: parse a rule
    pub fn add_rule(mut self, rule: PathBuf) -> Self {
        self.rules.push(rule);
        self
    }

    /// given an executable path and singular rule from ruleset, build a command to execute
    /// against and test for matches.
    fn build_cmd(&self, exec_name: &str, rule_path: &str) -> BinResult<String> {
        let mut command = Command::new("yara");

        // construct arguments to command
        command.arg(exec_name);
        for rule in &self.rules {
            command.arg(rule);
        }

        // execute command against the binary and error-check
        let _output = command.output().map_err(|e| {
            BinError {
                kind: ErrorKind::RuleEngineError,
                msg: e.to_string(),
            }
        })?;

        let output: &[u8] = _output.stdout.as_slice();
        let out = std::str::from_utf8(&output).unwrap();
        Ok(out.to_string())
    }

    /// given a set of rules, test them against the path to an executable and store their
    /// results for return and later consumption in a `YaraMatches` structure.
    pub fn execute(&self, exec_name: PathBuf) -> BinResult<Vec<YaraMatches>> {
        // if empty ruleset, return error
        if self.rules.len() == 0 {
            return Err(BinError {
                kind: ErrorKind::RuleEngineError,
                msg: "no rules found to test against binary".to_string(),
            });
        }
        todo!()
    }
}
