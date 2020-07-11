//! Implements a YARA-based interface for deploying rule checks against a binary. While this does not
//! implement a foreign function interface directly with the system-installed YARA library component,
//! this is used instead since the currently available Rust bindings to YARA only support up to 3.11.

use crate::check::FeatureCheck;
use crate::errors::{BinError, BinResult, ErrorKind};
use crate::format::{BinTable, FeatureMap};

use colored::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// A `YaraCollection` is denoted as a single file in a ruleset that stores all of the rules
/// grouped together for the type of analysis being done. Each file that is apart of the
/// collection must have a `Name` and `Description` comment parsed for informational display.
#[derive(Deserialize, Serialize, Debug)]
pub struct YaraCollection {
    /// Defines the name identifying the collection
    name: String,

    /// Represents an anecdotal description regarding the checks
    description: String,

    /// Represents collection of individual rules being run, and their resultant status
    rules: BTreeMap<String, bool>,
}

impl YaraCollection {
    /// Given a path to YARA file, parse it and create a `YaraMatch` to be represented
    fn parse(path: PathBuf) -> BinResult<Self> {
        // open and read file into string
        let contents: String = fs::read_to_string(path)?;
        let lines: Vec<&str> = contents.lines().collect();

        // read first line to determine collection name
        let _split = lines[0].split("// Name: ");
        let split: Vec<&str> = _split.collect();
        let name: String = split[1].to_string();

        // read second line to determine description for collection
        let _split = lines[1].split("// Description: ");
        let split: Vec<&str> = _split.collect();
        let description: String = split[1].to_string();

        // create BTreeMap for storing rules
        let mut rules: BTreeMap<String, bool> = BTreeMap::new();
        let _rules: Vec<String> = lines[2..]
            .iter()
            .filter(|r| r.starts_with("rule"))
            .map(|r| {
                let _split = r.split("rule ");
                let split: Vec<&str> = _split.collect();
                split[1].to_string()
            })
            .collect();

        // populate rules mapping with each
        for rule in _rules.iter() {
            rules.insert(rule.to_string(), false);
        }

        // find all instances of rules regex and parse out name
        Ok(Self {
            name,
            description,
            rules,
        })
    }
}

/// Represents a strongly typed collection of YARA rules, and their statuses when executed against a binary.
/// This is to be what ends up being serialized and returned to the user, or displayed as a table.
#[derive(Deserialize, Serialize, Debug, Default)]
pub struct YaraMatches(Vec<YaraCollection>);

#[typetag::serde]
impl FeatureCheck for YaraMatches {
    fn output(&self) -> String {
        let mut output: String = String::new();
        output.push_str(&format!(
            "{}\n\n",
            "Enhanced (YARA) Checks{}".bold().underline()
        ));
        for col in &self.0 {
            // create a new FeatureMap for the collection
            let mut feature_map: FeatureMap = FeatureMap::new();
            feature_map.insert("Yeet", json!(col.rules));
            output.push_str(&BinTable::parse(&col.name, feature_map));
        }
        output
    }
}

/// Defines a builder executor that calls yara directly through the command line rather than bindings,
/// and is able to consume rules and executables to match those rules against. The output format
/// that is generated is a `YaraMatches` -typed mapping.
#[derive(Deserialize, Serialize, Default)]
pub struct YaraExecutor {
    pub binpath: PathBuf,
    pub rules: Vec<PathBuf>,
    pub matches: YaraMatches,
}

impl YaraExecutor {
    /// Instantiates a new executor with no rules and executable to match against.
    pub fn new(binpath: PathBuf) -> Self {
        Self {
            binpath,
            ..Self::default()
        }
    }

    /// Add a rule to test against an executable, and parse it for correlation.
    pub fn add_rule(&mut self, rule: PathBuf) -> BinResult<()> {
        // store path to rule for later command reconstruction
        let _rule = rule.clone();
        self.rules.push(_rule);

        // create a new yara match to set for binary
        self.matches.0.push(YaraCollection::parse(rule)?);

        Ok(())
    }

    /// Given an executable path and singular rule from ruleset, build a command to execute
    /// against and test for matches, and execute. Once done, parse out all of the rules within
    /// that collection that passed for the executable passed in.
    fn exec_cmd(&self, exec_name: &str) -> BinResult<Vec<String>> {
        let mut command = Command::new("yara");

        // construct arguments to commands
        command.arg("--no-warnings");
        for rule in &self.rules {
            command.arg(rule);
        }

        // append binary name at end
        command.arg(exec_name);

        // execute command against the binary and error-check
        let _output = command.output().map_err(|e| BinError {
            kind: ErrorKind::RuleEngineError,
            msg: e.to_string(),
        })?;

        // convert output to string, parse and return appropriately
        let output: &[u8] = _output.stdout.as_slice();
        match std::str::from_utf8(&output) {
            Ok(out) => {
                // get all lines as vector
                let _lines: Vec<&str> = out.lines().collect();

                // iterate over each line, parse out rule from
                let lines: Vec<String> = _lines
                    .iter()
                    .map(|l| {
                        // split and recover rule name matched
                        let _split = l.split(exec_name);
                        let split: Vec<&str> = _split.collect();

                        // cleanup and remove any trailing whitespace
                        let mut res = split[0].to_string();
                        res.retain(|c| !c.is_whitespace());
                        res
                    })
                    .collect();

                Ok(lines)
            }
            Err(_e) => Err(BinError {
                kind: ErrorKind::RuleEngineError,
                msg: "cannot parse output from YARA execution".to_string(),
            }),
        }
    }

    /// Executes given a ruleset and a target binary to check against. Stores and mutates results
    /// in the `YaraExecutor.matches` attribute to represent checks done.
    pub fn execute(&mut self) -> BinResult<()> {
        // if empty ruleset, return error
        if self.rules.is_empty() {
            return Err(BinError {
                kind: ErrorKind::RuleEngineError,
                msg: "no rules found to test against binary".to_string(),
            });
        }

        // construct command to run and run against binary
        let bin_name: &str = self.binpath.to_str().unwrap();
        let result: Vec<String> = self.exec_cmd(bin_name)?;

        // parse results, and set respective
        // TODO: very ugly, cleanup
        if !result.is_empty() {
            for res in result.iter() {
                for ymatches in &mut self.matches.0 {
                    if ymatches.rules.contains_key(res) {
                        *ymatches.rules.get_mut(&res.to_string()).unwrap() = true;
                    }
                }
            }
        }
        Ok(())
    }
}
