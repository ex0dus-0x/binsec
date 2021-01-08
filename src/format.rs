//! Implements file output dumping given a file format. __binsec__ currently supports the
//! following backends for structured deserialization:
//!
//! * Normal output
//! * JSON
//! * TOML

use crate::detect::Detector;
use crate::errors::BinResult;

use colored::*;
use structmap::value::Value;
use term_table::{
    row::Row,
    table_cell::{Alignment, TableCell},
};
use term_table::{Table, TableStyle};

use std::collections::HashMap;

/// Aliases a finalized output type for a detector, storing all the checks that
/// were performed and their results for consumption by a `BinTable` for creating a table.
pub type FeatureMap = HashMap<String, Value>;

/// Helper struct that helps convert a `FeatureMap` into a normalized ASCII table
pub struct BinTable;

impl BinTable {
    /// initializes a stringified version of the ASCII table given a table name and a `FeatureMap`.
    pub fn parse(name: &str, mapping: FeatureMap) -> String {
        // initialize blank style term table
        let mut table = Table::new();
        table.max_column_width = 90;
        table.style = TableStyle::rounded();

        // create bolded header
        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            name.bold().underline(),
            2,
            Alignment::Center,
        )]));

        // add features to table
        for (name, feature) in mapping {
            // format display based on content
            let feature_cell = match feature {
                Value::Bool(true) => {
                    TableCell::new_with_alignment("✔️".green(), 1, Alignment::Center)
                }
                Value::Bool(false) => {
                    TableCell::new_with_alignment("✖️".red(), 1, Alignment::Center)
                }
                Value::String(val) => {
                    TableCell::new_with_alignment(val.bold(), 1, Alignment::Center)
                }
                _ => TableCell::new_with_alignment(feature, 1, Alignment::Center),
            };

            table.add_row(Row::new(vec![TableCell::new(name), feature_cell]));
        }
        table.render()
    }
}

/// Defines the output format variants that are supported by binsec. Enforces a uniform `dump()`
/// function to perform serialization to the respective format when outputting back to user.
pub enum BinFormat {
    Normal,
    Json,
    Toml,
}

impl BinFormat {
    #[inline]
    fn make_normal(input: &Detector) -> String {
        // finalized output string
        let mut output: String = String::new();

        // check if basic information specified
        if let Some(info) = &input.bin_info {
            output.push_str(&info.output());
        }

        // check if kernel checks were specified
        if let Some(kernchecks) = &input.kernel_features {
            output.push_str(&kernchecks.output());
        }

        // check if hardening checks were specified
        if let Some(harden_checks) = &input.harden_features {
            output.push_str(&harden_checks.output());
        }

        // check if enhanced checks were specified
        if let Some(rule_checks) = &input.rule_features {
            output.push_str(&rule_checks.output());
        }
        output
    }

    /// Constructs a printable string for respective output format for display or persistent
    /// storage by consuming a `Detector`.
    pub fn dump(&self, input: Detector) -> BinResult<String> {
        match self {
            BinFormat::Normal => Ok(BinFormat::make_normal(&input)),
            BinFormat::Toml => Ok(toml::to_string(&input).unwrap()),
            BinFormat::Json => Ok(serde_json::to_string_pretty(&input).unwrap()),
        }
    }
}
