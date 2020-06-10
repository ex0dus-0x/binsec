//! Implements file output dumping given a file format. __binsec__ currently supports the
//! following backends for structured deserialization:
//!
//! * Normal output
//! * Table output (term_table)
//! * JSON
//! * Protobuf

use crate::check::FeatureMap;
use crate::errors::BinResult;

use std::collections::BTreeMap;

pub type Features = BTreeMap<&'static str, FeatureMap>;

/// Defines the output format variants that are supported by binsec. Enforces a uniform `dump()`
/// function to perform serialization to the respective format when outputting back to user.
pub enum BinFormat {
    Normal,
    Json,
    Protobuf,
}

impl BinFormat {
    /// helper for constructing a table output string for display given a Features `BTreeMap`.
    #[inline]
    fn make_normal(input: &Features) -> String {
        use colored::*;
        use term_table::{
            row::Row,
            table_cell::{Alignment, TableCell},
        };
        use term_table::{Table, TableStyle};

        // initialize blank style term table
        let mut basic_table = Table::new();
        basic_table.max_column_width = 60;
        basic_table.style = TableStyle::blank();

        for (key, features) in input.iter() {
            // initialize a header row for each key
            // TODO: underline header
            basic_table.add_row(Row::new(vec![TableCell::new_with_alignment(
                key.bold().underline(),
                2,
                Alignment::Center,
            )]));

            // add additional rows for each feature and its name
            for (name, feature) in features {
                basic_table.add_row(Row::new(vec![
                    TableCell::new(name),
                    TableCell::new_with_alignment(feature, 1, Alignment::Right),
                ]));
            }
        }
        basic_table.render()
    }

    #[inline]
    fn make_protobuf(input: &Features) -> String {
        todo!()
    }

    /// constructs a printable string for respective output format for display or persistent
    /// storage by consuming a ``.
    pub fn dump(&self, input: &Features) -> BinResult<String> {
        match self {
            BinFormat::Normal => Ok(BinFormat::make_normal(input)),
            BinFormat::Protobuf => Ok(BinFormat::make_protobuf(input)),
            BinFormat::Json => Ok(serde_json::to_string_pretty(&input).unwrap()),
        }
    }
}
