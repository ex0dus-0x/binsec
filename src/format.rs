//! Implements file output dumping given a file format. __binsec__ currently supports the
//! following backends for structured deserialization:
//!
//! * Normal output
//! * Table output (term_table)
//! * JSON
//! * Protobuf

use crate::check::Features;
use crate::errors::BinResult;

/// Defines the output format variants that are supported by binsec. Enforces a uniform `dump()`
/// function to perform serialization to the respective format when outputting back to user.
pub enum BinFormat {
    Normal,
    Table,
    Json,
    Protobuf,
}

impl BinFormat {
    /// helper for constructing a normal output string for display given a Features `BTreeMap`.
    #[inline]
    fn make_normal(input: Features) -> String {
        let mut out_string: String = String::new();
        for (key, features) in input.iter() {
            // append title with newline
            out_string.push_str(key);
            out_string.push_str("\n");

            // print feature name and config with equidistance
            for (name, config) in features {
                let feature_line: String = format!("{}\t\t{}", name, config);
                out_string.push_str(feature_line.as_str());
            }
        }
        out_string
    }

    /// helper for constructing a table output string for display given a Features `BTreeMap`.
    #[inline]
    fn make_table(input: Features) -> String {
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
                key,
                2,
                Alignment::Center,
            )]));

            // add additional rows for each feature and its name
            for (name, config) in features {
                basic_table.add_row(Row::new(vec![
                    TableCell::new(name),
                    TableCell::new_with_alignment(config, 1, Alignment::Right),
                ]));
            }
        }
        basic_table.render()
    }

    #[inline]
    fn make_protobuf(input: Features) -> String {
        todo!()
    }

    /// constructs a printable string for respective output format for display or persistent
    /// storage by consuming a ``.
    pub fn dump(&self, input: Features) -> BinResult<String> {
        match self {
            BinFormat::Normal => Ok(BinFormat::make_normal(input)),
            BinFormat::Table => Ok(BinFormat::make_table(input)),
            BinFormat::Protobuf => Ok(BinFormat::make_protobuf(input)),
            BinFormat::Json => Ok(serde_json::to_string_pretty(&input).unwrap()),
        }
    }
}
