//! Implements file output dumping given a file format.
use colored::*;
use structmap::value::Value;

use std::collections::HashMap;

/// Aliases a finalized output type for a detector, storing all the checks that
/// were performed and their results for consumption by a `BinTable` for creating a table.
pub type FeatureMap = HashMap<String, Value>;

/// Initializes a stringified version of the ASCII table given a table name and a map.
pub fn generate_table(name: &str, mapping: FeatureMap) -> String {
    use term_table::{
        row::Row,
        table_cell::{Alignment, TableCell},
    };
    use term_table::{Table, TableStyle};

    // initialize blank style term table
    let mut table = Table::new();
    table.max_column_width = 200;
    table.style = TableStyle::blank();

    // create bolded header
    table.add_row(Row::new(vec![TableCell::new_with_alignment(
        name.bold().underline(),
        2,
        Alignment::Center,
    )]));

    for (name, feature) in mapping {
        let feature_cell = match feature {
            Value::Bool(true) => TableCell::new_with_alignment("✔️".green(), 1, Alignment::Right),
            Value::Bool(false) => TableCell::new_with_alignment("✖️".red(), 1, Alignment::Right),
            Value::String(val) => TableCell::new_with_alignment(val.bold(), 1, Alignment::Right),
            _ => TableCell::new_with_alignment(feature, 1, Alignment::Right),
        };

        table.add_row(Row::new(vec![TableCell::new(name), feature_cell]));
    }
    table.render()
}
