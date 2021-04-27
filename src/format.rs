use structmap::value::Value;
use std::collections::HashMap;

/// Aliases a finalized output type for a detector, storing all the checks that
/// were performed and their results for consumption by a `BinTable` for creating a table.
pub type GenericMap = HashMap<String, Value>;

pub fn generate_table(name: &str, mapping: GenericMap) -> String {
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
    let header: String = format!("{}", name);
    table.add_row(Row::new(vec![TableCell::new_with_alignment(
        &header,
        2,
        Alignment::Center,
    )]));


    for (name, feature) in mapping {
        let cell = match feature {
            Value::Bool(true) => TableCell::new_with_alignment("\x1b[0;32m✔️\x1b[0m", 1, Alignment::Right),
            Value::Bool(false) => TableCell::new_with_alignment("\x1b[0;31m✖️\x1b[0m", 1, Alignment::Right),
            Value::String(val) => TableCell::new_with_alignment(val, 1, Alignment::Right),
            _ => unimplemented!()
        };
        table.add_row(Row::new(vec![TableCell::new(name), cell]));
    }
    table.render()
}
