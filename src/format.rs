//! Implements file output dumping given a file format. __binsec__ currently supports the
//! following backends for structured deserialization:
//!
//! * Normal output
//! * JSON
//! * TOML

use crate::check::FeatureMap;
use crate::detect::Detector;
use crate::errors::BinResult;

use colored::*;
use term_table::{
    row::Row,
    table_cell::{Alignment, TableCell},
};
use term_table::{Table, TableStyle};

/// Defines the output format variants that are supported by binsec. Enforces a uniform `dump()`
/// function to perform serialization to the respective format when outputting back to user.
pub enum BinFormat {
    Normal,
    Json,
    Toml,
}

impl BinFormat {
    #[inline]
    fn add_header(table: &mut Table, header_name: &str) {
        table.add_row(Row::new(vec![TableCell::new_with_alignment(
            header_name.bold().underline(),
            2,
            Alignment::Center,
        )]));
    }

    #[inline]
    fn generate_rows(table: &mut Table, mapping: FeatureMap) {
        for (name, feature) in mapping {
            table.add_row(Row::new(vec![
                TableCell::new(name),
                TableCell::new_with_alignment(feature, 1, Alignment::Right),
            ]));
        }
    }

    #[inline]
    fn make_normal(input: &Detector) -> String {
        // initialize blank style term table
        let mut basic_table = Table::new();
        basic_table.max_column_width = 60;
        basic_table.style = TableStyle::blank();

        // check if basic information specified
        if let Some(info) = &input.bin_info {
            BinFormat::add_header(&mut basic_table, "Basic Information");
            BinFormat::generate_rows(&mut basic_table, info.dump_mapping());
        }

        // check if kernel checks were specified
        if let Some(kernchecks) = &input.kernel_features {
            BinFormat::add_header(&mut basic_table, "Host Kernel Checks");
            BinFormat::generate_rows(&mut basic_table, kernchecks.dump_mapping());
        }

        // add in hardening checks
        if let Some(harden_checks) = &input.harden_features {
            BinFormat::add_header(&mut basic_table, "Binary Hardening Checks");
            BinFormat::generate_rows(&mut basic_table, harden_checks.dump_mapping());
        }
        basic_table.render()
    }

    /// constructs a printable string for respective output format for display or persistent
    /// storage by consuming a ``.
    pub fn dump(&self, input: Detector) -> BinResult<String> {
        match self {
            BinFormat::Normal => Ok(BinFormat::make_normal(&input)),
            BinFormat::Toml => Ok(toml::to_string(&input).unwrap()),
            BinFormat::Json => Ok(serde_json::to_string_pretty(&input).unwrap()),
        }
    }
}
