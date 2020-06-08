//! Defines the `PE` security mitigation checker. Consumes an
//! PE binary, parses it, and checks for the following features:
//!
//! * NX (Non-eXecutable bit)
//! * Full/Partial RELRO
//! * Position-Independent Executable / ASLR

use serde::{Deserialize, Serialize};

use goblin::pe::PE;

use crate::check::{BinInfo, Checker, Features};
use crate::errors::{BinError, BinResult};

/// struct defining security features parsed from ELF, and
/// derives serde de/serialize traits for structured output.
pub struct PEChecker;
