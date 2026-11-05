//! callguard's policy file format (policy_version 1) and its layered,
//! tighten-only merge (docs/design.md section 5, ADR 0003).
//!
//! Unset is told from zero with `Option`. Integer fields are `i64`, so
//! `validate` can still report negative values. Paths stay `String`, with ""
//! meaning "default". Policy regexes are RE2; `rules::compile_regex` makes the
//! `regex` crate read them that way.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::permissions;
use crate::serde_util::{is_false, is_zero, nullable};

mod types;
pub use types::*;
mod load;
pub(crate) mod protected;
pub use load::*;
mod validate;
pub use validate::*;
mod merge;
pub(crate) use merge::*;
mod defaults;
pub use defaults::*;

#[cfg(test)]
mod tests;
