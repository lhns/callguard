//! serde helpers for the wire types: `null` stands for the zero value, raw
//! values keep their text, whole floats are written without a fraction. Kept
//! so existing logs and callers keep working.

use serde::{Deserialize, Deserializer, Serializer};
use serde_json::value::RawValue;

/// `null` is accepted for any field and leaves the zero value; serde does not.
pub fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A raw JSON field: keeps the raw text, `null` included (only an absent field
/// is empty).
pub fn raw_some<'de, D>(d: D) -> Result<Option<Box<RawValue>>, D::Error>
where
    D: Deserializer<'de>,
{
    Box::<RawValue>::deserialize(d).map(Some)
}

/// `omitempty` for integers.
pub fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// `omitempty` for bools.
pub fn is_false(v: &bool) -> bool {
    !*v
}

/// A whole float is written without a fraction (`1`, not `1.0`), as confidences
/// always have been in the logs; serde_json does not.
pub fn go_float<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
        s.serialize_i64(*v as i64)
    } else {
        s.serialize_f64(*v)
    }
}
