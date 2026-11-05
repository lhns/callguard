//! serde helpers for the wire types: `null` stands for the zero value, raw
//! values keep their text, whole floats are written without a fraction. Logs
//! and callers depend on these forms.

use serde::{Deserialize, Deserializer, Serializer};
use serde_json::value::RawValue;

/// `null` is accepted for any field and leaves the zero value; serde does not.
pub(crate) fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A raw JSON field: keeps the raw text, `null` included (only an absent field
/// is empty).
pub(crate) fn raw_some<'de, D>(d: D) -> Result<Option<Box<RawValue>>, D::Error>
where
    D: Deserializer<'de>,
{
    Box::<RawValue>::deserialize(d).map(Some)
}

/// For `skip_serializing_if`: a zero value is left out.
pub(crate) fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// For `skip_serializing_if`: `false` is left out.
pub(crate) fn is_false(v: &bool) -> bool {
    !*v
}

/// A whole float is written without a fraction (`1`, not `1.0`), as the
/// confidences in existing logs are; serde_json would write `1.0`.
pub(crate) fn whole_float<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
        s.serialize_i64(*v as i64)
    } else {
        s.serialize_f64(*v)
    }
}

/// Refuses anything but a JSON object: a derived `Deserialize` would also
/// take an array as a list of field values.
pub(crate) fn require_object(body: &[u8]) -> Result<(), String> {
    if body.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') {
        Ok(())
    } else {
        Err("not a JSON object".into())
    }
}

/// The members of a JSON object in order, each value kept as raw text.
pub(crate) fn members(body: &[u8]) -> Result<Vec<(String, Box<RawValue>)>, String> {
    use serde::de::{MapAccess, Visitor};
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<(String, Box<RawValue>)>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(kv) = m.next_entry::<String, Box<RawValue>>()? {
                out.push(kv);
            }
            Ok(out)
        }
    }
    require_object(body)?;
    let mut de = serde_json::Deserializer::from_slice(body);
    let out = de.deserialize_map(V).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(out)
}

/// The members of a JSON object with the keys in `known` matched in any
/// letter case: an exact spelling wins, otherwise the last of the other
/// spellings. Other keys are dropped. An exact key given twice is refused.
/// Values stay raw, so `tool.input` and the like are not touched.
fn fold_members(body: &[u8], known: &[&str]) -> Result<Vec<(String, Box<RawValue>)>, String> {
    let mut exact: Vec<Option<Box<RawValue>>> = known.iter().map(|_| None).collect();
    let mut loose: Vec<Option<Box<RawValue>>> = known.iter().map(|_| None).collect();
    for (k, v) in members(body)? {
        let Some(i) = known.iter().position(|n| n.eq_ignore_ascii_case(&k)) else {
            continue;
        };
        if known[i] == k {
            if exact[i].is_some() {
                return Err(format!("duplicate field `{k}`"));
            }
            exact[i] = Some(v);
        } else {
            loose[i] = Some(v);
        }
    }
    let mut out = Vec::new();
    for (i, name) in known.iter().enumerate() {
        if let Some(v) = exact[i].take().or_else(|| loose[i].take()) {
            out.push(((*name).to_owned(), v));
        }
    }
    Ok(out)
}

fn object_text(fields: &[(&str, &RawValue)]) -> String {
    let mut s = String::from("{");
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&serde_json::to_string(k).expect("a string serializes"));
        s.push(':');
        s.push_str(v.get());
    }
    s.push('}');
    s
}

/// The members of `body` for `known`, with the nested objects of `nested`
/// folded one level down. A nested value must be an object or null.
fn prepare(
    body: &[u8],
    known: &[&str],
    nested: &[(&str, &[&str])],
) -> Result<Vec<(String, Box<RawValue>)>, String> {
    let mut fields = fold_members(body, known)?;
    for (name, inner) in nested {
        if let Some((_, v)) = fields.iter_mut().find(|(k, _)| k.as_str() == *name) {
            let text = v.get().trim_start();
            if text.starts_with('{') {
                let folded = fold_members(v.get().as_bytes(), inner)?;
                let refs: Vec<(&str, &RawValue)> =
                    folded.iter().map(|(k, v)| (k.as_str(), &**v)).collect();
                *v = RawValue::from_string(object_text(&refs)).map_err(|e| e.to_string())?;
            } else if text != "null" {
                return Err(format!("`{name}` is not an object"));
            }
        }
    }
    Ok(fields)
}

/// Decodes a JSON object into `T`, matching the field names in `known` in any
/// letter case (exact spelling wins, otherwise the last). The members of the
/// fields in `nested` are matched the same way with the pair's names. Anything
/// but an object (also for a nested field) is an error, and so is a field of
/// the wrong type.
pub(crate) fn decode_object<T: serde::de::DeserializeOwned>(
    body: &[u8],
    known: &[&str],
    nested: &[(&str, &[&str])],
) -> Result<T, String> {
    let fields = prepare(body, known, nested)?;
    let refs: Vec<(&str, &RawValue)> = fields.iter().map(|(k, v)| (k.as_str(), &**v)).collect();
    serde_json::from_str::<T>(&object_text(&refs)).map_err(|e| e.to_string())
}

/// Like [`decode_object`], but a failure still returns what could be read:
/// the fields that have the right type, so a caller can use them (a
/// `permission_mode` that makes the fallback a deny) while it reports the error.
pub(crate) fn decode_partial<T: serde::de::DeserializeOwned + Default>(
    body: &[u8],
    known: &[&str],
) -> (T, Option<String>) {
    let fields = match prepare(body, known, &[]) {
        Ok(f) => f,
        Err(e) => return (T::default(), Some(e)),
    };
    let refs: Vec<(&str, &RawValue)> = fields.iter().map(|(k, v)| (k.as_str(), &**v)).collect();
    match serde_json::from_str::<T>(&object_text(&refs)) {
        Ok(v) => (v, None),
        Err(e) => {
            let good: Vec<(&str, &RawValue)> = refs
                .iter()
                .copied()
                .filter(|one| serde_json::from_str::<T>(&object_text(&[*one])).is_ok())
                .collect();
            let v = serde_json::from_str(&object_text(&good)).unwrap_or_default();
            (v, Some(e.to_string()))
        }
    }
}
