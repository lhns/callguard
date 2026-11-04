//! The facts nah established for a decision, projected for the LLM judge: nah's
//! effect graph as a neutral JSON value, which `facts.rs` maps onto `Facts`.
//!
//! nah's guard evidence is a typed effect graph (calls, resources, facts,
//! dataflow). The judge needs what it says, not its plumbing: the commands
//! the call unwraps into, what each may do to which resource, where analysis
//! gave up, and what the host looked like. Dataflow (occurrences, relations)
//! is left out. The shape is documented in docs/nahwasm.md ("Facts").
//!
//! The projection works on nah's serialized graph rather than its Rust types,
//! so new payload variants and fields pass through without a code change.

use nah_cli::DecisionResult;
use nah_proto::observation::Observation;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Version of the `facts` shape.
const FACTS_V: u64 = 1;

/// Payload fields that name a resource by id.
const RESOURCE_FIELDS: [&str; 5] = [
    "target",
    "destination",
    "repository",
    "resource",
    "resources",
];

pub(crate) fn graph_facts(result: &DecisionResult, observations: &[Observation]) -> Value {
    let graph = result
        .guard_evidence()
        .and_then(Result::ok)
        .and_then(|evidence| serde_json::to_value(evidence.graph()).ok())
        .unwrap_or(Value::Null);
    let resources: BTreeMap<u64, Value> = list(&graph, "resources")
        .iter()
        .filter_map(|resource| Some((resource.get("id")?.as_u64()?, resource_summary(resource))))
        .collect();
    json!({
        "v": FACTS_V,
        "commands": list(&graph, "calls").iter().map(command).collect::<Vec<_>>(),
        "effects": list(&graph, "facts").iter().map(|fact| effect(fact, &resources)).collect::<Vec<_>>(),
        "gaps": list(&graph, "gaps").iter().map(gap).collect::<Vec<_>>(),
        "observations": observed(observations),
    })
}

fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// `{"Known": x}` is x; `"Unknown"` and anything else is null.
fn known(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Object(object)) if object.len() == 1 && object.contains_key("Known") => {
            object["Known"].clone()
        }
        _ => Value::Null,
    }
}

/// One invocation the call unwrapped into: the tool call itself, a shell
/// script's commands, `bash -c` bodies, `xargs`/`find -exec` children...
fn command(call: &Value) -> Value {
    json!({
        "id": call.get("id"),
        "parent": call.get("parent"),
        "kind": call.get("kind"),
        "program": match known(call.get("identity")) {
            Value::Null | Value::String(_) => known(call.get("identity")),
            other => Value::String(other.to_string()),
        },
        "argv": known(call.get("arguments")),
        "cwd": known(call.get("cwd")),
        "coverage": call.get("coverage"),
    })
}

/// What one command may do: `FilesystemAccess/Delete` on `HostPath /x`.
fn effect(fact: &Value, resources: &BTreeMap<u64, Value>) -> Value {
    let (variant, fields) = fact
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.iter().next())
        .map(|(variant, fields)| (variant.clone(), fields.clone()))
        .unwrap_or_default();
    let mut kind = variant;
    let mut targets = Vec::new();
    let mut details = Map::new();
    if let Value::Object(fields) = fields {
        for (name, value) in fields {
            if name == "operation" {
                if let Some(operation) = value.as_str() {
                    kind = format!("{kind}/{operation}");
                    continue;
                }
            }
            if RESOURCE_FIELDS.contains(&name.as_str()) {
                let ids = match &value {
                    Value::Array(ids) => ids.clone(),
                    other => vec![other.clone()],
                };
                for id in ids.iter().filter_map(Value::as_u64) {
                    let mut target = resources.get(&id).cloned().unwrap_or(Value::Null);
                    if let Value::Object(target) = &mut target {
                        target.insert("role".into(), Value::String(name.clone()));
                    }
                    targets.push(target);
                }
                continue;
            }
            match simplify(value) {
                Value::Null => {}
                value => {
                    details.insert(name, value);
                }
            }
        }
    }
    json!({
        "id": fact.get("id"),
        "command": fact.get("call"),
        "kind": kind,
        "certainty": fact.get("certainty"),
        "modality": fact.get("modality"),
        "conditional": fact.get("condition").is_some_and(|condition| !condition.is_null()),
        "resources": targets,
        "details": details,
    })
}

/// Knowledge wrappers unwrapped, unknowns and empty values dropped.
fn simplify(value: Value) -> Value {
    match value {
        Value::Object(object) if object.len() == 1 && object.contains_key("Known") => simplify(
            object
                .into_iter()
                .next()
                .map(|(_, value)| value)
                .unwrap_or_default(),
        ),
        Value::String(text) if text == "Unknown" || text == "Absent" => Value::Null,
        Value::Array(items) if items.is_empty() => Value::Null,
        Value::Object(object) if object.is_empty() => Value::Null,
        Value::Object(object) => {
            let object: Map<String, Value> = object
                .into_iter()
                .filter_map(|(name, value)| match simplify(value) {
                    Value::Null => None,
                    value => Some((name, value)),
                })
                .collect();
            if object.is_empty() {
                Value::Null
            } else {
                Value::Object(object)
            }
        }
        other => other,
    }
}

/// A resource as the judge reads it: its kind, name and labels.
fn resource_summary(resource: &Value) -> Value {
    let identity = resource.get("identity").cloned().unwrap_or_default();
    let details = simplify(known(identity.get("details")));
    let name = match known(identity.get("name")) {
        Value::Null => details
            .as_object()
            .and_then(|details| details.values().next())
            .and_then(|inner| inner.as_object())
            .and_then(|inner| inner.get("lexical").or_else(|| inner.get("executable")))
            .cloned()
            .unwrap_or(Value::Null),
        name => name,
    };
    // Always text, so consumers get one type.
    let name = match name {
        Value::Null | Value::String(_) => name,
        other => Value::String(other.to_string()),
    };
    json!({
        "kind": identity.get("kind"),
        "name": name,
        "selection": match resource.get("selection") {
            Some(Value::String(selection)) => Value::String(selection.clone()),
            Some(other) if !other.is_null() => Value::String(
                other.as_object().and_then(|object| object.keys().next().cloned()).unwrap_or_default(),
            ),
            _ => Value::Null,
        },
        "labels": simplify(resource.get("labels").cloned().unwrap_or_default()),
    })
}

fn gap(gap: &Value) -> Value {
    json!({
        "command": gap.get("call"),
        "phase": gap.get("phase"),
        "category": gap.get("category"),
        "domain": gap.get("domain"),
        "code": gap.get("code"),
    })
}

/// Host facts nah observed, one per question: the last round's answer wins.
fn observed(observations: &[Observation]) -> Vec<Value> {
    let mut seen = BTreeMap::<(String, String), Value>::new();
    for observation in observations {
        let Ok(value) = serde_json::to_value(observation) else {
            continue;
        };
        for fact in list(&value, "facts") {
            let query = fact.get("query").cloned().unwrap_or_default();
            let kind = query
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let subject = ["requested", "name"]
                .iter()
                .find_map(|field| query.get(*field).and_then(Value::as_str))
                .unwrap_or("")
                .to_owned();
            let mut answer = fact.get("value").cloned().unwrap_or_default();
            if let Value::Object(answer) = &mut answer {
                answer.remove("kind");
            }
            let mut row = Map::new();
            row.insert("kind".into(), Value::String(kind.clone()));
            if !subject.is_empty() {
                row.insert("subject".into(), Value::String(subject.clone()));
            }
            if let Value::Object(answer) = answer {
                row.extend(answer);
            }
            seen.insert((kind, subject), Value::Object(row));
        }
    }
    seen.into_values().collect()
}
