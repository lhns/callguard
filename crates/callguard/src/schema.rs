//! The wire types: `callguard/request/v1` and `callguard/verdict/v1`
//! (ADR 0002). Same JSON names and
//! omit-when-empty rules. `Tool.input` stays raw JSON.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

pub use crate::hostmeta::{GitStatus, Meta, RepoVisibility};
use crate::serde_util::{go_float, is_false, is_zero, nullable, raw_some};

/// Schema identifiers (ADR 0002).
pub const REQUEST_SCHEMA: &str = "callguard/request/v1";
pub const VERDICT_SCHEMA: &str = "callguard/verdict/v1";

/// The outcome for one tool call. An unknown decision cannot be built,
/// so there is no validity check. Parse an untrusted string with [`Decision::parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// No human prompt needed.
    Allow,
    /// A human should confirm.
    Ask,
    /// Do not run.
    Deny,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Ask => "ask",
            Decision::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<Decision> {
        match s {
            "allow" => Some(Decision::Allow),
            "ask" => Some(Decision::Ask),
            "deny" => Some(Decision::Deny),
            _ => None,
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Layer names recorded in `Verdict.layer`.
pub const LAYER_BUILTIN: &str = "builtin";
pub const LAYER_NAH: &str = "nah";
pub const LAYER_RULES: &str = "rules";
pub const LAYER_LLM: &str = "llm";
/// Nothing decided; `enforced` is false.
pub const LAYER_NONE: &str = "none";
/// Error, timeout, unavailable backend.
pub const LAYER_FALLBACK: &str = "fallback";

/// callguard/request/v1.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Request {
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub schema: String,
    #[serde(skip_serializing_if = "is_zero", deserialize_with = "nullable")]
    pub v: i64,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub harness: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub session_id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub tool_use_id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub cwd: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub project_dir: String,
    #[serde(deserialize_with = "nullable")]
    pub tool: ToolCall,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript: Option<Transcript>,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "nullable"
    )]
    pub context: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub unattended: bool,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub permission_mode: String,
    /// Host observations; adapters never fill them from agent text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts: Option<Facts>,
}

impl Request {
    /// Decodes a request object. Field names match in any letter case (the
    /// exact spelling wins), also inside `tool`; `tool.input` stays as sent.
    pub fn from_json(body: &[u8]) -> Result<Request, String> {
        crate::serde_util::decode_object(
            body,
            &[
                "schema",
                "v",
                "harness",
                "session_id",
                "tool_use_id",
                "cwd",
                "project_dir",
                "tool",
                "transcript",
                "context",
                "unattended",
                "permission_mode",
                "meta",
                "facts",
            ],
            &[("tool", &["name", "input"])],
            false,
        )
    }
}

/// The pending call. `input` is the harness's argument object, as sent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolCall {
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "raw_some")]
    pub input: Option<Box<RawValue>>,
}

impl ToolCall {
    /// The raw input text, "" if the request had none.
    pub fn input_str(&self) -> &str {
        self.input.as_deref().map_or("", RawValue::get)
    }
}

/// Points at, or carries, the conversation so far. Only user text and earlier
/// tool calls are ever shown to the judge.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Transcript {
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub path: String,
    /// "claude-jsonl".
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub format: String,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub messages: Vec<Message>,
}

/// One reasoning-blind transcript entry. `role` is "user" or "assistant"
/// (`text`), "tool_call" (`tool`, `input`, optional `id`), "outcome" (`id` of
/// the call, `outcome`: ok, error, interrupted, rejected-by-user,
/// blocked-by-permissions, blocked-by-classifier, blocked-by-callguard,
/// classifier-unavailable) or "third_party" (no content; marks a teammate or
/// task message so the assistant text before it is not taken as a referent).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Message {
    #[serde(deserialize_with = "nullable")]
    pub role: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub text: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "raw_some")]
    pub input: Option<Box<RawValue>>,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub id: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub outcome: String,
}

/// callguard/verdict/v1. `decision` is required on read: a verdict without
/// one is not a verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    #[serde(default, deserialize_with = "nullable")]
    pub schema: String,
    #[serde(default, deserialize_with = "nullable")]
    pub v: i64,
    #[serde(default, deserialize_with = "nullable")]
    pub id: String,
    pub decision: Decision,
    #[serde(default, deserialize_with = "nullable")]
    pub enforced: bool,
    #[serde(default, deserialize_with = "nullable")]
    pub reason: String,
    #[serde(default, deserialize_with = "nullable")]
    pub layer: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub rule: String,
    #[serde(default, serialize_with = "go_float", deserialize_with = "nullable")]
    pub confidence: f64,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub policy_rev: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub backend: String,
    #[serde(default, deserialize_with = "nullable")]
    pub latency_ms: i64,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "nullable"
    )]
    pub warnings: Vec<String>,
}

/// A deterministic parse of the pending call (from nah). Strings inside are
/// untrusted data.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Facts {
    /// "nah-decide", "nah-wasm", or a host name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub source: String,
    /// "full" or "partial".
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub coverage: String,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub guards: Vec<String>,
    /// Unwrapped sub-commands.
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub commands: Vec<FactCommand>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub effects: Vec<FactEffect>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub paths: Vec<FactPath>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub git: Vec<FactGit>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub hosts: Vec<FactHost>,
    /// Decoded payloads (base64, -EncodedCommand, ...).
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub decoded: Vec<FactPayload>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub gaps: Vec<String>,
}

/// One unwrapped sub-command. `via` names the wrapper that ran it: "bash -c",
/// "eval", "xargs", "find -exec", "base64", ...
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FactCommand {
    /// Always written, even when empty (no omitempty here).
    #[serde(deserialize_with = "nullable")]
    pub argv: Vec<String>,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub cwd: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub via: String,
}

/// Something the call does. `kind` examples: fs.read fs.write fs.delete
/// fs.move net.download net.upload net.request net.listen exec env.read
/// env.write credential.read git.push git.history-rewrite.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FactEffect {
    #[serde(deserialize_with = "nullable")]
    pub kind: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub target: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub detail: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub certainty: String,
}

/// A path the call touches. `scope`: project home system temp outside unknown.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FactPath {
    #[serde(deserialize_with = "nullable")]
    pub path: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub scope: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub sensitivity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracked: Option<bool>,
}

/// A git operation the call performs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FactGit {
    #[serde(deserialize_with = "nullable")]
    pub op: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub remote: String,
    #[serde(
        rename = "ref",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub git_ref: String,
    #[serde(skip_serializing_if = "is_false", deserialize_with = "nullable")]
    pub force: bool,
}

/// A network host the call talks to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FactHost {
    #[serde(deserialize_with = "nullable")]
    pub host: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub operation: String,
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "nullable"
    )]
    pub direction: String,
}

/// A decoded payload (base64, -EncodedCommand, ...).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FactPayload {
    #[serde(deserialize_with = "nullable")]
    pub encoding: String,
    #[serde(deserialize_with = "nullable")]
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn repo_file(rel: &str) -> String {
        let p = format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
    }

    /// The zero value that omitempty leaves out.
    fn is_empty_value(v: &Value) -> bool {
        match v {
            Value::Null => true,
            Value::Bool(b) => !b,
            Value::Number(n) => n.as_f64() == Some(0.0),
            Value::String(s) => s.is_empty(),
            Value::Array(a) => a.is_empty(),
            Value::Object(o) => o.is_empty(),
        }
    }

    /// `out` holds every non-empty field of `orig`, equal, and nothing else.
    fn same_modulo_empty(orig: &Value, out: &Value, at: &str) {
        match (orig, out) {
            (Value::Object(a), Value::Object(b)) => {
                for (k, av) in a {
                    match b.get(k) {
                        Some(bv) => same_modulo_empty(av, bv, &format!("{at}.{k}")),
                        None => assert!(is_empty_value(av), "{at}.{k} = {av} was dropped"),
                    }
                }
                for k in b.keys() {
                    assert!(a.contains_key(k), "{at}.{k} appeared");
                }
            }
            (Value::Array(a), Value::Array(b)) => {
                assert_eq!(a.len(), b.len(), "{at}: array length");
                for (i, (av, bv)) in a.iter().zip(b).enumerate() {
                    same_modulo_empty(av, bv, &format!("{at}[{i}]"));
                }
            }
            _ => assert_eq!(orig, out, "{at}"),
        }
    }

    #[test]
    fn cases_jsonl_requests_round_trip() {
        let mut n = 0;
        for line in repo_file("evals/cases.jsonl").lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let case: Value = serde_json::from_str(line).unwrap();
            let id = case["id"].as_str().unwrap().to_owned();
            let req_text = serde_json::to_string(&case["request"]).unwrap();
            let req: Request =
                serde_json::from_str(&req_text).unwrap_or_else(|e| panic!("{id}: {e}"));
            let out = serde_json::to_string(&req).unwrap();
            let back: Value = serde_json::from_str(&out).unwrap();
            same_modulo_empty(&case["request"], &back, &id);
            assert_eq!(
                req.tool.input_str(),
                serde_json::to_string(&case["request"]["tool"]["input"]).unwrap(),
                "{id}: tool.input"
            );
            let again =
                serde_json::to_string(&serde_json::from_str::<Request>(&out).unwrap()).unwrap();
            assert_eq!(out, again, "{id}");
            n += 1;
        }
        assert!(n >= 60, "only {n} cases");
    }

    #[test]
    fn hook_fixtures_are_json_objects() {
        // The fixtures are harness payloads, not callguard requests, so the
        // hook adapters (not this module) parse them; this only guards the files.
        let dir = format!("{}/testdata/hook", env!("CARGO_MANIFEST_DIR"));
        let mut n = 0;
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            assert!(v.is_object(), "{}", p.display());
            n += 1;
        }
        assert!(n >= 9);
    }

    #[test]
    fn request_omits_empty_fields() {
        let req = Request {
            tool: ToolCall {
                name: "Bash".into(),
                input: None,
            },
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"tool":{"name":"Bash"}}"#
        );
    }

    #[test]
    fn request_keys_match_in_any_letter_case() {
        let r = Request::from_json(
            br#"{"Unattended":true,"TOOL":{"Name":"Bash","INPUT":{"Command":"ls"}}}"#,
        )
        .unwrap();
        assert!(r.unattended);
        assert_eq!(r.tool.name, "Bash");
        // The tool input is raw: its keys and spacing are not touched.
        assert_eq!(r.tool.input_str(), r#"{"Command":"ls"}"#);
        // The exact name wins, whatever the order.
        let r = Request::from_json(br#"{"cwd":"/a","CWD":"/b"}"#).unwrap();
        assert_eq!(r.cwd, "/a");
        let r = Request::from_json(br#"{"CWD":"/b","cwd":"/a"}"#).unwrap();
        assert_eq!(r.cwd, "/a");
        // Without an exact name the last one wins.
        let r = Request::from_json(br#"{"Cwd":"/a","CWD":"/b"}"#).unwrap();
        assert_eq!(r.cwd, "/b");
        // Still refused: an exact duplicate, a null in a string map, a non-object.
        assert!(Request::from_json(br#"{"cwd":"/a","cwd":"/b"}"#).is_err());
        assert!(Request::from_json(br#"{"context":{"a":null}}"#).is_err());
        assert!(Request::from_json(b"[1]").is_err());
    }

    #[test]
    fn request_accepts_nulls_and_missing_fields() {
        let req: Request = serde_json::from_str(
            r#"{"cwd":null,"context":null,"unattended":null,"tool":{"name":"Read","input":null},"transcript":null,"unknown":1}"#,
        )
        .unwrap();
        assert_eq!(req.cwd, "");
        assert!(req.context.is_empty());
        assert_eq!(req.tool.input_str(), "null"); // the literal null is kept
        assert!(req.transcript.is_none());
        let req: Request = serde_json::from_str("{}").unwrap();
        assert_eq!(req.tool.name, "");
        assert!(serde_json::from_str::<Request>(r#"{"v":"1"}"#).is_err());
    }

    #[test]
    fn tool_input_is_kept_verbatim() {
        let text =
            r#"{"tool":{"name":"Bash","input":{"command":"echo  \"x\"","n":1.50,"z":[1, 2]}}}"#;
        let req: Request = serde_json::from_str(text).unwrap();
        assert_eq!(
            req.tool.input_str(),
            r#"{"command":"echo  \"x\"","n":1.50,"z":[1, 2]}"#
        );
        let out = serde_json::to_string(&req).unwrap();
        assert!(out.contains(req.tool.input_str()));
    }

    #[test]
    fn verdict_field_order_and_omissions() {
        let v = Verdict {
            schema: VERDICT_SCHEMA.into(),
            v: 1,
            id: "abc".into(),
            decision: Decision::Deny,
            enforced: true,
            reason: "r".into(),
            layer: LAYER_BUILTIN.into(),
            rule: String::new(),
            confidence: 1.0,
            policy_rev: String::new(),
            backend: String::new(),
            latency_ms: 0,
            warnings: vec![],
        };
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#"{"schema":"callguard/verdict/v1","v":1,"id":"abc","decision":"deny","enforced":true,"reason":"r","layer":"builtin","confidence":1,"latency_ms":0}"#
        );
        let v = Verdict {
            confidence: 0.9,
            rule: "x".into(),
            warnings: vec!["w".into()],
            ..v
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(
            s.contains(r#""rule":"x","confidence":0.9,"#) && s.ends_with(r#""warnings":["w"]}"#),
            "{s}"
        );
    }

    #[test]
    fn facts_round_trip() {
        let facts = json!({
            "source": "nah-decide", "coverage": "full", "guards": ["a"],
            "commands": [{"argv": ["git", "push"], "via": "bash -c"}, {"argv": []}],
            "effects": [{"kind": "git.push", "target": "origin"}],
            "paths": [{"path": "/x", "scope": "home", "tracked": false}],
            "git": [{"op": "push", "ref": "main", "force": true}],
            "hosts": [{"host": "h", "direction": "out"}],
            "decoded": [{"encoding": "base64", "text": "hi"}],
            "gaps": ["g"]
        });
        let f: Facts = serde_json::from_value(facts.clone()).unwrap();
        assert_eq!(f.git[0].git_ref, "main");
        assert_eq!(f.paths[0].tracked, Some(false));
        assert_eq!(serde_json::to_value(&f).unwrap(), facts);
    }

    #[test]
    fn decision_parses_only_the_three() {
        assert_eq!(Decision::parse("ask"), Some(Decision::Ask));
        assert_eq!(Decision::parse("Allow"), None);
        assert!(serde_json::from_str::<Decision>("\"maybe\"").is_err());
    }
}
