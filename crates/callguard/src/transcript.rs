//! The reasoning-blind view of a conversation: user text, the assistant text a
//! user reply referred to, tool calls and their outcome labels (design
//! section 7, ADR 0005). Tool output never gets here.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::json_text;
use crate::serde_util::{nullable, raw_some};

/// Roles of a [`Message`].
pub const ROLE_USER: &str = "user";
pub const ROLE_ASSISTANT: &str = "assistant";
pub const ROLE_TOOL_CALL: &str = "tool_call";
pub const ROLE_OUTCOME: &str = "outcome";
/// Internal marker, never rendered.
pub const ROLE_THIRD_PARTY: &str = "third_party";

/// Outcomes of a tool call, derived from the harness's status and the start of
/// its error text, never from tool output.
pub const OUTCOME_OK: &str = "ok";
pub const OUTCOME_ERROR: &str = "error";
pub const OUTCOME_INTERRUPTED: &str = "interrupted";
pub const OUTCOME_REJECTED_BY_USER: &str = "rejected-by-user";
pub const OUTCOME_BLOCKED_BY_PERMISSIONS: &str = "blocked-by-permissions";
pub const OUTCOME_BLOCKED_BY_CLASSIFIER: &str = "blocked-by-classifier";
pub const OUTCOME_BLOCKED_BY_CALLGUARD: &str = "blocked-by-callguard";
pub const OUTCOME_CLASSIFIER_UNAVAILABLE: &str = "classifier-unavailable";

const TAIL_BYTES: u64 = 2 << 20;
const DEFAULT_MESSAGES: usize = 20;
const DEFAULT_BYTES: usize = 24000;
const TRUNC_MARKER: &str = "…[truncated]";

const OUTCOMES: [&str; 8] = [
    OUTCOME_OK,
    OUTCOME_ERROR,
    OUTCOME_INTERRUPTED,
    OUTCOME_REJECTED_BY_USER,
    OUTCOME_BLOCKED_BY_PERMISSIONS,
    OUTCOME_BLOCKED_BY_CLASSIFIER,
    OUTCOME_BLOCKED_BY_CALLGUARD,
    OUTCOME_CLASSIFIER_UNAVAILABLE,
];

/// One kept entry. "user" and "assistant" carry `text`; "tool_call" carries
/// `tool`, `input` and `id`; "outcome" carries the `id` of its call and an
/// `outcome`, never any tool output; "third_party" marks text from someone
/// other than the user and carries nothing.
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

/// Whether `s` is a known outcome value.
pub fn valid_outcome(s: &str) -> bool {
    OUTCOMES.contains(&s)
}

/// Harness-injected text in user-role messages: reminders, slash-command
/// echoes, shell and local command output.
const IGNORED_USER_PREFIXES: [&str; 5] = [
    "<system-reminder>",
    "<command-",
    "<local-command-",
    "<bash-stdout>",
    "<bash-stderr>",
];

/// User-role text that comes from a background task, a teammate agent or
/// another session, not from the user.
const THIRD_PARTY_PREFIXES: [&str; 3] = [
    "<task-notification>",
    "<teammate-message",
    "<cross-session-message",
];

#[derive(Deserialize, Default)]
#[serde(default)]
struct Entry {
    #[serde(rename = "type", deserialize_with = "nullable")]
    kind: String,
    #[serde(rename = "isMeta", deserialize_with = "nullable")]
    is_meta: bool,
    /// A subagent's turn: its "user" text is the assistant's prompt.
    #[serde(rename = "isSidechain", deserialize_with = "nullable")]
    is_sidechain: bool,
    #[serde(rename = "isCompactSummary", deserialize_with = "nullable")]
    is_compact_summary: bool,
    #[serde(rename = "toolUseResult", deserialize_with = "raw_some")]
    tool_use_result: Option<Box<RawValue>>,
    #[serde(deserialize_with = "nullable")]
    message: Body,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Body {
    #[serde(deserialize_with = "raw_some")]
    content: Option<Box<RawValue>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Block {
    #[serde(rename = "type", deserialize_with = "nullable")]
    kind: String,
    #[serde(deserialize_with = "nullable")]
    text: String,
    #[serde(deserialize_with = "nullable")]
    name: String,
    #[serde(deserialize_with = "nullable")]
    id: String,
    #[serde(deserialize_with = "raw_some")]
    input: Option<Box<RawValue>>,
    #[serde(deserialize_with = "nullable")]
    tool_use_id: String,
    #[serde(deserialize_with = "nullable")]
    is_error: bool,
    #[serde(deserialize_with = "raw_some")]
    content: Option<Box<RawValue>>,
}

/// Reads the last 2 MiB of a Claude Code JSONL transcript and returns the
/// newest messages within `max_messages` and `max_bytes`: user text, the
/// assistant text a user reply followed (see [`referents`]), tool calls and
/// their outcomes. Unparseable lines are skipped; a file with nothing usable
/// yields an empty vector. A limit of 0 means 20 messages and 24000 bytes.
///
/// Thinking and tool_result content are dropped, so tool output never reaches
/// the judge; a tool_result only yields an outcome label.
pub fn read_claude_jsonl(
    path: &str,
    max_messages: usize,
    max_bytes: usize,
) -> io::Result<Vec<Message>> {
    Ok(limit(
        referents(read_claude_messages(path)?),
        max_messages,
        max_bytes,
    ))
}

/// The messages in the tail of a Claude Code JSONL transcript, oldest first,
/// before [`referents`] and [`limit`].
pub fn read_claude_messages(path: &str) -> io::Result<Vec<Message>> {
    let mut f = File::open(path)?;
    let size = f.metadata()?.len();
    let partial = size > TAIL_BYTES;
    if partial {
        f.seek(SeekFrom::Start(size - TAIL_BYTES))?;
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let mut data = &buf[..];
    if partial {
        // The first line is cut in the middle.
        data = match data.iter().position(|&b| b == b'\n') {
            Some(i) => &data[i + 1..],
            None => &[],
        };
    }
    let mut msgs = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(line);
        let line = line.trim();
        if !line.is_empty() {
            msgs.extend(parse_line(line));
        }
    }
    Ok(msgs)
}

fn parse_line(line: &str) -> Vec<Message> {
    let Ok(e) = serde_json::from_str::<Entry>(line) else {
        return Vec::new();
    };
    if e.is_meta || e.is_sidechain || e.is_compact_summary {
        return Vec::new();
    }
    if e.kind != "user" && e.kind != "assistant" {
        return Vec::new();
    }
    let Some(content) = e.message.content.as_deref().map(RawValue::get) else {
        return Vec::new();
    };
    if let Ok(text) = serde_json::from_str::<Option<String>>(content) {
        return text_message(&e.kind, &text.unwrap_or_default());
    }
    let Ok(blocks) = serde_json::from_str::<Vec<Option<Block>>>(content) else {
        return Vec::new();
    };
    // The entry-level toolUseResult is a plain string only when the user
    // rejected the call.
    let rejected = e
        .tool_use_result
        .as_deref()
        .and_then(|r| serde_json::from_str::<String>(r.get()).ok())
        .is_some_and(|s| s == "User rejected tool use");
    let mut out = Vec::new();
    for b in blocks.into_iter().map(Option::unwrap_or_default) {
        if b.kind == "text" {
            out.extend(text_message(&e.kind, &b.text));
        } else if e.kind == "assistant" && b.kind == "tool_use" && !b.name.is_empty() {
            out.push(Message {
                role: ROLE_TOOL_CALL.into(),
                tool: b.name,
                input: b.input,
                id: b.id,
                ..Default::default()
            });
        } else if e.kind == "user" && b.kind == "tool_result" && !b.tool_use_id.is_empty() {
            let outcome = if rejected {
                OUTCOME_REJECTED_BY_USER.to_owned()
            } else {
                result_outcome(&b)
            };
            out.push(Message {
                role: ROLE_OUTCOME.into(),
                id: b.tool_use_id,
                outcome,
                ..Default::default()
            });
        }
    }
    out
}

fn text_message(kind: &str, text: &str) -> Vec<Message> {
    let t = text.trim();
    if t.is_empty() {
        return Vec::new();
    }
    let role = if kind == "assistant" {
        ROLE_ASSISTANT
    } else if THIRD_PARTY_PREFIXES.iter().any(|p| t.starts_with(p)) {
        return vec![Message {
            role: ROLE_THIRD_PARTY.into(),
            ..Default::default()
        }];
    } else if IGNORED_USER_PREFIXES.iter().any(|p| t.starts_with(p)) {
        return Vec::new();
    } else {
        ROLE_USER
    };
    vec![Message {
        role: role.into(),
        text: text.to_owned(),
        ..Default::default()
    }]
}

/// Error texts the harness writes for a call that did not run. Rejections and
/// denials always set is_error, and a failing Bash call starts with
/// "Exit code N", so command output cannot reach these prefixes while is_error
/// is set. They are matched only then: a successful result, whose text the
/// tool or an attacker controls, can never forge a label.
const ERROR_PREFIXES: [(&str, &str); 6] = [
    (
        "The user doesn't want to proceed with this tool use",
        OUTCOME_REJECTED_BY_USER,
    ),
    (
        "[Request interrupted by user for tool use]",
        OUTCOME_INTERRUPTED,
    ),
    (
        "Permission for this action was denied by the Claude Code auto mode classifier",
        OUTCOME_BLOCKED_BY_CLASSIFIER,
    ),
    (
        "Permission for this command was denied by a built-in Claude Code safety check",
        OUTCOME_BLOCKED_BY_PERMISSIONS,
    ),
    ("Permission to use ", OUTCOME_BLOCKED_BY_PERMISSIONS),
    (
        "The server-side auto mode classifier gave no verdict",
        OUTCOME_CLASSIFIER_UNAVAILABLE,
    ),
];

fn result_outcome(b: &Block) -> String {
    if !b.is_error {
        return OUTCOME_OK.into();
    }
    let text = first_text(b.content.as_deref().map(RawValue::get));
    let text = text.trim();
    for (prefix, outcome) in ERROR_PREFIXES {
        if text.starts_with(prefix) {
            return outcome.into();
        }
    }
    OUTCOME_ERROR.into()
}

/// The content string, or the first text block of a content array.
fn first_text(raw: Option<&str>) -> String {
    let Some(raw) = raw else {
        return String::new();
    };
    if let Ok(s) = serde_json::from_str::<Option<String>>(raw) {
        return s.unwrap_or_default();
    }
    if let Ok(blocks) = serde_json::from_str::<Vec<Option<Block>>>(raw) {
        for b in blocks.into_iter().flatten() {
            if b.kind == "text" {
                return b.text;
            }
        }
    }
    String::new()
}

/// Keeps assistant text only as the referent of a following user reply: an
/// assistant message stays only if the next message that is not a tool call or
/// outcome is a user message. Text with another assistant message or a
/// third-party marker in between, and all assistant text after the last user
/// message (the agent narrating the pending action), is dropped. Third-party
/// markers are removed.
pub fn referents(msgs: Vec<Message>) -> Vec<Message> {
    let keep: Vec<bool> = (0..msgs.len())
        .map(|i| match msgs[i].role.as_str() {
            ROLE_THIRD_PARTY => false,
            ROLE_ASSISTANT => msgs[i + 1..]
                .iter()
                .find(|m| m.role != ROLE_TOOL_CALL && m.role != ROLE_OUTCOME)
                .is_some_and(|m| m.role == ROLE_USER),
            _ => true,
        })
        .collect();
    msgs.into_iter()
        .zip(keep)
        .filter_map(|(m, k)| k.then_some(m))
        .collect()
}

/// Marks the tool calls whose ids are in `ids` as blocked by callguard: sets
/// the outcome of each, adding an outcome message after the call if it has none.
pub fn mark_blocked(msgs: Vec<Message>, ids: &HashSet<String>) -> Vec<Message> {
    if ids.is_empty() {
        return msgs;
    }
    let mut out = Vec::with_capacity(msgs.len() + 1);
    for (i, m) in msgs.iter().enumerate() {
        let mut m = m.clone();
        if m.role == ROLE_OUTCOME && ids.contains(&m.id) {
            m.outcome = OUTCOME_BLOCKED_BY_CALLGUARD.into();
        } else if m.role == ROLE_TOOL_CALL && !m.id.is_empty() && ids.contains(&m.id) {
            let has_outcome = msgs[i + 1..]
                .iter()
                .any(|x| x.role == ROLE_OUTCOME && x.id == m.id);
            let id = m.id.clone();
            out.push(m);
            if !has_outcome {
                out.push(Message {
                    role: ROLE_OUTCOME.into(),
                    id,
                    outcome: OUTCOME_BLOCKED_BY_CALLGUARD.into(),
                    ..Default::default()
                });
            }
            continue;
        }
        out.push(m);
    }
    out
}

/// Keeps the newest messages within `max_messages` and `max_bytes` (a
/// message's size is its text plus its input, in bytes). Outcomes are tiny and
/// do not count toward `max_messages`; those whose call was cut are dropped.
/// Any single text or input over `max_bytes / 4` is truncated with a marker.
/// A limit of 0 means 20 messages and 24000 bytes.
pub fn limit(msgs: Vec<Message>, max_messages: usize, max_bytes: usize) -> Vec<Message> {
    let max_messages = if max_messages == 0 {
        DEFAULT_MESSAGES
    } else {
        max_messages
    };
    let max_bytes = if max_bytes == 0 {
        DEFAULT_BYTES
    } else {
        max_bytes
    };
    let one = max_bytes / 4;
    let mut kept = Vec::new();
    let (mut total, mut n) = (0, 0);
    for m in msgs.into_iter().rev() {
        if n >= max_messages {
            break;
        }
        let m = truncate(m, one);
        let size = m.text.len() + m.input.as_deref().map_or(0, |r| r.get().len());
        if total + size > max_bytes {
            break;
        }
        total += size;
        if m.role != ROLE_OUTCOME {
            n += 1;
        }
        kept.push(m);
    }
    kept.reverse();
    let calls: HashSet<String> = kept
        .iter()
        .filter(|m| m.role == ROLE_TOOL_CALL && !m.id.is_empty())
        .map(|m| m.id.clone())
        .collect();
    kept.retain(|m| m.role != ROLE_OUTCOME || calls.contains(&m.id));
    kept
}

fn truncate(mut m: Message, max: usize) -> Message {
    if m.text.len() > max {
        m.text = cut(&m.text, max);
    }
    if let Some(raw) = m.input.as_deref().map(RawValue::get)
        && raw.len() > max
    {
        // A cut JSON document is invalid, so the truncated input becomes a string.
        let s = json_text::to_string(&cut(raw, max)).unwrap_or_default();
        m.input = RawValue::from_string(s).ok();
    }
    m
}

/// Shortens `s` so that the result, marker included, fits in `max` bytes
/// (best effort for tiny limits) and ends on a character boundary.
fn cut(s: &str, max: usize) -> String {
    let mut n = max.saturating_sub(TRUNC_MARKER.len());
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    format!("{}{TRUNC_MARKER}", &s[..n])
}

/// Removes the trailing tool_call that duplicates the pending action: Claude
/// writes the tool_use to the transcript before the hook runs.
///
/// This must run before [`limit`]: a long input is cut to a string there, which
/// no longer equals the pending input.
pub fn drop_pending(mut msgs: Vec<Message>, tool: &str, input: Option<&RawValue>) -> Vec<Message> {
    if let Some(m) = msgs.last()
        && m.role == ROLE_TOOL_CALL
        && m.tool == tool
        && same_json(m.input.as_deref(), input)
    {
        msgs.pop();
    }
    msgs
}

/// Compares two JSON documents by value, so key order and spacing (which
/// differ between the hook payload and the transcript) do not matter.
fn same_json(a: Option<&RawValue>, b: Option<&RawValue>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            match (
                serde_json::from_str::<Value>(a.get()),
                serde_json::from_str::<Value>(b.get()),
            ) {
                (Ok(a), Ok(b)) => json_eq(&a, &b),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Value equality on decoded JSON: every number
/// is a float64, so `1` equals `1.0`.
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, p)| y.get(k).is_some_and(|q| json_eq(p, q)))
        }
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        format!(
            "{}/testdata/transcript/claude.jsonl",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    fn raw(s: &str) -> Option<Box<RawValue>> {
        Some(RawValue::from_string(s.into()).unwrap())
    }

    fn input_str(m: &Message) -> &str {
        m.input.as_deref().map_or("", RawValue::get)
    }

    fn msg(role: &str, text: &str) -> Message {
        Message {
            role: role.into(),
            text: text.into(),
            ..Default::default()
        }
    }

    fn write_lines(lines: &[&str]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.jsonl");
        std::fs::write(&p, lines.join("\n")).unwrap();
        let p = p.to_str().unwrap().to_owned();
        (dir, p)
    }

    #[test]
    fn read_claude_jsonl_fixture() {
        let msgs = read_claude_jsonl(&fixture(), 0, 0).unwrap();
        // role, text, tool, input, id, outcome
        let wants = [
            ("user", "please run the tests", "", "", "", ""),
            // The assistant text the user's next message replies to is kept.
            (
                "assistant",
                "ASSISTANT PROSE: I will run go test",
                "",
                "",
                "",
                "",
            ),
            (
                "tool_call",
                "",
                "Bash",
                r#"{"command":"go test ./..."}"#,
                "t1",
                "",
            ),
            ("outcome", "", "", "", "t1", "ok"),
            ("user", "now fix the failing test", "", "", "", ""),
            // The trailing assistant text is the agent narrating, not a referent.
            (
                "tool_call",
                "",
                "Edit",
                r#"{"file_path":"/work/app/main_test.go","old_string":"a","new_string":"b"}"#,
                "t2",
                "",
            ),
        ];
        let all = serde_json::to_string(&msgs).unwrap();
        assert_eq!(msgs.len(), wants.len(), "{all}");
        for (i, w) in wants.iter().enumerate() {
            let m = &msgs[i];
            let got = (
                m.role.as_str(),
                m.text.as_str(),
                m.tool.as_str(),
                input_str(m),
                m.id.as_str(),
                m.outcome.as_str(),
            );
            assert_eq!(got, *w, "msg {i}");
        }
        for bad in [
            "IGNORE PREVIOUS",
            "SECRET REASONING",
            "plain string assistant text",
            "Caveat",
            "compact summary",
            "harness noise",
            "AAAA",
        ] {
            assert!(!all.contains(bad), "{bad:?} survived");
        }
    }

    #[test]
    fn read_claude_jsonl_edge_cases() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.jsonl");
        assert!(read_claude_jsonl(missing.to_str().unwrap(), 0, 0).is_err());
        let p = dir.path().join("junk.jsonl");
        std::fs::write(&p, "garbage\n{not json\n").unwrap();
        assert!(
            read_claude_jsonl(p.to_str().unwrap(), 0, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn tail_drops_partial_line() {
        let line = "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"LINE\"}}\n";
        let pad = format!(
            "{{\"type\":\"user\",\"message\":{{\"role\":\"user\",\"content\":\"{}\"}}}}\n",
            "p".repeat(1000)
        );
        let mut b = String::from(line); // far in front of the tail window
        while (b.len() as u64) < TAIL_BYTES + 5000 {
            b.push_str(&pad);
        }
        b.push_str("{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"LAST\"}}\n");
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.jsonl");
        std::fs::write(&p, b).unwrap();
        let msgs = read_claude_jsonl(p.to_str().unwrap(), 3, 0).unwrap();
        assert_eq!(msgs.last().map(|m| m.text.as_str()), Some("LAST"));
        assert!(
            msgs.iter().all(|m| m.text != "LINE"),
            "line outside the tail window was read"
        );
    }

    #[test]
    fn limit_counts_and_truncates() {
        let msgs: Vec<Message> = (0..30)
            .map(|i| msg("user", &format!("{}xx", (b'a' + i % 26) as char)))
            .collect();
        let got = limit(msgs.clone(), 0, 0);
        assert_eq!(got.len(), 20);
        assert_eq!(got[19].text, msgs[29].text);
        assert_eq!(got[0].text, msgs[10].text);
        let got = limit(msgs.clone(), 100, 12); // 4 messages of 3 bytes
        assert_eq!(got.len(), 4);
        assert_eq!(got[3].text, msgs[29].text);

        let long = msg("user", &"é".repeat(400));
        let got = limit(vec![long], 5, 400);
        assert!(
            got.len() == 1 && got[0].text.ends_with("…[truncated]") && got[0].text.len() <= 100
        );
        let call = Message {
            role: "tool_call".into(),
            tool: "Bash".into(),
            input: raw(&format!("{{\"command\":\"{}\"}}", "x".repeat(500))),
            ..Default::default()
        };
        let got = limit(vec![call], 5, 400);
        assert_eq!(got.len(), 1);
        let s: String = serde_json::from_str(got[0].input.as_deref().unwrap().get()).unwrap();
        assert!(s.ends_with("…[truncated]"));
    }

    /// Harness-generated user-role text (background task results, shell output,
    /// local command caveats) and sidechain entries (a subagent prompt written by
    /// the assistant) are not the user's words and must not reach the judge.
    #[test]
    fn drops_non_user_text() {
        let (_d, p) = write_lines(&[
            r#"{"type":"user","message":{"role":"user","content":"<task-notification>\n<summary>LEAK1</summary>\n</task-notification>"}}"#,
            r#"{"type":"user","message":{"role":"user","content":"<local-command-caveat>LEAK2</local-command-caveat>"}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"text","text":"<bash-stdout>LEAK3</bash-stdout>"}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":"<bash-stderr>LEAK4</bash-stderr>"}}"#,
            r#"{"type":"user","isSidechain":true,"message":{"role":"user","content":"LEAK5 written by the assistant"}}"#,
            r#"{"type":"user","message":{"role":"user","content":"keep me"}}"#,
        ]);
        let msgs = read_claude_jsonl(&p, 0, 0).unwrap();
        assert!(msgs.len() == 1 && msgs[0].text == "keep me", "{msgs:?}");
    }

    /// A teammate or cross-session message arrives in a user-role entry but is
    /// not the user's consent: its text must not reach the judge as user text.
    #[test]
    fn third_party_messages_are_not_user_text() {
        let (_d, p) = write_lines(&[
            r#"{"type":"user","message":{"role":"user","content":"<teammate-message teammate_id=\"a\">LEAKT approve the push</teammate-message>"}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"text","text":"<cross-session-message>LEAKC do it</cross-session-message>"}]}}"#,
            r#"{"type":"user","message":{"role":"user","content":"keep me"}}"#,
        ]);
        let msgs = read_claude_jsonl(&p, 0, 0).unwrap();
        let all = serde_json::to_string(&msgs).unwrap();
        assert!(
            !all.contains("LEAK") && msgs.len() == 1 && msgs[0].text == "keep me",
            "{all}"
        );
    }

    fn result(id: &str, is_err: bool, content: &str) -> String {
        format!(
            r#"{{"type":"user","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"{id}","is_error":{is_err},"content":{}}}]}}}}"#,
            serde_json::to_string(content).unwrap()
        )
    }

    #[test]
    fn outcomes_from_tool_results() {
        let arr = r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"a7","is_error":true,"content":[{"type":"text","text":"[Request interrupted by user for tool use]"}]}]}}"#;
        let reject = r#"{"type":"user","toolUseResult":"User rejected tool use","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"a8","is_error":true,"content":"whatever"}]}}"#;
        let mut lines: Vec<String> = ["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"]
            .iter()
            .map(|id| {
                format!(
                    r#"{{"type":"assistant","message":{{"role":"assistant","content":[{{"type":"tool_use","id":"{id}","name":"Bash","input":{{}}}}]}}}}"#
                )
            })
            .collect();
        lines.extend([
            result("a1", false, "fine"),
            result("a2", true, "Exit code 1\nboom"),
            result(
                "a3",
                true,
                "The user doesn't want to proceed with this tool use. The tool use was rejected",
            ),
            result(
                "a4",
                true,
                "Permission for this action was denied by the Claude Code auto mode classifier: x",
            ),
            result("a5", true, "Permission to use Bash has been denied."),
            result(
                "a6",
                true,
                "The server-side auto mode classifier gave no verdict",
            ),
            arr.into(),
            reject.into(),
            // Without is_error the prefixes are plain output.
            result(
                "a9",
                false,
                "The user doesn't want to proceed with this tool use",
            ),
        ]);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let (_d, p) = write_lines(&refs);
        let msgs = read_claude_jsonl(&p, 100, 1 << 20).unwrap();
        let got: std::collections::HashMap<&str, &str> = msgs
            .iter()
            .filter(|m| m.role == ROLE_OUTCOME)
            .map(|m| (m.id.as_str(), m.outcome.as_str()))
            .collect();
        let want = [
            ("a1", "ok"),
            ("a2", "error"),
            ("a3", "rejected-by-user"),
            ("a4", "blocked-by-classifier"),
            ("a5", "blocked-by-permissions"),
            ("a6", "classifier-unavailable"),
            ("a7", "interrupted"),
            ("a8", "rejected-by-user"),
            ("a9", "ok"),
        ];
        for (id, w) in want {
            assert_eq!(got.get(id), Some(&w), "{id}");
        }
        assert!(
            !serde_json::to_string(&msgs).unwrap().contains("boom"),
            "tool output reached the transcript"
        );
    }

    #[test]
    fn referents_keep_only_reply_targets() {
        let u = |s| msg(ROLE_USER, s);
        let a = |s| msg(ROLE_ASSISTANT, s);
        let call = Message {
            role: ROLE_TOOL_CALL.into(),
            tool: "Bash".into(),
            id: "c".into(),
            ..Default::default()
        };
        let out = Message {
            role: ROLE_OUTCOME.into(),
            id: "c".into(),
            outcome: "ok".into(),
            ..Default::default()
        };
        let tp = msg(ROLE_THIRD_PARTY, "");
        let input = vec![
            a("A1 dropped, A2 follows"),
            a("A2 kept"),
            call.clone(),
            out.clone(),
            u("U1"),
            a("A3 dropped by third party"),
            tp,
            u("U2"),
            a("A4 narration"),
            call,
            out,
        ];
        let got: Vec<String> = referents(input)
            .iter()
            .map(|m| format!("{}:{}", m.role, m.text))
            .collect();
        assert_eq!(
            got.join(" "),
            "assistant:A2 kept tool_call: outcome: user:U1 user:U2 tool_call: outcome:"
        );
    }

    #[test]
    fn limit_drops_orphan_outcomes_and_mark_blocked() {
        let msgs = vec![
            Message {
                role: ROLE_TOOL_CALL.into(),
                tool: "Bash".into(),
                id: "c1".into(),
                input: raw(r#"{"a":"xxxxxxxx"}"#),
                ..Default::default()
            },
            Message {
                role: ROLE_OUTCOME.into(),
                id: "c1".into(),
                outcome: "ok".into(),
                ..Default::default()
            },
            msg(ROLE_USER, "hi"),
        ];
        let got = limit(msgs, 1, 0); // only the newest non-outcome message fits
        assert!(got.len() == 1 && got[0].role == ROLE_USER, "{got:?}");

        let call = |id: &str| Message {
            role: ROLE_TOOL_CALL.into(),
            tool: "Bash".into(),
            id: id.into(),
            ..Default::default()
        };
        let marked = mark_blocked(
            vec![
                call("c1"),
                Message {
                    role: ROLE_OUTCOME.into(),
                    id: "c1".into(),
                    outcome: "error".into(),
                    ..Default::default()
                },
                call("c2"),
                call("c3"),
            ],
            &["c1", "c2"].iter().map(|s| s.to_string()).collect(),
        );
        let s: Vec<String> = marked
            .iter()
            .map(|m| format!("{}:{}:{}", m.role, m.id, m.outcome))
            .collect();
        assert_eq!(
            s.join(" "),
            "tool_call:c1: outcome:c1:blocked-by-callguard tool_call:c2: outcome:c2:blocked-by-callguard tool_call:c3:"
        );
    }

    #[test]
    fn valid_outcomes() {
        assert!(valid_outcome("blocked-by-callguard"));
        assert!(!valid_outcome("fine"));
    }

    #[test]
    fn json_numbers_compare_by_value() {
        assert!(same_json(
            raw(r#"{"n":1}"#).as_deref(),
            raw(r#"{"n":1.0}"#).as_deref()
        ));
        assert!(!same_json(
            raw(r#"{"n":1}"#).as_deref(),
            raw(r#"{"n":2}"#).as_deref()
        ));
        assert!(!same_json(raw("1").as_deref(), None));
    }
}
