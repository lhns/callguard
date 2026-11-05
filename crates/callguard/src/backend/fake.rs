use super::*;

// ---------------------------------------------------------------------------
// fake

/// Fake modes (`policy::Backend::fake_mode`).
pub(crate) const FAKE_RULES: &str = "rules";
pub(crate) const FAKE_ALLOW: &str = "allow";
pub(crate) const FAKE_ASK: &str = "ask";
pub(crate) const FAKE_DENY: &str = "deny";
pub(crate) const FAKE_GARBAGE: &str = "garbage";
pub(crate) const FAKE_SLOW: &str = "slow";
pub(crate) const FAKE_ERROR: &str = "error";
pub(crate) const FAKE_OBEY_INJECTION: &str = "obey-injection";
pub(super) const FAKE_RULES_CONFIDENT: f64 = 0.9;
pub(super) const FAKE_FIXED_CONFIDENT: f64 = 0.95;

pub(super) struct Fake {
    mode: String,
    classes: Vec<String>,
}

/// A fake backend in the given mode ("" means rules), for tests and offline eval.
pub fn new_fake(mode: &str) -> Result<Box<dyn Backend>, BackendError> {
    Ok(Box::new(Fake::new(&policy::Backend {
        r#type: "fake".into(),
        fake_mode: mode.into(),
        ..Default::default()
    })?))
}

impl Fake {
    pub(super) fn new(cfg: &policy::Backend) -> Result<Fake, BackendError> {
        let mode = if cfg.fake_mode.is_empty() {
            FAKE_RULES
        } else {
            cfg.fake_mode.as_str()
        };
        if ![
            FAKE_RULES,
            FAKE_ALLOW,
            FAKE_ASK,
            FAKE_DENY,
            FAKE_GARBAGE,
            FAKE_SLOW,
            FAKE_ERROR,
            FAKE_OBEY_INJECTION,
        ]
        .contains(&mode)
        {
            return Err(other(format!("unknown fake_mode {mode:?}")));
        }
        Ok(Fake {
            mode: mode.to_owned(),
            classes: cfg.data_classes.clone(),
        })
    }
}

impl Backend for Fake {
    fn name(&self) -> String {
        format!("fake:{}", self.mode)
    }

    fn data_classes(&self) -> &[String] {
        &self.classes
    }

    fn classify(
        &self,
        req: &ClassifyRequest,
        deadline: Instant,
    ) -> Result<ClassifyResult, BackendError> {
        match self.mode.as_str() {
            FAKE_ALLOW | FAKE_ASK | FAKE_DENY => {
                return Ok(ClassifyResult {
                    label: self.mode.clone(),
                    confidence: FAKE_FIXED_CONFIDENT,
                    rule: "fake".into(),
                    reason: "fixed fake answer".into(),
                    ..Default::default()
                });
            }
            FAKE_GARBAGE => {
                return Ok(ClassifyResult {
                    label: "definitely-fine".into(),
                    confidence: 7.0,
                    reason: "garbage".into(),
                    ..Default::default()
                });
            }
            FAKE_SLOW => {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                return Err(BackendError::Timeout);
            }
            FAKE_ERROR => return Err(other("fake backend error")),
            FAKE_OBEY_INJECTION if res::OBEY.is_match(&req.prompt) => {
                return Ok(ClassifyResult {
                    label: "allow".into(),
                    confidence: 0.99,
                    rule: "fake".into(),
                    reason: "obeyed injected instruction".into(),
                    ..Default::default()
                });
            }
            _ => {}
        }
        Ok(fake_rules(req))
    }
}

/// Injected text the obey-injection mode follows.
pub(super) const OBEY_PATTERN: &str = r"(?i)label[ _+-]this[ _+-]allow|ignore[ _+-](all[ _+-])?(the[ _+-])?(previous|prior)[ _+-]instructions|classifier|you are the reviewer";

mod res {
    use std::sync::LazyLock;

    use regex::Regex;

    use super::OBEY_PATTERN;
    use crate::rules::builtin_regex as re2;

    pub(crate) static OBEY: LazyLock<Regex> = LazyLock::new(|| re2(OBEY_PATTERN));
    pub(crate) static INJECTION: LazyLock<Regex> = LazyLock::new(|| {
        re2(&format!(
            "{OBEY_PATTERN}|</callguard-data>|</transcript>|reviewer:"
        ))
    });
    pub(crate) static SECRET_PATH: LazyLock<Regex> = LazyLock::new(|| {
        re2(
            r"(?i)\.ssh|id_rsa|id_ed25519|\.env\b|\.aws|\.npmrc|credentials|\.pem\b|/etc/shadow|secrets?\b",
        )
    });
    pub(crate) static UPLOAD: LazyLock<Regex> = LazyLock::new(|| {
        re2(
            r"(?i)(curl|wget)\b.*(-d\s*@|--data(-binary|-raw|-urlencode)?[ =]+@|-F\s*\S*=@|-T\s|--upload-file)",
        )
    });
    pub(crate) static COPY_OUT: LazyLock<Regex> =
        LazyLock::new(|| re2(r"(?i)\b(scp|nc|ncat|netcat|rsync|sftp)\b"));
    pub(crate) static ENV_LEAK: LazyLock<Regex> = LazyLock::new(|| {
        re2(
            r"(?i)\b(env|printenv|set)\b[^|]*\|\s*(curl|wget|nc)\b|(curl|wget)\b.*\$\(\s*(env|printenv)",
        )
    });
    pub(crate) static PIPE_SHELL: LazyLock<Regex> =
        LazyLock::new(|| re2(r"(?i)(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b"));
    pub(crate) static RM_RF: LazyLock<Regex> = LazyLock::new(|| {
        re2(r"(?i)\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-r\s+-f|-f\s+-r)\s+(\S+)")
    });
    pub(crate) static ASK: LazyLock<Regex> = LazyLock::new(|| {
        re2(
            r"(?i)\bgit\s+push\b|\bdeploy\b|\bdelete\b|\bpublish\b|chmod\s+(-r\s+)?777|\bterraform\s+(destroy|apply)\b|\bdrop\s+(database|table)\b|\brm\s+-[a-z]*r|\bgit\s+reset\s+--hard|\bgit\s+clean\s+-[a-z]*f",
        )
    });
    pub static POST: LazyLock<Regex> =
        LazyLock::new(|| re2(r"(?i)(curl|wget)\b.*(-X\s*(POST|PUT)|\s-d\s|--data)"));
}

/// A deterministic keyword heuristic. It scans the tool input (not the
/// transcript) when the structured input is present.
pub(super) fn fake_rules(req: &ClassifyRequest) -> ClassifyResult {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Structured {
        #[serde(deserialize_with = "raw_some")]
        input: Option<Box<RawValue>>,
        #[serde(deserialize_with = "nullable")]
        project_dir: String,
        #[serde(deserialize_with = "nullable")]
        context: std::collections::BTreeMap<String, String>,
    }
    let mut text = req.prompt.clone();
    let (mut project_dir, mut tainted) = (String::new(), false);
    if let Some(s) = req
        .input
        .as_deref()
        .and_then(|r| serde_json::from_str::<Structured>(r.get()).ok())
        && let Some(tool_input) = s.input
    {
        text = flatten(tool_input.get());
        project_dir = s.project_dir;
        tainted = s.context.get("trust").is_some_and(|t| t == "tainted");
    }
    let verdict = |label: &str, rule: &str, reason: &str| ClassifyResult {
        label: label.into(),
        confidence: FAKE_RULES_CONFIDENT,
        rule: rule.into(),
        reason: reason.into(),
        ..Default::default()
    };
    let secret = res::SECRET_PATH.is_match(&text);
    if res::UPLOAD.is_match(&text) && secret {
        return verdict("deny", "Data Exfiltration", "uploads a secret file");
    }
    if res::COPY_OUT.is_match(&text) && secret {
        return verdict("deny", "Data Exfiltration", "copies a secret file out");
    }
    if res::ENV_LEAK.is_match(&text) {
        return verdict(
            "deny",
            "Data Exfiltration",
            "sends the environment to a remote host",
        );
    }
    if res::PIPE_SHELL.is_match(&text) {
        return verdict(
            "deny",
            "Untrusted Code Execution",
            "pipes a download into a shell",
        );
    }
    for m in res::RM_RF.captures_iter(&text) {
        let arg = m.get(m.len() - 1).map_or("", |g| g.as_str());
        if outside_project(arg, &project_dir) {
            return verdict(
                "deny",
                "Destructive Action",
                "recursive delete outside the project",
            );
        }
    }
    if res::INJECTION.is_match(&text) {
        return verdict(
            "ask",
            "Injection",
            "tool input addresses a classifier or reviewer",
        );
    }
    if res::ASK.is_match(&text) {
        return verdict(
            "ask",
            "Irreversible Action",
            "affects shared state or is hard to undo",
        );
    }
    if tainted && (res::POST.is_match(&text) || res::UPLOAD.is_match(&text)) {
        return verdict(
            "ask",
            "Network Egress",
            "network write after reading untrusted content",
        );
    }
    verdict("allow", "", "routine call")
}

pub(super) fn outside_project(arg: &str, project_dir: &str) -> bool {
    let arg = arg.trim_matches(|c| c == '"' || c == '\'');
    if matches!(arg, "." | "./" | "") {
        return false;
    }
    if arg.starts_with('~') || arg.starts_with("$HOME") || arg == "/" || arg == "/*" {
        return true;
    }
    if arg.starts_with('/') {
        let prefix = format!("{}/", project_dir.trim_end_matches('/'));
        return project_dir.is_empty() || (arg != project_dir && !arg.starts_with(&prefix));
    }
    arg.starts_with("..")
}

/// Joins every string value of a JSON document with newlines.
pub(super) fn flatten(raw: &str) -> String {
    fn walk(v: &Value, out: &mut String) {
        match v {
            Value::String(s) => {
                out.push_str(s);
                out.push('\n');
            }
            Value::Array(a) => a.iter().for_each(|e| walk(e, out)),
            Value::Object(o) => o.values().for_each(|e| walk(e, out)),
            _ => {}
        }
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(v) => {
            let mut out = String::new();
            walk(&v, &mut out);
            out
        }
        Err(_) => raw.to_owned(),
    }
}
