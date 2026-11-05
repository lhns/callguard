use super::*;

// ---------------------------------------------------------------------------
// exec

pub(super) const MAX_EXEC_OUTPUT: usize = 64 << 10;

pub(super) struct ExecBackend {
    command: Vec<String>,
    classes: Vec<String>,
}

impl ExecBackend {
    pub(super) fn new(cfg: &policy::Backend) -> Result<ExecBackend, BackendError> {
        if cfg.command.first().is_none_or(String::is_empty) {
            return Err(other("exec backend needs command"));
        }
        Ok(ExecBackend {
            command: cfg.command.clone(),
            classes: cfg.data_classes.clone(),
        })
    }
}

/// What an exec plugin receives on stdin: the request's fields, with `schema`
/// naming the wire format. The request's own answer schema is not sent.
#[derive(Serialize)]
pub(super) struct ExecInput<'a> {
    schema: &'static str,
    system: &'a str,
    prompt: &'a str,
    labels: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<&'a RawValue>,
}

/// Reads `r` to the end, keeping at most `max` bytes and noting overflow. It
/// keeps draining so the child never blocks on a full pipe.
pub(super) fn read_limited(mut r: impl Read, max: usize) -> (Vec<u8>, bool) {
    let (mut buf, mut overflow) = (Vec::new(), false);
    let mut chunk = [0u8; 8192];
    while let Ok(n) = r.read(&mut chunk) {
        if n == 0 {
            break;
        }
        let room = max - buf.len();
        if n > room {
            overflow = true;
        }
        buf.extend_from_slice(&chunk[..n.min(room)]);
    }
    (buf, overflow)
}

impl Backend for ExecBackend {
    fn name(&self) -> String {
        let base = std::path::Path::new(&self.command[0])
            .file_name()
            .map_or_else(
                || self.command[0].clone(),
                |f| f.to_string_lossy().into_owned(),
            );
        let stem = match base.rfind('.') {
            Some(i) if i > 0 => &base[..i],
            _ => &base,
        };
        format!("exec:{stem}")
    }

    fn data_classes(&self) -> &[String] {
        &self.classes
    }

    fn classify(
        &self,
        req: &ClassifyRequest,
        deadline: Instant,
    ) -> Result<ClassifyResult, BackendError> {
        let stdin_json = json_text::to_string(&ExecInput {
            schema: CLASSIFY_SCHEMA,
            system: &req.system,
            prompt: &req.prompt,
            labels: &req.labels,
            input: req.input.as_deref(),
        })
        .map_err(|e| other(e.to_string()))?;
        remaining(deadline)?;
        let mut child = Command::new(crate::which::program(&self.command[0]))
            .args(&self.command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| other(format!("exec: {e}")))?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        // The plugin may exit without reading; a failed write is its business.
        std::thread::spawn(move || {
            let _ = stdin.write_all(stdin_json.as_bytes());
        });
        // A grandchild holding a pipe open must not hold us past the deadline.
        let out_rx = read_in_background(stdout, |r| read_limited(r, MAX_EXEC_OUTPUT));
        let err_rx = read_in_background(stderr, |r| read_limited(r, 2048));
        let status = match wait_until(&mut child, deadline) {
            Ok(Some(st)) => st,
            Ok(None) => {
                // The readers are left to finish alone.
                kill(&mut child);
                return Err(BackendError::Timeout);
            }
            Err(e) => return Err(other(format!("exec: {e}"))),
        };
        let wait = deadline.saturating_duration_since(Instant::now());
        let (stdout, overflow) = out_rx
            .recv_timeout(wait)
            .map_err(|_| BackendError::Timeout)?;
        let (stderr, _) = err_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_default();
        if !status.success() {
            let code = status
                .code()
                .map_or_else(|| "signal".to_owned(), |c| c.to_string());
            let stderr = String::from_utf8_lossy(&stderr);
            return Err(other(format!(
                "exec: exit status {code}: {}",
                clip(stderr.trim(), MAX_ERR_BODY)
            )));
        }
        if overflow {
            return Err(other("exec: output exceeds 64 KiB"));
        }
        crate::serde_util::require_object(&stdout)
            .and_then(|()| serde_json::from_slice(&stdout).map_err(|e| e.to_string()))
            .map_err(|e| other(format!("exec: bad output: {e}")))
    }
}
