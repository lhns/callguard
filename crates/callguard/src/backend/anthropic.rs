use super::*;

// ---------------------------------------------------------------------------
// anthropic

pub(super) const ANTHROPIC_VERSION: &str = "2026-10-21";
pub(super) const ANTHROPIC_DEFAULT_MODEL: &str = "claude-haiku-5-5";
pub(super) const ANTHROPIC_DEFAULT_URL: &str = "https://api.anthropic.com";

pub(super) struct Anthropic {
    model: String,
    base_url: String,
    key_env: String,
    max_tokens: i64,
    classes: Vec<String>,
    agent: ureq::Agent,
}

impl Anthropic {
    pub(super) fn new(cfg: &policy::Backend) -> Result<Anthropic, BackendError> {
        let or = |v: &str, d: &str| {
            if v.is_empty() {
                d.to_owned()
            } else {
                v.to_owned()
            }
        };
        let base_url = or(cfg.base_url.trim_end_matches('/'), ANTHROPIC_DEFAULT_URL);
        Ok(Anthropic {
            model: or(&cfg.model, ANTHROPIC_DEFAULT_MODEL),
            key_env: or(&cfg.api_key_env, "ANTHROPIC_API_KEY"),
            max_tokens: max_tokens(cfg),
            classes: cfg.data_classes.clone(),
            agent: http_agent(&base_url)?,
            base_url,
        })
    }
}

#[derive(Serialize)]
pub(super) struct AnthropicBody<'a> {
    model: &'a str,
    max_tokens: i64,
    system: [SystemBlock<'a>; 1],
    messages: [ChatMessage<'a>; 1],
    output_config: OutputConfig<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<Thinking>,
}

#[derive(Serialize)]
pub(super) struct SystemBlock<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    text: &'a str,
    cache_control: CacheControl,
}

#[derive(Serialize)]
pub(super) struct CacheControl {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
pub(super) struct ChatMessage<'a> {
    pub(super) role: &'static str,
    pub(super) content: &'a str,
}

#[derive(Serialize)]
pub(super) struct OutputConfig<'a> {
    format: OutputFormat<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<&'static str>,
}

#[derive(Serialize)]
pub(super) struct OutputFormat<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    /// Raw, so the property order of the schema (reason first) survives.
    schema: Option<&'a RawValue>,
}

#[derive(Serialize)]
pub(super) struct Thinking {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct AnthropicResponse {
    #[serde(deserialize_with = "nullable")]
    content: Vec<ContentBlock>,
    #[serde(deserialize_with = "nullable")]
    stop_reason: String,
    #[serde(deserialize_with = "nullable")]
    usage: AnthropicUsage,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct ContentBlock {
    #[serde(rename = "type", deserialize_with = "nullable")]
    kind: String,
    #[serde(deserialize_with = "nullable")]
    text: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct AnthropicUsage {
    #[serde(deserialize_with = "nullable")]
    input_tokens: i64,
    #[serde(deserialize_with = "nullable")]
    output_tokens: i64,
    #[serde(rename = "cache_read_input_tokens", deserialize_with = "nullable")]
    cache_read: i64,
    #[serde(rename = "cache_creation_input_tokens", deserialize_with = "nullable")]
    cache_write: i64,
}

impl Backend for Anthropic {
    fn name(&self) -> String {
        format!("anthropic:{}", self.model)
    }

    fn data_classes(&self) -> &[String] {
        &self.classes
    }

    fn classify(
        &self,
        req: &ClassifyRequest,
        deadline: Instant,
    ) -> Result<ClassifyResult, BackendError> {
        let key = std::env::var(&self.key_env).unwrap_or_default();
        if key.is_empty() {
            return Err(other(format!(
                "anthropic: environment variable {} is not set",
                self.key_env
            )));
        }
        // Haiku 5.5 takes disabled thinking and effort "low". Sonnet 5.5 and
        // Opus 5.5 reject disabled thinking, and Haiku 4.5 rejects effort, so
        // other models get neither and run with their defaults. No sampling
        // parameters (temperature, top_p, top_k): this API version answers 400.
        let haiku5 = self.model.starts_with("claude-haiku-5");
        let body = AnthropicBody {
            model: &self.model,
            max_tokens: self.max_tokens,
            system: [SystemBlock {
                kind: "text",
                text: &req.system,
                cache_control: CacheControl { kind: "ephemeral" },
            }],
            messages: [ChatMessage {
                role: "user",
                content: &req.prompt,
            }],
            output_config: OutputConfig {
                format: OutputFormat {
                    kind: "json_schema",
                    schema: req.schema.as_deref(),
                },
                effort: haiku5.then_some("low"),
            },
            thinking: haiku5.then_some(Thinking { kind: "disabled" }),
        };
        let body = json_text::to_string(&body).map_err(|e| other(e.to_string()))?;
        let raw = post_json(
            &self.agent,
            &format!("{}/v1/messages", self.base_url),
            &[
                ("x-api-key", &key),
                ("anthropic-version", ANTHROPIC_VERSION),
                ("content-type", "application/json"),
            ],
            body,
            deadline,
            "anthropic",
        )?;
        let resp: AnthropicResponse = serde_json::from_slice(&raw)
            .map_err(|e| other(format!("anthropic: bad response: {e}")))?;
        if resp.stop_reason == "refusal" || resp.stop_reason == "max_tokens" {
            return Err(other(format!(
                "anthropic: stop_reason {}",
                resp.stop_reason
            )));
        }
        for c in &resp.content {
            if c.kind != "text" {
                continue;
            }
            let mut res =
                parse_verdict_json(&c.text).map_err(|e| other(format!("anthropic: {e}")))?;
            res.input_tokens = resp.usage.input_tokens;
            res.output_tokens = resp.usage.output_tokens;
            res.cache_read_tokens = resp.usage.cache_read;
            res.cache_write_tokens = resp.usage.cache_write;
            return Ok(res);
        }
        Err(other("anthropic: no text block in response"))
    }
}
