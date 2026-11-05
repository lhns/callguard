use super::*;

// ---------------------------------------------------------------------------
// openai

pub(super) struct OpenAi {
    model: String,
    base_url: String,
    key_env: String,
    max_tokens: i64,
    classes: Vec<String>,
    agent: ureq::Agent,
}

impl OpenAi {
    pub(super) fn new(cfg: &policy::Backend) -> Result<OpenAi, BackendError> {
        if cfg.base_url.is_empty() {
            return Err(other(
                "openai backend needs base_url (e.g. http://127.0.0.1:8080/v1)",
            ));
        }
        let base_url = cfg.base_url.trim_end_matches('/').to_owned();
        Ok(OpenAi {
            model: cfg.model.clone(),
            key_env: cfg.api_key_env.clone(),
            max_tokens: max_tokens(cfg),
            classes: cfg.data_classes.clone(),
            agent: http_agent(&base_url)?,
            base_url,
        })
    }
}

#[derive(Serialize)]
pub(super) struct OpenAiBody<'a> {
    model: &'a str,
    messages: [ChatMessage<'a>; 2],
    max_tokens: i64,
    response_format: ResponseFormat<'a>,
}

#[derive(Serialize)]
pub(super) struct ResponseFormat<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    json_schema: JsonSchema<'a>,
}

#[derive(Serialize)]
pub(super) struct JsonSchema<'a> {
    name: &'static str,
    strict: bool,
    schema: Option<&'a RawValue>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct OpenAiResponse {
    #[serde(deserialize_with = "nullable")]
    choices: Vec<OpenAiChoice>,
    #[serde(deserialize_with = "nullable")]
    usage: OpenAiUsage,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct OpenAiChoice {
    #[serde(deserialize_with = "nullable")]
    message: OpenAiMessage,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct OpenAiMessage {
    #[serde(deserialize_with = "nullable")]
    content: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct OpenAiUsage {
    #[serde(deserialize_with = "nullable")]
    prompt_tokens: i64,
    #[serde(deserialize_with = "nullable")]
    completion_tokens: i64,
}

impl Backend for OpenAi {
    fn name(&self) -> String {
        format!("openai:{}", self.model)
    }

    fn data_classes(&self) -> &[String] {
        &self.classes
    }

    fn classify(
        &self,
        req: &ClassifyRequest,
        deadline: Instant,
    ) -> Result<ClassifyResult, BackendError> {
        let body = OpenAiBody {
            model: &self.model,
            messages: [
                ChatMessage {
                    role: "system",
                    content: &req.system,
                },
                ChatMessage {
                    role: "user",
                    content: &req.prompt,
                },
            ],
            max_tokens: self.max_tokens,
            response_format: ResponseFormat {
                kind: "json_schema",
                json_schema: JsonSchema {
                    name: "callguard_verdict",
                    strict: true,
                    schema: req.schema.as_deref(),
                },
            },
        };
        let body = json_text::to_string(&body).map_err(|e| other(e.to_string()))?;
        let auth;
        let mut headers = vec![("content-type", "application/json")];
        if !self.key_env.is_empty() {
            let k = std::env::var(&self.key_env).unwrap_or_default();
            if !k.is_empty() {
                auth = format!("Bearer {k}");
                headers.push(("Authorization", &auth));
            }
        }
        let raw = post_json(
            &self.agent,
            &format!("{}/chat/completions", self.base_url),
            &headers,
            body,
            deadline,
            "openai",
        )?;
        let resp: OpenAiResponse = serde_json::from_slice(&raw)
            .map_err(|e| other(format!("openai: bad response: {e}")))?;
        let first = resp
            .choices
            .first()
            .ok_or_else(|| other("openai: no choices in response"))?;
        let mut res = parse_verdict_json(&first.message.content)
            .map_err(|e| other(format!("openai: {e}")))?;
        res.input_tokens = resp.usage.prompt_tokens;
        res.output_tokens = resp.usage.completion_tokens;
        Ok(res)
    }
}
