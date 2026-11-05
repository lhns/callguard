use super::*;

/// Decodes the model's {decision, confidence, rule, reason} text, tolerating a
/// surrounding code fence.
pub(super) fn parse_verdict_json(text: &str) -> Result<ClassifyResult, BackendError> {
    let mut text = text.trim();
    if let Some(rest) = text.strip_prefix("```") {
        text = rest;
        if let Some(i) = text.find('\n') {
            text = &text[i + 1..];
        }
        let t = text.trim();
        text = t.strip_suffix("```").unwrap_or(t).trim();
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Answer {
        #[serde(deserialize_with = "nullable")]
        decision: String,
        #[serde(deserialize_with = "nullable")]
        confidence: f64,
        #[serde(deserialize_with = "nullable")]
        rule: String,
        #[serde(deserialize_with = "nullable")]
        reason: String,
    }
    crate::serde_util::require_object(text.as_bytes())
        .map_err(|e| other(format!("model output is not the expected JSON: {e}")))?;
    let v: Answer = serde_json::from_str(text)
        .map_err(|e| other(format!("model output is not the expected JSON: {e}")))?;
    Ok(ClassifyResult {
        label: v.decision,
        confidence: v.confidence,
        rule: v.rule,
        reason: v.reason,
        ..Default::default()
    })
}
