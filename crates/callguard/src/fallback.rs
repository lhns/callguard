//! The verdict for a call callguard could not evaluate (fallback.go).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::schema::{Decision, LAYER_FALLBACK, Request, VERDICT_SCHEMA, Verdict};

/// A fresh 32-hex-digit verdict id (engine.go's `newID`; it lives here because
/// the fallback needs it and must never fail). Falls back to a clock-and-counter
/// id if the system random source is unavailable.
pub fn new_id() -> String {
    let mut b = [0u8; 16];
    if getrandom::fill(&mut b).is_err() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        b[..8].copy_from_slice(&(nanos as u64).to_le_bytes());
        b[8..].copy_from_slice(&COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    }
    hex::encode(b)
}

/// Ask, or deny when the request is unattended; enforced, layer "fallback".
/// `cause` goes into the reason. Safe to call with no or a partial request.
pub fn fallback_verdict(req: Option<&Request>, cause: &str) -> Verdict {
    let mut v = Verdict {
        schema: VERDICT_SCHEMA.into(),
        v: 1,
        id: new_id(),
        decision: Decision::Ask,
        enforced: true,
        reason: format!(
            "callguard could not evaluate this call: {cause}. A human should confirm it."
        ),
        layer: LAYER_FALLBACK.into(),
        rule: String::new(),
        confidence: 0.0,
        policy_rev: String::new(),
        backend: String::new(),
        latency_ms: 0,
        warnings: Vec::new(),
    };
    if req.is_some_and(|r| r.unattended) {
        v.decision = Decision::Deny;
        v.reason = format!(
            "callguard could not evaluate this call: {cause}. A human must approve it; \
             ask the user to approve it or add a policy rule."
        );
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asks_by_default_and_denies_when_unattended() {
        let v = fallback_verdict(None, "bad thing");
        assert_eq!(v.decision, Decision::Ask);
        assert!(v.enforced);
        assert_eq!(v.layer, "fallback");
        assert_eq!(v.schema, VERDICT_SCHEMA);
        assert_eq!(v.v, 1);
        assert!(v.reason.contains("bad thing"));

        let unattended = Request {
            unattended: true,
            ..Default::default()
        };
        let v = fallback_verdict(Some(&unattended), "x");
        assert_eq!(v.decision, Decision::Deny);
        assert!(v.reason.contains("A human must approve it"));
        let attended = Request::default();
        assert_eq!(
            fallback_verdict(Some(&attended), "x").decision,
            Decision::Ask
        );
    }

    #[test]
    fn ids_are_fresh_hex() {
        let (a, b) = (fallback_verdict(None, "x"), fallback_verdict(None, "x"));
        assert_ne!(a.id, b.id);
        assert_eq!(a.id.len(), 32);
        assert!(a.id.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
