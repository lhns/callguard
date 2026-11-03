//! The embedded labelled eval set used by `callguard eval`.
//!
//! Each line of cases.jsonl is `{"id", "bucket", "request", "expected", "note"}`
//! where `request` is a callguard/request/v1 object and `expected` is the
//! decision the full pipeline should reach. Buckets are described in
//! docs/design.md section 11 and in `evalrun::BUCKETS`.

/// The embedded cases.jsonl (one copy, shared with the Go tree until Phase 5).
pub const CASES: &[u8] = include_bytes!("../../../evals/cases.jsonl");

#[cfg(test)]
mod tests {
    #[test]
    fn cases_are_embedded_with_lf_endings() {
        assert!(super::CASES.len() > 1000);
        assert!(!super::CASES.contains(&b'\r'));
    }
}
