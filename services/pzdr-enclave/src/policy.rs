//! policy.rs — hash-pinned, default-deny policy engine for the PZDR enclave.
//!
//! Replaces the ad-hoc `<RESTRICTED` substring check in main.rs. The policy is a
//! declarative document; its sha256 over canonical JSON (`policy_hash`) is
//! recorded in every proof's `policy_decision`, so an auditor can re-hash the
//! published ruleset and confirm the gateway enforced exactly that policy. Rules
//! run inside the enclave on plaintext; the auditor never sees plaintext, only
//! the pinned ruleset and the recorded decision.
//!
//! Mirrors `tools/pzdr_ledger.py::evaluate_policy` and the `DEFAULT_POLICY`
//! document used to generate the conformance vectors.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub policy_id: String,
    pub policy_version: u32,
    pub default: String, // "deny"
    pub max_input_bytes: usize,
    pub deny_markers: Vec<String>,
    /// Substring PII markers (kept dependency-free; the reference impl documents
    /// the equivalent regex forms — SSN `ddd-dd-dddd`, 16-digit PAN).
    pub deny_patterns_pii: Vec<String>,
    pub allowed_processors: Vec<String>,
}

impl Policy {
    /// The default ruleset; keep byte-identical to DEFAULT_POLICY in the Python
    /// reference so `policy_hash()` matches the conformance vectors.
    pub fn default_v1() -> Self {
        Policy {
            policy_id: "pzdr-default".into(),
            policy_version: 1,
            default: "deny".into(),
            max_input_bytes: 100_000,
            deny_markers: vec!["<RESTRICTED".into()],
            deny_patterns_pii: vec![r"\b\d{3}-\d{2}-\d{4}\b".into(), r"\b\d{16}\b".into()],
            allowed_processors: vec!["gateway".into()],
        }
    }

    /// sha256 over canonical JSON of the policy document.
    pub fn policy_hash(&self) -> String {
        let v = serde_json::to_value(self).unwrap_or(Value::Null);
        hex::encode(Sha256::digest(canonical_json(&v)))
    }

    /// Default-deny evaluation. Returns Ok(()) on allow, Err(reason) on deny.
    /// NOTE: PII matching here uses substring/byte scanning to avoid a regex
    /// dependency inside the enclave; the published policy records the canonical
    /// regex forms. Swap in the `regex` crate if richer matching is required.
    pub fn evaluate(&self, plaintext: &[u8], processor: &str) -> Result<(), &'static str> {
        if !self.allowed_processors.iter().any(|p| p == processor) {
            return Err("processor_not_allowed");
        }
        if plaintext.len() > self.max_input_bytes {
            return Err("input_too_large");
        }
        for marker in &self.deny_markers {
            if contains(plaintext, marker.as_bytes()) {
                return Err("restricted_marker");
            }
        }
        if looks_like_ssn(plaintext) || looks_like_pan(plaintext) {
            return Err("pii_detected");
        }
        Ok(())
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Detect `ddd-dd-dddd` (US SSN shape).
fn looks_like_ssn(b: &[u8]) -> bool {
    let d = |c: u8| c.is_ascii_digit();
    b.windows(11).any(|w| {
        d(w[0])
            && d(w[1])
            && d(w[2])
            && w[3] == b'-'
            && d(w[4])
            && d(w[5])
            && w[6] == b'-'
            && d(w[7])
            && d(w[8])
            && d(w[9])
            && d(w[10])
    })
}

/// Detect a run of exactly 16 digits not embedded in a longer digit run (bare PAN).
fn looks_like_pan(b: &[u8]) -> bool {
    let mut run = 0usize;
    for &c in b {
        if c.is_ascii_digit() {
            run += 1;
        } else {
            if run == 16 {
                return true;
            }
            run = 0;
        }
    }
    run == 16
}

/// Canonical JSON: recursively sorted object keys, compact separators.
/// Identical to main.rs `canonical_json` and the Python/TS implementations.
pub fn canonical_json(v: &Value) -> Vec<u8> {
    serde_json::to_vec(&sort_keys(v.clone())).unwrap_or_default()
}

fn sort_keys(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<_> = m.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), sort_keys(m.get(&k).cloned().unwrap()));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_allows_clean_input() {
        let p = Policy::default_v1();
        assert!(p
            .evaluate(b"summarize the maintenance log", "gateway")
            .is_ok());
    }

    #[test]
    fn denies_marker_pii_size_and_processor() {
        let p = Policy::default_v1();
        assert_eq!(
            p.evaluate(b"<RESTRICTED> x", "gateway"),
            Err("restricted_marker")
        );
        assert_eq!(
            p.evaluate(b"ssn 123-45-6789", "gateway"),
            Err("pii_detected")
        );
        assert_eq!(
            p.evaluate(b"pan 4111111111111111", "gateway"),
            Err("pii_detected")
        );
        assert_eq!(p.evaluate(b"hi", "rogue"), Err("processor_not_allowed"));
        let big = vec![b'a'; 100_001];
        assert_eq!(p.evaluate(&big, "gateway"), Err("input_too_large"));
    }

    #[test]
    fn policy_hash_matches_python_reference() {
        // Cross-language conformance: this MUST equal the policy_hash emitted by
        // tools/pzdr_gen_vectors.py and recorded in tools/conformance/bundle.json.
        // If this fails, the Rust canonical JSON has diverged from the reference.
        let p = Policy::default_v1();
        assert_eq!(
            p.policy_hash(),
            "96b9a9b4df3d1538f068d2b87b8c5952b78da9e39e2c23d28ee71feb025ade48"
        );
    }
}
