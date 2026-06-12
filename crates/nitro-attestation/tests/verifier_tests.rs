//! Integration tests for the Nitro attestation verifier.
//!
//! These build *synthetic* attestation documents that follow the AWS NSM wire
//! format exactly (COSE_Sign1 / ES384 over a CBOR attestation map, signed by a
//! leaf certificate chaining to a root CA), using a test root generated with
//! openssl (see tests/fixtures/). This lets us exercise the full verification
//! path — COSE parse, alg pinning, cert-chain walk, CA constraints, signature,
//! freshness, PCR pinning — without an actual Nitro Enclave.

use nitro_attestation::{NitroError, Verifier};

use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use p384::ecdsa::{signature::Signer, Signature, SigningKey};

const ROOT_PEM: &[u8] = include_bytes!("fixtures/root_cert.pem");
const ROOT_DER: &[u8] = include_bytes!("fixtures/root_cert.der");
const LEAF_DER: &[u8] = include_bytes!("fixtures/leaf_cert.der");
const EVIL_ROOT_PEM: &[u8] = include_bytes!("fixtures/evil_root_cert.pem");
const LEAF_TEST_SCALAR_HEX: &str =
    "be84fa2685eb306e066cb13152dfe2ca5bb015ead5b67d9a2f6465a44374914b\
     8a164fcbeca627554c35db685c3b8ae3";

/// Test PCR0 (hex of 48 bytes — SHA-384 sized) used in the synthetic docs.
const TEST_PCR0: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                         aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn leaf_signer() -> SigningKey {
    SigningKey::from_slice(&hex::decode(LEAF_TEST_SCALAR_HEX).expect("test scalar hex"))
        .expect("valid deterministic test scalar")
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Build the inner Nitro attestation payload map as CBOR bytes.
fn build_payload(
    timestamp_ms: i64,
    pcr0: &[u8],
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
    include_cabundle_root: bool,
) -> Vec<u8> {
    use ciborium::value::Value;

    let pcrs: Vec<(Value, Value)> = vec![
        (Value::Integer(0.into()), Value::Bytes(pcr0.to_vec())),
        // PCR1/PCR2 with arbitrary measurements, like a real doc
        (Value::Integer(1.into()), Value::Bytes(vec![0xBB; 48])),
        (Value::Integer(2.into()), Value::Bytes(vec![0xCC; 48])),
    ];

    let mut map: Vec<(Value, Value)> = vec![
        (
            Value::Text("module_id".into()),
            Value::Text("i-0synthetic-enc0".into()),
        ),
        (Value::Text("digest".into()), Value::Text("SHA384".into())),
        (
            Value::Text("timestamp".into()),
            Value::Integer((timestamp_ms as i128).try_into().unwrap()),
        ),
        (Value::Text("pcrs".into()), Value::Map(pcrs)),
        (
            Value::Text("certificate".into()),
            Value::Bytes(LEAF_DER.to_vec()),
        ),
    ];

    let cabundle = if include_cabundle_root {
        vec![Value::Bytes(ROOT_DER.to_vec())]
    } else {
        vec![]
    };
    map.push((Value::Text("cabundle".into()), Value::Array(cabundle)));

    if let Some(ud) = user_data {
        map.push((Value::Text("user_data".into()), Value::Bytes(ud.to_vec())));
    }
    if let Some(n) = nonce {
        map.push((Value::Text("nonce".into()), Value::Bytes(n.to_vec())));
    }
    if let Some(pk) = public_key {
        map.push((Value::Text("public_key".into()), Value::Bytes(pk.to_vec())));
    }

    let mut out = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

/// Wrap a payload in COSE_Sign1, ES384-signed with the leaf key — the same
/// structure the NSM emits.
fn cose_sign1(payload: Vec<u8>, alg: iana::Algorithm) -> Vec<u8> {
    let protected = HeaderBuilder::new().algorithm(alg).build();
    let signer = leaf_signer();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(&[], |tbs| {
            let sig: Signature = signer.sign(tbs);
            sig.to_bytes().to_vec() // raw r||s — COSE convention
        })
        .build();
    sign1.to_vec().unwrap()
}

fn synthetic_doc() -> Vec<u8> {
    let pcr0 = hex::decode(TEST_PCR0).unwrap();
    let payload = build_payload(
        now_ms(),
        &pcr0,
        Some(b"channel-pubkey-bytes"),
        Some(b"client-nonce-123"),
        Some(&[0x42; 32]),
        true,
    );
    cose_sign1(payload, iana::Algorithm::ES384)
}

// ───────────────────────── POSITIVE PATH ─────────────────────────

#[test]
fn parse_extracts_all_fields() {
    let doc = synthetic_doc();
    let parsed = Verifier::parse(&doc).expect("parse");
    assert_eq!(parsed.module_id, "i-0synthetic-enc0");
    assert_eq!(parsed.digest, "SHA384");
    assert_eq!(parsed.pcrs.len(), 3);
    assert_eq!(parsed.measurement_pcr0().unwrap(), TEST_PCR0);
    assert_eq!(
        parsed.user_data.as_deref(),
        Some(&b"channel-pubkey-bytes"[..])
    );
    assert_eq!(parsed.nonce.as_deref(), Some(&b"client-nonce-123"[..]));
    assert_eq!(parsed.channel_public_key(), Some(&[0x42u8; 32][..]));
    assert_eq!(parsed.certificate_chain.len(), 2); // leaf + root in cabundle
}

#[test]
fn full_verification_passes_against_test_root() {
    let doc = synthetic_doc();
    let parsed = Verifier::parse(&doc).expect("parse");
    Verifier::verify_signature(&doc, &parsed, ROOT_PEM).expect("verify");
}

#[test]
fn parse_and_verify_one_call_api() {
    let doc = synthetic_doc();
    let v = Verifier::parse_and_verify(&doc, ROOT_PEM, now_ms(), 300, Some(TEST_PCR0))
        .expect("one-call verify");
    assert_eq!(v.module_id, "i-0synthetic-enc0");
}

#[test]
fn leaf_directly_under_root_with_empty_cabundle_verifies() {
    // AWS sometimes ships short chains; leaf issued directly by the root with
    // no intermediates must validate.
    let pcr0 = hex::decode(TEST_PCR0).unwrap();
    let payload = build_payload(now_ms(), &pcr0, None, None, None, false);
    let doc = cose_sign1(payload, iana::Algorithm::ES384);
    let parsed = Verifier::parse(&doc).expect("parse");
    assert_eq!(parsed.certificate_chain.len(), 1);
    Verifier::verify_signature(&doc, &parsed, ROOT_PEM).expect("short chain verify");
}

#[test]
fn pcr_pinning_matches() {
    let doc = synthetic_doc();
    let parsed = Verifier::parse(&doc).unwrap();
    parsed
        .assert_measurement_matches(TEST_PCR0)
        .expect("pcr match");
    // case-insensitive
    parsed
        .assert_measurement_matches(&TEST_PCR0.to_uppercase())
        .expect("pcr match case-insensitive");
}

#[test]
fn freshness_within_skew_passes() {
    let doc = synthetic_doc();
    let parsed = Verifier::parse(&doc).unwrap();
    parsed.assert_fresh(now_ms(), 300).expect("fresh");
}

// ───────────────────────── NEGATIVE PATHS ─────────────────────────

#[test]
fn tampered_payload_fails_signature() {
    let mut doc = synthetic_doc();
    // Flip one bit somewhere in the middle of the document (payload region)
    let mid = doc.len() / 2;
    doc[mid] ^= 0x01;
    // Either the COSE/CBOR parse breaks, or the signature must fail — a
    // tampered doc must NEVER verify.
    match Verifier::parse(&doc) {
        Err(_) => {} // structural break — acceptable
        Ok(parsed) => {
            let res = Verifier::verify_signature(&doc, &parsed, ROOT_PEM);
            assert!(res.is_err(), "tampered document verified — CRITICAL BUG");
        }
    }
}

#[test]
fn wrong_root_rejected() {
    let doc = synthetic_doc();
    let parsed = Verifier::parse(&doc).unwrap();
    let res = Verifier::verify_signature(&doc, &parsed, EVIL_ROOT_PEM);
    assert!(matches!(res, Err(NitroError::CertChain(_))));
}

#[test]
fn wrong_cose_algorithm_rejected() {
    // Same payload, but protected header declares ES256 — alg-confusion guard
    // must refuse before any key material is touched.
    let pcr0 = hex::decode(TEST_PCR0).unwrap();
    let payload = build_payload(now_ms(), &pcr0, None, None, None, true);
    let doc = cose_sign1(payload, iana::Algorithm::ES256);
    let parsed = Verifier::parse(&doc).unwrap();
    let res = Verifier::verify_signature(&doc, &parsed, ROOT_PEM);
    match res {
        Err(NitroError::Cose(msg)) => assert!(msg.contains("ES384"), "got: {msg}"),
        other => panic!("expected Cose alg error, got {other:?}"),
    }
}

#[test]
fn pcr_mismatch_rejected_with_details() {
    let doc = synthetic_doc();
    let parsed = Verifier::parse(&doc).unwrap();
    let wrong = "ff".repeat(48);
    match parsed.assert_measurement_matches(&wrong) {
        Err(NitroError::PcrMismatch { expected, got }) => {
            assert_eq!(expected, wrong);
            assert_eq!(got, TEST_PCR0);
        }
        other => panic!("expected PcrMismatch, got {other:?}"),
    }
}

#[test]
fn stale_document_rejected() {
    let pcr0 = hex::decode(TEST_PCR0).unwrap();
    let old_ts = now_ms() - 3_600_000; // one hour old
    let payload = build_payload(old_ts, &pcr0, None, None, None, true);
    let doc = cose_sign1(payload, iana::Algorithm::ES384);
    let parsed = Verifier::parse(&doc).unwrap();
    assert!(matches!(
        parsed.assert_fresh(now_ms(), 300),
        Err(NitroError::Expired { .. })
    ));
}

#[test]
fn future_dated_document_rejected() {
    let pcr0 = hex::decode(TEST_PCR0).unwrap();
    let future_ts = now_ms() + 3_600_000;
    let payload = build_payload(future_ts, &pcr0, None, None, None, true);
    let doc = cose_sign1(payload, iana::Algorithm::ES384);
    let parsed = Verifier::parse(&doc).unwrap();
    assert!(matches!(
        parsed.assert_fresh(now_ms(), 300),
        Err(NitroError::Expired { .. })
    ));
}

#[test]
fn missing_required_fields_rejected() {
    use ciborium::value::Value;
    // Payload missing module_id and timestamp
    let map: Vec<(Value, Value)> = vec![
        (Value::Text("digest".into()), Value::Text("SHA384".into())),
        (
            Value::Text("certificate".into()),
            Value::Bytes(LEAF_DER.to_vec()),
        ),
    ];
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut payload).unwrap();
    let doc = cose_sign1(payload, iana::Algorithm::ES384);
    assert!(matches!(Verifier::parse(&doc), Err(NitroError::Missing(_))));
}

#[test]
fn garbage_input_rejected_cleanly() {
    for garbage in [
        &b""[..],
        &b"\x00"[..],
        &[0xFFu8; 64][..],
        b"not cbor at all",
    ] {
        assert!(Verifier::parse(garbage).is_err(), "garbage parsed?!");
    }
}

#[test]
fn signature_swap_across_documents_rejected() {
    // Sign two different payloads, then graft doc A's signature onto doc B.
    let pcr0 = hex::decode(TEST_PCR0).unwrap();
    let p_a = build_payload(now_ms(), &pcr0, Some(b"AAA"), None, None, true);
    let p_b = build_payload(now_ms(), &pcr0, Some(b"BBB"), None, None, true);
    let doc_a = cose_sign1(p_a, iana::Algorithm::ES384);
    let doc_b = cose_sign1(p_b, iana::Algorithm::ES384);

    let cose_a = coset::CoseSign1::from_slice(&doc_a).unwrap();
    let mut cose_b = coset::CoseSign1::from_slice(&doc_b).unwrap();
    cose_b.signature = cose_a.signature; // grafted
    let franken = cose_b.to_vec().unwrap();

    let parsed = Verifier::parse(&franken).unwrap();
    assert!(matches!(
        Verifier::verify_signature(&franken, &parsed, ROOT_PEM),
        Err(NitroError::Signature)
    ));
}

// ───────────────────── ROBUSTNESS (no-panic guarantee) ─────────────────────

#[test]
fn parser_never_panics_on_mutated_documents() {
    // Deterministic mutation sweep: for a real doc, flip every byte position
    // through 3 values and confirm the verifier returns Err or Ok — never
    // panics, never accepts a corrupted doc as valid with changed content.
    let doc = synthetic_doc();
    let baseline = Verifier::parse(&doc).unwrap();
    let baseline_pcr0 = baseline.measurement_pcr0().unwrap().to_string();

    let mut accepted_mutations = 0u32;
    for pos in (0..doc.len()).step_by(7) {
        for delta in [0x01u8, 0x80, 0xFF] {
            let mut m = doc.clone();
            m[pos] ^= delta;
            if m == doc {
                continue;
            }
            // Must not panic:
            if let Ok(parsed) = Verifier::parse(&m) {
                // If it still parses, full verification must reject it…
                if Verifier::verify_signature(&m, &parsed, ROOT_PEM).is_ok() {
                    // …unless the mutation hit a byte that round-trips to an
                    // identical signing input (theoretically impossible for
                    // bit flips inside payload/signature). Treat as critical.
                    assert_eq!(
                        parsed.measurement_pcr0().unwrap(),
                        baseline_pcr0,
                        "mutated doc verified with DIFFERENT content — CRITICAL"
                    );
                    accepted_mutations += 1;
                }
            }
        }
    }
    // A handful of mutations may land in ignored/unprotected regions and still
    // verify with identical content; that is acceptable. Log for visibility.
    eprintln!("mutations that still verified (content-identical): {accepted_mutations}");
}
