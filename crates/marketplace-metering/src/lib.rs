//! AWS Marketplace metering helpers.
//!
//! This crate deliberately does not call AWS. It builds validated, idempotent
//! payloads that an out-of-enclave parent service, Lambda, or cron worker can
//! submit through `BatchMeterUsage`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use thiserror::Error;

pub const INFERENCE_DIMENSION: &str = "inference_request";

#[derive(Debug, Error)]
pub enum MeteringError {
    #[error("missing required field: {0}")]
    Missing(&'static str),
    #[error("quantity must be greater than zero")]
    InvalidQuantity,
    #[error("too many records for BatchMeterUsage: {0}; maximum is 25")]
    TooManyRecords(usize),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketplaceUsageEvent {
    pub product_code: String,
    pub customer_aws_account_id: String,
    pub dimension: String,
    pub quantity: u32,
    pub timestamp_unix_seconds: i64,
    pub tenant_id: String,
    pub request_id: String,
    pub proof_id: String,
    pub receipt_root_hex: String,
    pub idempotency_key: String,
}

impl MarketplaceUsageEvent {
    pub fn new(input: MarketplaceUsageInput) -> Result<Self, MeteringError> {
        require("product_code", &input.product_code)?;
        require("customer_aws_account_id", &input.customer_aws_account_id)?;
        require("dimension", &input.dimension)?;
        require("tenant_id", &input.tenant_id)?;
        require("request_id", &input.request_id)?;
        require("proof_id", &input.proof_id)?;
        require("receipt_root_hex", &input.receipt_root_hex)?;
        if input.quantity == 0 {
            return Err(MeteringError::InvalidQuantity);
        }

        let idempotency_key = stable_idempotency_key(&[
            &input.product_code,
            &input.customer_aws_account_id,
            &input.dimension,
            &input.request_id,
            &input.proof_id,
        ]);

        Ok(Self {
            product_code: input.product_code,
            customer_aws_account_id: input.customer_aws_account_id,
            dimension: input.dimension,
            quantity: input.quantity,
            timestamp_unix_seconds: input.timestamp_unix_seconds,
            tenant_id: input.tenant_id,
            request_id: input.request_id,
            proof_id: input.proof_id,
            receipt_root_hex: input.receipt_root_hex,
            idempotency_key,
        })
    }

    pub fn inference(
        product_code: impl Into<String>,
        customer_aws_account_id: impl Into<String>,
        tenant_id: impl Into<String>,
        request_id: impl Into<String>,
        proof_id: impl Into<String>,
        receipt_root_hex: impl Into<String>,
        timestamp_unix_seconds: i64,
    ) -> Result<Self, MeteringError> {
        Self::new(MarketplaceUsageInput {
            product_code: product_code.into(),
            customer_aws_account_id: customer_aws_account_id.into(),
            dimension: INFERENCE_DIMENSION.to_string(),
            quantity: 1,
            timestamp_unix_seconds,
            tenant_id: tenant_id.into(),
            request_id: request_id.into(),
            proof_id: proof_id.into(),
            receipt_root_hex: receipt_root_hex.into(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct MarketplaceUsageInput {
    pub product_code: String,
    pub customer_aws_account_id: String,
    pub dimension: String,
    pub quantity: u32,
    pub timestamp_unix_seconds: i64,
    pub tenant_id: String,
    pub request_id: String,
    pub proof_id: String,
    pub receipt_root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct BatchMeterUsagePayload {
    pub product_code: String,
    pub usage_records: Vec<UsageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct UsageRecord {
    pub customer_aws_account_id: String,
    pub dimension: String,
    pub quantity: u32,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub usage_allocations: Vec<UsageAllocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct UsageAllocation {
    pub allocated_usage_quantity: u32,
    pub tags: Vec<UsageAllocationTag>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct UsageAllocationTag {
    pub key: String,
    pub value: String,
}

pub fn batch_meter_usage_payload(
    product_code: impl Into<String>,
    events: &[MarketplaceUsageEvent],
) -> Result<BatchMeterUsagePayload, MeteringError> {
    let product_code = product_code.into();
    require("product_code", &product_code)?;
    if events.len() > 25 {
        return Err(MeteringError::TooManyRecords(events.len()));
    }

    let usage_records = events
        .iter()
        .map(|event| UsageRecord {
            customer_aws_account_id: event.customer_aws_account_id.clone(),
            dimension: event.dimension.clone(),
            quantity: event.quantity,
            timestamp: event.timestamp_unix_seconds,
            usage_allocations: vec![UsageAllocation {
                allocated_usage_quantity: event.quantity,
                tags: vec![
                    UsageAllocationTag {
                        key: "tenant_id".to_string(),
                        value: event.tenant_id.clone(),
                    },
                    UsageAllocationTag {
                        key: "proof_id".to_string(),
                        value: event.proof_id.clone(),
                    },
                    UsageAllocationTag {
                        key: "receipt_root_hex".to_string(),
                        value: event.receipt_root_hex.clone(),
                    },
                ],
            }],
        })
        .collect();

    Ok(BatchMeterUsagePayload {
        product_code,
        usage_records,
    })
}

pub fn append_event_jsonl(
    path: impl AsRef<Path>,
    event: &MarketplaceUsageEvent,
) -> Result<(), MeteringError> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, event)?;
    file.write_all(b"\n")?;
    Ok(())
}

pub fn read_events_jsonl(
    path: impl AsRef<Path>,
) -> Result<Vec<MarketplaceUsageEvent>, MeteringError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        events.push(serde_json::from_str(&line)?);
    }
    Ok(events)
}

fn stable_idempotency_key(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn require(field: &'static str, value: &str) -> Result<(), MeteringError> {
    if value.trim().is_empty() {
        Err(MeteringError::Missing(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(request_id: &str) -> MarketplaceUsageEvent {
        MarketplaceUsageEvent::inference(
            "prod-123",
            "111122223333",
            "tenant-a",
            request_id,
            "proof-abc",
            "aa55",
            1_779_984_000,
        )
        .unwrap()
    }

    #[test]
    fn idempotency_key_is_stable() {
        let a = sample_event("req-1");
        let b = sample_event("req-1");
        let c = sample_event("req-2");

        assert_eq!(a.idempotency_key, b.idempotency_key);
        assert_ne!(a.idempotency_key, c.idempotency_key);
    }

    #[test]
    fn builds_batch_meter_usage_payload() {
        let event = sample_event("req-1");
        let payload = batch_meter_usage_payload("prod-123", &[event]).unwrap();

        assert_eq!(payload.product_code, "prod-123");
        assert_eq!(payload.usage_records.len(), 1);
        assert_eq!(
            payload.usage_records[0].customer_aws_account_id,
            "111122223333"
        );
        assert_eq!(payload.usage_records[0].dimension, INFERENCE_DIMENSION);
        assert_eq!(payload.usage_records[0].quantity, 1);
        assert_eq!(
            payload.usage_records[0].usage_allocations[0].tags[0].key,
            "tenant_id"
        );
    }

    #[test]
    fn rejects_large_batches() {
        let events = (0..26)
            .map(|i| sample_event(&format!("req-{i}")))
            .collect::<Vec<_>>();

        let err = batch_meter_usage_payload("prod-123", &events).unwrap_err();
        assert!(matches!(err, MeteringError::TooManyRecords(26)));
    }

    #[test]
    fn idempotency_key_changes_when_any_field_changes() {
        // Changing any non-cosmetic field must produce a different idempotency
        // key, otherwise BatchMeterUsage will reject the record as a duplicate
        // of a previously sent one (DuplicateRecordException).
        let base = sample_event("req-1");

        let tenant = MarketplaceUsageEvent::inference(
            "prod-123",
            "111122223333",
            "tenant-DIFFERENT",
            "req-1",
            "proof-abc",
            "aa55",
            1_779_984_000,
        )
        .unwrap();
        assert_ne!(base.idempotency_key, tenant.idempotency_key);

        let product = MarketplaceUsageEvent::inference(
            "prod-DIFFERENT",
            "111122223333",
            "tenant-a",
            "req-1",
            "proof-abc",
            "aa55",
            1_779_984_000,
        )
        .unwrap();
        assert_ne!(base.idempotency_key, product.idempotency_key);

        let customer = MarketplaceUsageEvent::inference(
            "prod-123",
            "999988887777",
            "tenant-a",
            "req-1",
            "proof-abc",
            "aa55",
            1_779_984_000,
        )
        .unwrap();
        assert_ne!(base.idempotency_key, customer.idempotency_key);

        let proof = MarketplaceUsageEvent::inference(
            "prod-123",
            "111122223333",
            "tenant-a",
            "req-1",
            "proof-XYZ",
            "aa55",
            1_779_984_000,
        )
        .unwrap();
        assert_ne!(base.idempotency_key, proof.idempotency_key);
    }
}
