# AWS Marketplace Metering

PZDR's first Marketplace dimension is:

- API identifier: `inference_request`
- Unit: `Request`
- Quantity: `1` per successful billable inference

AWS Marketplace SaaS metering is submitted outside the enclave. The enclave
should produce the signed proof and receipt; the parent control plane should
queue a metering event after the proof has been returned to the customer.

## Flow

1. Customer subscribes through AWS Marketplace.
2. Registration token is exchanged with `ResolveCustomer`.
3. Store `CustomerAWSAccountId`, product code, tenant id, and internal account id.
4. For every billable inference, queue a `MarketplaceUsageEvent`.
5. A parent-side worker batches up to 25 records and calls `BatchMeterUsage`.
6. Persist AWS responses and retry retryable failures.

## Local Helper Crate

`crates/marketplace-metering` builds validated payloads for `BatchMeterUsage`
without taking a runtime dependency on AWS credentials.

The helper deliberately stays out of the enclave. Metering is billing and
control-plane state, not secret inference data.

## Example Payload Shape

```json
{
  "ProductCode": "prod-123",
  "UsageRecords": [
    {
      "CustomerAWSAccountId": "111122223333",
      "Dimension": "inference_request",
      "Quantity": 1,
      "Timestamp": 1779984000,
      "UsageAllocations": [
        {
          "AllocatedUsageQuantity": 1,
          "Tags": [
            { "Key": "tenant_id", "Value": "tenant-a" },
            { "Key": "proof_id", "Value": "proof-abc" },
            { "Key": "receipt_root_hex", "Value": "aa55" }
          ]
        }
      ]
    }
  ]
}
```

## Operational Rules

- Do not meter failed or policy-denied requests until the commercial terms
  explicitly say those are billable.
- Keep idempotency keys stable per request/proof pair.
- Batch no more than 25 records per `BatchMeterUsage` call.
- Store the AWS result for every record.
- Keep proof id and receipt root in metering tags for revenue-to-evidence
  reconciliation.
