# PZDR Gateway Quickstart

Get from zero to a verified signed deletion receipt.

## Local Docker Smoke Check

```bash
git clone https://github.com/vpratab/PZD
cd PZD
docker compose up -d

# Confirm the parent proxy is reachable.
curl http://127.0.0.1:8090/health
```

Local Docker only proves that the parent proxy starts. Full attestation and
inference require a Nitro Enclave running on EC2 because `/v1/attestation` and
`/v1/gateway/inference` are forwarded over vsock to the enclave.

## TypeScript SDK

```bash
npm install @pzdr/gateway-client
```

```typescript
import { PZDRClient } from "@pzdr/gateway-client";

const client = new PZDRClient({ url: "http://localhost:8090" });

const attestation = await client.getAttestation();
console.log("Enclave measurement:", attestation.measurement);

const result = await client.process({
  prompt: "Summarize this clinical encounter: ...",
  processor: "patient_aggregate",
  tenant: "clinic-test-01",
});

console.log("Model response:", result.modelResponse);
console.log("Ledger receipt:", result.receipt);
console.log("Counter:", result.proof.statement.counter);

const valid = await client.verifyProof(
  result.proof,
  attestation.proof_verifier_key_hex,
);
console.log("Proof verifies?", valid);
```

## Production Nitro Bring-Up

```bash
PZDR_VERSION="${PZDR_VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo v0.1.0)}"
(cd eif && PZDR_VERSION="$PZDR_VERSION" ./build-eif.sh)
```

Then launch the resulting EIF on a Nitro-enabled EC2 instance:

```bash
sudo nitro-cli run-enclave \
  --eif-path "eif/out/pzdr-enclave-${PZDR_VERSION}.eif" \
  --memory 2048 \
  --cpu-count 2 \
  --enclave-cid 16
```

Run the parent proxy on the EC2 parent partition with matching CID/port:

```bash
ENCLAVE_CID=16 ENCLAVE_PORT=5000 PROXY_ADDR=0.0.0.0:8090 vsock-parent-proxy
```

## What To Save

Save the `proof` and `receipt` returned by every request. The proof is the
signed statement; the receipt anchors that proof into the Merkle log.

## Troubleshooting

- `channel_decrypt_failed`: refresh `/v1/attestation` and encrypt to the
  returned `channel_public_key_hex`.
- `commitment_mismatch`: recompute `SHA-256(plaintext || salt || context)`.
- `policy_denied`: inspect `proof.statement.policy_decision`.

## Next Steps

- Read `docs/ARCHITECTURE.md` for the deployment shape and trust boundary.
- Read `docs/SECURITY.md` for assumptions, risks, and non-claims.
- Read `docs/openapi.yaml` for the HTTP API.
