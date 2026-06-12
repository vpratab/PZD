import { X509Certificate, verify as verifySignature } from "node:crypto";
import cbor from "cbor";

const { decodeFirstSync, encodeCanonical } = cbor;

export const AWS_NITRO_ROOT_PEM_COMMERCIAL = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

export interface AttestationEnvelope {
  nitro_attestation_b64: string;
  measurement: string;
  channel_public_key_hex: string;
  proof_verifier_key_hex: string;
  binding_format?: string;
}

export interface NitroVerificationOptions {
  expectedPcr0: string;
  awsRootPem?: string;
  maxAgeSeconds?: number;
  now?: Date;
}

export interface VerifiedNitroDocument {
  measurement: string;
  timestampMs: number;
  channelPublicKeyHex: string;
  proofVerifierKeyHex: string;
}

type CborMap = Map<unknown, unknown> | Record<string, unknown>;

function mapGet(map: CborMap, key: string | number): unknown {
  if (map instanceof Map) return map.get(key);
  return map[String(key)];
}

function bytes(value: unknown, label: string): Uint8Array<ArrayBuffer> {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new Error(`Nitro attestation ${label} is not a byte string`);
  }
  return Uint8Array.from(value);
}

function certIsValid(cert: X509Certificate, now: Date): boolean {
  return now >= new Date(cert.validFrom) && now <= new Date(cert.validTo);
}

function validateCertificatePath(
  leafDer: Uint8Array<ArrayBuffer>,
  caBundle: Uint8Array<ArrayBuffer>[],
  rootPem: string,
  now: Date,
): X509Certificate {
  const pinnedRoot = new X509Certificate(rootPem);
  const supplied = caBundle.map((der) => new X509Certificate(der));
  const rootHex = pinnedRoot.raw.toString("hex");
  const rootIndex = supplied.findIndex((cert) => cert.raw.toString("hex") === rootHex);
  if (rootIndex < 0) throw new Error("Nitro certificate bundle is not rooted in the pinned AWS CA");

  const pool = supplied.slice();
  const chain = [new X509Certificate(leafDer)];
  while (chain[chain.length - 1].raw.toString("hex") !== rootHex) {
    const child = chain[chain.length - 1];
    const issuerIndex = pool.findIndex(
      (candidate) => child.issuer === candidate.subject && child.verify(candidate.publicKey),
    );
    if (issuerIndex < 0) throw new Error("Nitro certificate path signature validation failed");
    chain.push(pool.splice(issuerIndex, 1)[0]);
  }

  for (let i = 0; i < chain.length; i += 1) {
    if (!certIsValid(chain[i], now)) throw new Error("Nitro certificate is outside its validity window");
    if (i > 0 && !chain[i].ca) throw new Error("Nitro issuer certificate is not a CA");
  }
  if (!pinnedRoot.verify(pinnedRoot.publicKey)) {
    throw new Error("Pinned AWS Nitro root is not self-signed");
  }
  return chain[0];
}

export function verifyNitroAttestation(
  attestation: AttestationEnvelope,
  options: NitroVerificationOptions,
): VerifiedNitroDocument {
  if (!/^[0-9a-fA-F]{96}$/.test(options.expectedPcr0)) {
    throw new Error("expectedPcr0 must be a 48-byte hexadecimal measurement");
  }
  const raw = Uint8Array.from(Buffer.from(attestation.nitro_attestation_b64, "base64"));
  const decoded = decodeFirstSync(raw) as unknown;
  const cose = (
    typeof decoded === "object"
    && decoded !== null
    && "value" in decoded
  ) ? (decoded as { value: unknown }).value : decoded;
  if (!Array.isArray(cose) || cose.length !== 4) throw new Error("Invalid COSE_Sign1 envelope");

  const protectedBytes = bytes(cose[0], "protected header");
  const protectedMap = decodeFirstSync(protectedBytes) as CborMap;
  if (mapGet(protectedMap, 1) !== -35) throw new Error("Nitro COSE algorithm is not ES384");

  const payloadBytes = bytes(cose[2], "payload");
  const signature = bytes(cose[3], "signature");
  if (signature.length !== 96) throw new Error("Nitro ES384 signature must be 96 bytes");
  const payload = decodeFirstSync(payloadBytes) as CborMap;
  if (mapGet(payload, "digest") !== "SHA384") {
    throw new Error("Nitro attestation digest is not SHA384");
  }

  const now = options.now ?? new Date();
  const leaf = validateCertificatePath(
    bytes(mapGet(payload, "certificate"), "certificate"),
    (mapGet(payload, "cabundle") as unknown[]).map((item) => bytes(item, "CA certificate")),
    options.awsRootPem ?? AWS_NITRO_ROOT_PEM_COMMERCIAL,
    now,
  );
  const sigStructure = Uint8Array.from(encodeCanonical([
    "Signature1",
    Buffer.from(protectedBytes),
    Buffer.alloc(0),
    Buffer.from(payloadBytes),
  ]));
  if (!verifySignature(
    "sha384",
    sigStructure,
    { key: leaf.publicKey, dsaEncoding: "ieee-p1363" },
    signature,
  )) {
    throw new Error("Nitro COSE signature validation failed");
  }

  const timestampMs = Number(mapGet(payload, "timestamp"));
  if (!Number.isSafeInteger(timestampMs)) throw new Error("Invalid Nitro attestation timestamp");
  const maxAgeMs = (options.maxAgeSeconds ?? 300) * 1000;
  if (Math.abs(now.getTime() - timestampMs) > maxAgeMs) {
    throw new Error("Nitro attestation is stale or from the future");
  }

  const pcrs = mapGet(payload, "pcrs") as CborMap;
  const pcr0 = bytes(mapGet(pcrs, 0), "PCR0");
  if (pcr0.length !== 48) throw new Error("Nitro PCR0 must be 48 bytes");
  const measurement = Buffer.from(pcr0).toString("hex");
  if (measurement.toLowerCase() !== options.expectedPcr0.toLowerCase()) {
    throw new Error("Nitro PCR0 does not match the pinned enclave measurement");
  }
  if (measurement !== attestation.measurement.toLowerCase()) {
    throw new Error("Advertised measurement does not match signed PCR0");
  }

  const channelKeyBytes = bytes(mapGet(payload, "public_key"), "public key");
  if (channelKeyBytes.length !== 32) throw new Error("PZDR channel key must be 32 bytes");
  const channelKey = Buffer.from(channelKeyBytes).toString("hex");
  const bindingBytes = bytes(mapGet(payload, "user_data"), "user data");
  let binding: Record<string, unknown>;
  try {
    binding = JSON.parse(Buffer.from(bindingBytes).toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new Error("Nitro user_data does not contain the PZDR key binding");
  }
  if (binding.format !== "pzdr-attestation-binding/v1") {
    throw new Error("Unsupported PZDR attestation binding format");
  }
  if (attestation.binding_format !== "pzdr-attestation-binding/v1") {
    throw new Error("Advertised PZDR attestation binding format does not match");
  }
  if (channelKey !== attestation.channel_public_key_hex.toLowerCase()
      || binding.channel_public_key_hex !== channelKey) {
    throw new Error("Channel public key is not bound to the Nitro document");
  }
  const proofKey = String(binding.proof_verifier_key_hex ?? "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(proofKey)) throw new Error("PZDR proof verifier key must be 32 bytes");
  if (proofKey !== attestation.proof_verifier_key_hex.toLowerCase()) {
    throw new Error("Proof verifier key is not bound to the Nitro document");
  }

  return {
    measurement,
    timestampMs,
    channelPublicKeyHex: channelKey,
    proofVerifierKeyHex: proofKey,
  };
}
