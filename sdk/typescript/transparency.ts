/**
 * PZDR transparency-log verification (RFC 6962), pure TypeScript.
 *
 * Lets the client independently verify, with no server trust:
 *   - inclusion:    a deletion-proof is recorded under a signed checkpoint root
 *   - consistency:  the ledger is append-only (no rewritten history / split view)
 *   - checkpoint:   the signed tree head was signed by the attested proof key
 *
 * Hashing is byte-identical to tools/pzdr_verify.py and services/pzdr-enclave's
 * transparency.rs:
 *     leafHash(entry) = SHA256(0x00 || entry)
 *     nodeHash(l, r)  = SHA256(0x01 || l || r)
 */
import { createHash } from "node:crypto";
import { canonicalJSON } from "./canonical.js";
import sodium from "./sodium.js";

export type Hash = Uint8Array;

export interface SignedCheckpoint {
  size: number;
  root_hex: string;
  timestamp: number;
  checkpoint_signature_b64: string;
}

const hexToBytes = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
const bytesToHex = (b: Uint8Array): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const eq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export function leafHash(entryBytes: Uint8Array): Hash {
  return sha256(new Uint8Array([0x00]), entryBytes);
}
export function nodeHash(l: Hash, r: Hash): Hash {
  return sha256(new Uint8Array([0x01]), l, r);
}
export function entryBytesOf(proof: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJSON(proof));
}

export async function verifyCheckpoint(
  checkpoint: SignedCheckpoint,
  proofVerifierKeyHex: string,
): Promise<boolean> {
  await sodium.ready;
  const message = new TextEncoder().encode(canonicalJSON({
    root_hex: checkpoint.root_hex,
    size: checkpoint.size,
    timestamp: checkpoint.timestamp,
  }));
  return sodium.crypto_sign_verify_detached(
    Uint8Array.from(Buffer.from(checkpoint.checkpoint_signature_b64, "base64")),
    message,
    sodium.from_hex(proofVerifierKeyHex),
  );
}

export function verifyInclusion(
  leaf: Hash,
  index: number,
  size: number,
  pathHex: string[],
  rootHex: string,
): boolean {
  if (index >= size || size <= 0) return false;
  const path = pathHex.map(hexToBytes);
  const root = hexToBytes(rootHex);
  let fn = index;
  let sn = size - 1;
  let h = leaf;
  for (const sib of path) {
    if (fn % 2 === 1 || fn === sn) {
      h = nodeHash(sib, h);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      h = nodeHash(h, sib);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return eq(h, root) && sn === 0;
}

export function verifyConsistency(
  firstSize: number,
  firstRootHex: string,
  secondSize: number,
  secondRootHex: string,
  proofHex: string[],
): boolean {
  const firstRoot = hexToBytes(firstRootHex);
  const secondRoot = hexToBytes(secondRootHex);
  if (firstSize > secondSize) return false;
  if (firstSize === secondSize) return eq(firstRoot, secondRoot) && proofHex.length === 0;
  if (firstSize === 0) return true;

  const pr: Uint8Array[] = [];
  if ((firstSize & (firstSize - 1)) === 0) pr.push(firstRoot);
  for (const h of proofHex) pr.push(hexToBytes(h));
  if (pr.length === 0) return false;

  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = pr[0];
  let sr = pr[0];
  for (let i = 1; i < pr.length; i += 1) {
    const c = pr[i];
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return eq(fr, firstRoot) && eq(sr, secondRoot) && sn === 0;
}

export { hexToBytes, bytesToHex };
