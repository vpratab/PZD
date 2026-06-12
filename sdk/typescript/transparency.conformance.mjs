// Cross-language conformance test: verify the Python-generated golden bundle
// using the TypeScript transparency verifier. If this passes, the Rust, Python,
// and TS implementations all agree on the RFC 6962 hashing and canonical JSON.
//
// Run:  node transparency.conformance.mjs
//
// RFC6962 logic is repeated inline for an independent algorithm check; signed
// checkpoint verification calls the built SDK implementation.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyCheckpoint } from "./dist/transparency.js";

const here = dirname(fileURLToPath(import.meta.url));
const bundlePath = join(here, "..", "..", "tools", "conformance", "bundle.json");

// ---- canonical JSON (sorted keys, compact) ----
function canonicalJSON(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJSON(value[k])}`).join(",")}}`;
}

const hexToBytes = (h) => Uint8Array.from(h.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
function sha256(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}
const leafHash = (e) => sha256(new Uint8Array([0]), e);
const nodeHash = (l, r) => sha256(new Uint8Array([1]), l, r);
const entryBytes = (proof) => new TextEncoder().encode(canonicalJSON(proof));

function verifyInclusion(leaf, index, size, pathHex, rootHex) {
  if (index >= size || size <= 0) return false;
  const path = pathHex.map(hexToBytes);
  const root = hexToBytes(rootHex);
  let fn = index, sn = size - 1, h = leaf;
  for (const sib of path) {
    if (fn % 2 === 1 || fn === sn) {
      h = nodeHash(sib, h);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else { h = nodeHash(h, sib); }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return eq(h, root) && sn === 0;
}

function verifyConsistency(firstSize, firstRootHex, secondSize, secondRootHex, proofHex) {
  const firstRoot = hexToBytes(firstRootHex), secondRoot = hexToBytes(secondRootHex);
  if (firstSize > secondSize) return false;
  if (firstSize === secondSize) return eq(firstRoot, secondRoot) && proofHex.length === 0;
  if (firstSize === 0) return true;
  const pr = [];
  if ((firstSize & (firstSize - 1)) === 0) pr.push(firstRoot);
  for (const h of proofHex) pr.push(hexToBytes(h));
  if (pr.length === 0) return false;
  let fn = firstSize - 1, sn = secondSize - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = pr[0], sr = pr[0];
  for (let i = 1; i < pr.length; i += 1) {
    const c = pr[i];
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else { sr = nodeHash(sr, c); }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return eq(fr, firstRoot) && eq(sr, secondRoot) && sn === 0;
}

// ---- run against the golden bundle ----
let failures = 0;
const check = (name, ok) => { console.log(`  [${ok ? "PASS" : "FAIL"}] ${name}`); if (!ok) failures += 1; };

const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
const cp = bundle.checkpoint;
console.log(`PZDR TS conformance against Python golden bundle (size ${cp.size})`);
check("checkpoint signature verifies under attested proof key",
  await verifyCheckpoint(cp, bundle.proof_verifier_key_hex));

for (const item of bundle.inclusions) {
  const leaf = leafHash(entryBytes(item.proof));
  check(`inclusion leaf ${item.index} (leaf-hash matches)`, bundlesLeafMatches(item, leaf));
  check(`inclusion leaf ${item.index} verifies under checkpoint root`,
    verifyInclusion(leaf, item.index, cp.size, item.audit_path, cp.root_hex));
}

{
  const tampered = { ...cp, root_hex: "00".repeat(32) };
  check("negative control: tampered checkpoint rejected",
    !(await verifyCheckpoint(tampered, bundle.proof_verifier_key_hex)));
}
for (const t of bundle.consistency) {
  check(`append-only ${t.from.size}->${t.to.size}`,
    verifyConsistency(t.from.size, t.from.root_hex, t.to.size, t.to.root_hex, t.proof));
}

// negative control: a tampered audit path must fail
{
  const item = bundle.inclusions[0];
  const leaf = leafHash(entryBytes(item.proof));
  const bad = [...item.audit_path];
  bad[0] = "00".repeat(32);
  check("negative control: tampered audit path rejected",
    !verifyInclusion(leaf, item.index, cp.size, bad, cp.root_hex));
}

function bundlesLeafMatches(item, leaf) {
  if (!item.leaf_hash_hex) return true;
  return item.leaf_hash_hex === Array.from(leaf).map((x) => x.toString(16).padStart(2, "0")).join("");
}

console.log(`  ----\n  ${failures === 0 ? "ALL PASS" : failures + " FAILED"}`);
process.exit(failures === 0 ? 0 : 1);
