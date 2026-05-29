import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJSON } from "./dist/canonical.js";

test("canonicalJSON keeps proof timestamps integral", () => {
  const statement = {
    commitment_hex: "aa",
    counter: 1,
    measurement: "00",
    proof_id: "proof",
    proof_version: 3,
    session_id: "session",
    success: true,
    timestamp: 1779984000,
  };

  const canonical = canonicalJSON(statement);
  assert.match(canonical, /"timestamp":1779984000/);
  assert.doesNotMatch(canonical, /1779984000\.0/);
});
