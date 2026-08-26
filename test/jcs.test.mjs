import assert from "node:assert/strict";
import test from "node:test";
import { canonicalize, canonicalizeBytes } from "../src/jcs.mjs";

test("canonicalizes the RFC 8785 primitive example", () => {
  const value = {
    numbers: [333333333.33333329, 1E30, 4.50, 2e-3, 1e-27],
    string: "\u20ac$\u000F\nA'B\"\\\"/",
    literals: [null, true, false],
  };
  assert.equal(
    canonicalize(value),
    "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\"/\"}",
  );
});

test("orders object property names by UTF-16 code units recursively", () => {
  assert.equal(
    canonicalize({ z: 1, a: { d: 4, c: 3 }, aa: 2 }),
    '{"a":{"c":3,"d":4},"aa":2,"z":1}',
  );
  assert.deepEqual(canonicalizeBytes({ b: 2, a: 1 }), new TextEncoder().encode('{"a":1,"b":2}'));
});

test("rejects values outside the I-JSON data model", () => {
  assert.throws(() => canonicalize({ value: Number.NaN }), /NaN or infinite/);
  assert.throws(() => canonicalize({ value: 1n }), /bigint/);
  assert.throws(() => canonicalize([, 1]), /sparse arrays/);
  assert.throws(() => canonicalize("\ud800"), /unpaired UTF-16 surrogate/);
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalize(cyclic), /cyclic/);
});
