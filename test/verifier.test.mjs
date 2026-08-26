import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { analyzeClaim, loadTrustModel } from "../src/verifier.mjs";

const projectRoot = path.resolve(import.meta.dirname, "..");

const statusDocument = {
  schemaVersion: 1,
  generatedAt: "2026-08-27T00:00:00.000Z",
  capabilities: [{
    id: "technocore-claim-token-endpoint",
    state: "not-offered-current-service",
    evidence: [{
      sourceId: "technocore-auth",
      url: "https://technocore.chat/auth.md",
      observedAt: "2026-08-27T00:00:00.000Z",
      sha256: "a".repeat(64),
    }],
  }],
  officialContracts: [],
};

const trustModel = await loadTrustModel(path.join(projectRoot, "config/trust-roots.json"));

test("recognizes an exact pinned official root", () => {
  const result = analyzeClaim("https://flop.finance/", { trustModel, statusDocument });
  assert.equal(result.verdict, "VERIFIED_OFFICIAL_ROOT");
  assert.equal(result.indicators.length, 0);
});

test("recognizes an official organization namespace without calling it an exact root", () => {
  const result = analyzeClaim("https://github.com/flop-labs/technocore-chat", {
    trustModel,
    statusDocument,
  });
  assert.equal(result.verdict, "OFFICIALLY_REFERENCED");
});

test("does not treat world-writable Technocore room content as official", () => {
  const result = analyzeClaim("https://technocore.chat/r/lobby", {
    trustModel,
    statusDocument,
  });
  assert.equal(result.verdict, "UNVERIFIED");
  assert.ok(result.indicators.some((item) => item.code === "USER_WRITABLE_OFFICIAL_SERVICE"));
});

test("flags a claim that conflicts with the current service specification", () => {
  const result = analyzeClaim("Claim the FLOP airdrop at https://technocore.chat/claim", {
    trustModel,
    statusDocument,
  });
  assert.equal(result.verdict, "CONFLICTS_WITH_CURRENT_OFFICIAL_STATE");
  assert.ok(result.evidence.some((item) => item.sourceId === "technocore-auth"));
});

test("keeps unknown contract addresses unverified", () => {
  const result = analyzeClaim(`Contract: 0x${"12".repeat(20)}`, {
    trustModel,
    statusDocument,
  });
  assert.equal(result.verdict, "UNVERIFIED");
  assert.ok(result.indicators.some((item) => item.code === "UNVERIFIED_CONTRACT_ADDRESS"));
});

test("malicious-input corpus produces the required risk indicators", async () => {
  const corpus = JSON.parse(
    await readFile(path.join(projectRoot, "test/fixtures/malicious-inputs.json"), "utf8"),
  );
  for (const fixture of corpus) {
    const result = analyzeClaim(fixture.input, { trustModel, statusDocument });
    assert.equal(result.verdict, fixture.verdict, fixture.name);
    assert.ok(
      result.indicators.some((item) => item.code === fixture.indicator),
      `${fixture.name}: missing ${fixture.indicator}`,
    );
  }
});

test("analysis is deterministic for the same input and status dataset", () => {
  const input = "Verify https://flop.finance/ before doing anything.";
  const first = analyzeClaim(input, { trustModel, statusDocument });
  const second = analyzeClaim(input, { trustModel, statusDocument });
  assert.deepEqual(first, second);
});
