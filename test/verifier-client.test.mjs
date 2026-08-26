import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { analyzeClaim } from "../src/verifier.mjs";
import { analyzeClaimInBrowser } from "../src/web/verifier-client.mjs";
import { loadTrustModel } from "../src/verifier.mjs";

const projectRoot = path.resolve(import.meta.dirname, "..");
const trustModel = await loadTrustModel(path.join(projectRoot, "config/trust-roots.json"));
const statusDocument = {
  schemaVersion: 1,
  generatedAt: "2026-08-27T00:00:00.000Z",
  capabilities: [{
    id: "technocore-claim-token-endpoint",
    state: "not-offered-current-service",
    evidence: [{ sourceId: "technocore-auth", url: "https://technocore.chat/auth.md" }],
  }],
  officialContracts: [],
};

test("browser analyzer matches CLI verdicts for the shared malicious corpus", async () => {
  const corpus = JSON.parse(
    await readFile(path.join(projectRoot, "test/fixtures/malicious-inputs.json"), "utf8"),
  );
  for (const fixture of corpus) {
    const cli = analyzeClaim(fixture.input, { trustModel, statusDocument });
    const browser = await analyzeClaimInBrowser(fixture.input, { trustModel, statusDocument });
    assert.equal(browser.verdict, cli.verdict, fixture.name);
    assert.ok(browser.indicators.some((item) => item.code === fixture.indicator), fixture.name);
  }
});

test("browser analyzer keeps user-written Technocore content unverified", async () => {
  const result = await analyzeClaimInBrowser("https://technocore.chat/kv/demo/key", {
    trustModel,
    statusDocument,
  });
  assert.equal(result.verdict, "UNVERIFIED");
  assert.ok(result.indicators.some((item) => item.code === "USER_WRITABLE_OFFICIAL_SERVICE"));
  assert.match(result.input.sha256, /^[a-f0-9]{64}$/);
});
