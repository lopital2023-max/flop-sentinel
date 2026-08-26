import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildStatusDocument,
  readStatusDocument,
  writeStatusDocument,
} from "../src/status.mjs";

function source(id, url, summary) {
  return {
    id,
    url,
    finalUrl: url,
    status: "unchanged",
    contentHash: id.padEnd(64, "0").slice(0, 64),
    summary,
  };
}

function fixtureReport() {
  return {
    version: 1,
    checkedAt: "2026-08-27T00:00:00.000Z",
    counts: { baseline: 0, unchanged: 4, changed: 0, error: 0, alerts: 0 },
    sources: [
      source("technocore-openapi", "https://technocore.chat/openapi.json", {
        specificationVersion: "3.1.0",
        infoVersion: "0.9.6",
        paths: ["/r/{room}", "/kv/{namespace}/{key}"],
      }),
      source("technocore-auth", "https://technocore.chat/auth.md", {
        explicitlySaysNoRegistrationEndpoint: true,
        explicitlySaysNoClaimOrTokenEndpoint: true,
      }),
      source("flop-site", "https://flop.finance/", { keywordLines: [] }),
      source("flop-github-repos", "https://api.github.com/orgs/flop-labs/repos?per_page=100&type=public", {
        repositories: [],
      }),
    ],
  };
}

test("builds conservative capability states from monitor evidence", () => {
  const document = buildStatusDocument(fixtureReport());
  assert.equal(document.generatedAt, "2026-08-27T00:00:00.000Z");
  assert.equal(
    document.capabilities.find((item) => item.id === "technocore-claim-token-endpoint").state,
    "not-offered-current-service",
  );
  assert.equal(
    document.capabilities.find((item) => item.id === "faucet").state,
    "not-published-in-monitored-sources",
  );
  assert.deepEqual(document.officialContracts, []);
});

test("writes status.json atomically and reads it back", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "flop-status-test-"));
  try {
    const output = path.join(directory, "public", "status.json");
    const expected = buildStatusDocument(fixtureReport());
    await writeStatusDocument(output, expected);
    assert.deepEqual(await readStatusDocument(output), expected);
    assert.match(await readFile(output, "utf8"), /FLOP Sentinel/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
