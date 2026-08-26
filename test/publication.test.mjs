import assert from "node:assert/strict";
import test from "node:test";
import { buildAtomFeed, buildSourcesDocument } from "../src/publication.mjs";

const report = {
  version: 1,
  checkedAt: "2026-08-27T00:00:00.000Z",
  sources: [{
    id: "technocore-auth",
    kind: "text",
    url: "https://technocore.chat/auth.md",
    finalUrl: "https://technocore.chat/auth.md",
    httpStatus: 200,
    contentType: "text/plain",
    status: "unchanged",
    contentHash: "a".repeat(64),
    rawContentHash: "b".repeat(64),
    rawByteLength: 123,
    snapshotPath: `evidence/snapshots/${"b".repeat(64)}.snapshot`,
  }],
};
const trust = {
  version: 1,
  roots: [{ id: "technocore-auth", url: report.sources[0].url, scope: "exact-url", trust: "official-root" }],
  untrustedHostedZones: [],
};

test("builds an agent-readable source register without raw source content", () => {
  const result = buildSourcesDocument(report, trust);
  assert.equal(result.monitoredSources[0].raw.bytes, 123);
  assert.equal(result.monitoredSources[0].raw.sha256, "b".repeat(64));
  assert.equal(JSON.stringify(result).includes("private source body"), false);
  assert.equal(result.collectionPolicy.userSubmittedUrlFetch, false);
});

test("builds a deterministic, escaped Atom change feed", () => {
  const changes = {
    schemaVersion: 1,
    generatedAt: report.checkedAt,
    events: [{
      id: "event&1",
      observedAt: report.checkedAt,
      sourceId: "source<one>",
      sourceUrl: "https://example.test/?a=1&b=2",
      kind: "source-change",
      severity: "notice",
      summary: ["A <change> & review."],
    }],
  };
  const feed = buildAtomFeed(changes, { siteUrl: "https://example.test/project" });
  assert.match(feed, /https:\/\/example\.test\/project\/feed\.xml/);
  assert.match(feed, /source&lt;one&gt;/);
  assert.match(feed, /A &lt;change&gt; &amp; review\./);
  assert.doesNotMatch(feed, /A <change>/);
});
