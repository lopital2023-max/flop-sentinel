import assert from "node:assert/strict";
import test from "node:test";
import { buildChangesDocument } from "../src/changes.mjs";

test("converts monitor diffs into a newest-first public timeline", () => {
  const document = buildChangesDocument([
    {
      version: 1,
      checkedAt: "2026-08-26T10:00:00.000Z",
      alerts: [],
      sources: [{ id: "flop-site", url: "https://flop.finance/", status: "baseline" }],
    },
    {
      version: 1,
      checkedAt: "2026-08-26T11:00:00.000Z",
      alerts: [],
      sources: [{
        id: "technocore-openapi",
        url: "https://technocore.chat/openapi.json",
        status: "changed",
        contentHash: "a".repeat(64),
        diff: {
          infoVersion: { before: "0.9.6", after: "0.10.0" },
          addedPaths: ["/faucet"],
          removedPaths: [],
          alerts: ["new interesting OpenAPI path: /faucet"],
        },
      }],
    },
  ]);
  assert.equal(document.observationCount, 2);
  assert.equal(document.eventCount, 1);
  assert.equal(document.events[0].severity, "review");
  assert.match(document.events[0].summary.join(" "), /0\.10\.0/);
  assert.match(document.events[0].summary.join(" "), /faucet/);
});

test("does not expose monitored keyword excerpts in the public timeline", () => {
  const secretLookingExcerpt = "paste your seed phrase here";
  const document = buildChangesDocument([{
    version: 1,
    checkedAt: "2026-08-26T11:00:00.000Z",
    alerts: [],
    sources: [{
      id: "flop-site",
      url: "https://flop.finance/",
      status: "changed",
      contentHash: "b".repeat(64),
      diff: { addedKeywordLines: [secretLookingExcerpt], removedKeywordLines: [], alerts: [] },
    }],
  }]);
  assert.doesNotMatch(JSON.stringify(document), /seed phrase/);
  assert.match(document.events[0].summary[0], /Relevant wording changed/);
});
