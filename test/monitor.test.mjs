import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  compareSummaries,
  fetchOfficialSource,
  normalizeSource,
  runMonitor,
} from "../src/monitor.mjs";

const SOURCES = [
  { id: "technocore-openapi", url: "https://technocore.chat/openapi.json", kind: "openapi" },
  { id: "technocore-auth", url: "https://technocore.chat/auth.md", kind: "text" },
  { id: "flop-site", url: "https://flop.finance/", kind: "html" },
  {
    id: "flop-github-repos",
    url: "https://api.github.com/orgs/flop-labs/repos?per_page=100&type=public",
    kind: "github-repos",
  },
];

function openApi(version, paths) {
  return JSON.stringify({
    openapi: "3.1.0",
    info: { title: "fixture", version },
    paths: Object.fromEntries(paths.map((item) => [item, { get: {} }])),
  });
}

function fakeFetchFor(payloads) {
  return async (url) => {
    const value = payloads.get(String(url));
    if (value == null) return new Response("missing fixture", { status: 404 });
    return new Response(value, {
      status: 200,
      headers: { "content-type": "text/plain" },
    });
  };
}

test("detects a newly added faucet path as an alert", () => {
  const before = normalizeSource("openapi", openApi("0.9.6", ["/r/{room}"]));
  const after = normalizeSource(
    "openapi",
    openApi("0.10.0", ["/r/{room}", "/faucet/{did}"]),
  );
  const diff = compareSummaries("openapi", before.summary, after.summary);
  assert.deepEqual(diff.addedPaths, ["/faucet/{did}"]);
  assert.match(diff.alerts[0], /faucet/);
});

test("rejects a URL outside the pinned official-source allowlist", async () => {
  await assert.rejects(
    () => fetchOfficialSource({ url: "https://example.com/", kind: "text" }),
    /unpinned source URL/,
  );
});

test("runs baseline and change detection entirely against mock responses", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "flop-monitor-test-"));
  try {
    const configPath = path.join(directory, "sources.json");
    const statePath = path.join(directory, "state.json");
    const reportPath = path.join(directory, "report.json");
    const historyPath = path.join(directory, "history.jsonl");
    const snapshotDirectory = path.join(directory, "public", "evidence", "snapshots");
    await writeFile(configPath, JSON.stringify(SOURCES), "utf8");

    const payloads = new Map([
      [SOURCES[0].url, openApi("0.9.6", ["/r/{room}"])],
      [SOURCES[1].url, "There is no registration, provisioning, claim or token endpoint at any path."],
      [SOURCES[2].url, "<html><body>No pre-sale. Follow for testnet information.</body></html>"],
      [SOURCES[3].url, JSON.stringify([{ name: "technocore-chat", html_url: "https://github.com/flop-labs/technocore-chat", description: "chat", pushed_at: "2026-08-17T00:00:00Z", default_branch: "main", archived: false }])],
    ]);

    const options = {
      configPath,
      statePath,
      reportPath,
      historyPath,
      snapshotDirectory,
      fetchImpl: fakeFetchFor(payloads),
    };
    const baseline = await runMonitor(options);
    assert.deepEqual(baseline.counts, {
      baseline: 4,
      unchanged: 0,
      changed: 0,
      error: 0,
      alerts: 0,
    });

    payloads.set(SOURCES[0].url, openApi("0.10.0", ["/r/{room}", "/faucet/{did}"]));
    const changed = await runMonitor(options);
    assert.equal(changed.counts.changed, 1);
    assert.equal(changed.counts.alerts, 1);
    assert.match(changed.alerts[0].message, /faucet/);
    assert.equal(JSON.parse(await readFile(reportPath, "utf8")).counts.alerts, 1);
    const report = JSON.parse(await readFile(reportPath, "utf8"));
    assert.match(report.sources[0].rawContentHash, /^[a-f0-9]{64}$/);
    assert.equal(report.sources[0].snapshotPath, `evidence/snapshots/${report.sources[0].rawContentHash}.snapshot`);
    assert.equal(
      (await readFile(path.join(snapshotDirectory, `${report.sources[0].rawContentHash}.snapshot`), "utf8")),
      payloads.get(SOURCES[0].url),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
