import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  bootstrapMonitorState,
  createObservationManifest,
  signReviewedCheckpoint,
  verifyEvidence,
  writeProofDocument,
} from "../src/evidence.mjs";
import { didFromKey, generateIdentityPrivateKey } from "../src/identity.mjs";
import { runMonitor } from "../src/monitor.mjs";
import { verifyPublishedEvidence } from "../src/web/proof-verifier.mjs";

const SOURCES = [
  { id: "technocore-auth", url: "https://technocore.chat/auth.md", kind: "text" },
];

test("builds and verifies content-addressed manifests and Ed25519 checkpoints", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "flop-evidence-test-"));
  try {
    const publicRoot = path.join(directory, "public");
    const evidenceRoot = path.join(publicRoot, "evidence");
    const configPath = path.join(directory, "sources.json");
    const statePath = path.join(directory, "state.json");
    const reportPath = path.join(directory, "report.json");
    const historyPath = path.join(directory, "history.jsonl");
    const statusPath = path.join(directory, "status.json");
    const changesPath = path.join(directory, "changes.json");
    const trustRootsPath = path.join(directory, "trust-roots.json");
    await writeFile(configPath, JSON.stringify(SOURCES), "utf8");
    await Promise.all([
      writeFile(statusPath, '{"schemaVersion":1}\n', "utf8"),
      writeFile(changesPath, '{"schemaVersion":1,"events":[]}\n', "utf8"),
      writeFile(trustRootsPath, '{"version":1,"roots":[]}\n', "utf8"),
    ]);
    const body = "There is no registration, provisioning, claim or token endpoint at any path.";
    await runMonitor({
      configPath,
      statePath,
      reportPath,
      historyPath,
      snapshotDirectory: path.join(evidenceRoot, "snapshots"),
      fetchImpl: async () => new Response(body, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      }),
    });

    const options = { evidenceRoot, reportPath, statusPath, changesPath, trustRootsPath };
    const first = await createObservationManifest({ ...options, now: () => new Date("2026-08-27T00:00:00Z") });
    assert.equal(first.created, true);
    assert.match(first.hash, /^[a-f0-9]{64}$/);
    const duplicate = await createObservationManifest({ ...options, now: () => new Date("2026-08-27T01:00:00Z") });
    assert.equal(duplicate.created, false);
    assert.equal(duplicate.hash, first.hash);

    const privateKey = generateIdentityPrivateKey();
    const reviewerDid = didFromKey(privateKey);
    const checkpoint = await signReviewedCheckpoint({
      privateKey,
      reviewerDid,
      evidenceRoot,
      now: () => new Date("2026-08-27T02:00:00Z"),
    });
    assert.equal(checkpoint.created, true);
    assert.equal(checkpoint.envelope.payload.manifestHash, first.hash);
    const verified = await verifyEvidence({ evidenceRoot });
    assert.deepEqual(
      { ok: verified.ok, manifests: verified.manifestCount, attestations: verified.attestationCount },
      { ok: true, manifests: 1, attestations: 1 },
    );

    const proofPath = path.join(publicRoot, "proof.json");
    const proof = await writeProofDocument({
      evidenceRoot,
      proofPath,
      now: () => new Date("2026-08-27T03:00:00Z"),
    });
    assert.equal(proof.latest.attestation.reviewerDid, reviewerDid);
    assert.equal(JSON.parse(await readFile(proofPath, "utf8")).verification.ok, true);
    const publicFetch = async (url) => {
      const relative = String(url).replace(/^\//u, "");
      try {
        return new Response(await readFile(path.join(publicRoot, relative)), { status: 200 });
      } catch {
        return new Response("not found", { status: 404 });
      }
    };
    const browserResult = await verifyPublishedEvidence({ fetchImpl: publicFetch });
    assert.equal(browserResult.ok, true);
    assert.equal(browserResult.latestAttestation.envelope.payload.reviewerDid, reviewerDid);
    assert.equal(browserResult.latestManifestReviewed, true);
    const projectBaseFetch = async (url) => publicFetch(String(url).replace(/^\/flop-sentinel/u, ""));
    assert.equal(
      (await verifyPublishedEvidence({ fetchImpl: projectBaseFetch, baseUrl: "/flop-sentinel/" })).ok,
      true,
    );
    const bootstrappedStatePath = path.join(directory, "bootstrapped-state.json");
    const bootstrapped = await bootstrapMonitorState({ evidenceRoot, statePath: bootstrappedStatePath });
    assert.equal(bootstrapped.sourceCount, 1);
    assert.equal(
      JSON.parse(await readFile(bootstrappedStatePath, "utf8")).sources["technocore-auth"].contentHash,
      first.manifest.sources[0].normalizedSha256,
    );

    const snapshotPath = path.join(publicRoot, first.manifest.sources[0].raw.path);
    const original = await readFile(snapshotPath);
    await writeFile(snapshotPath, Buffer.concat([original, Buffer.from("tamper")]));
    await assert.rejects(() => verifyEvidence({ evidenceRoot }), /byte length mismatch/);
    await assert.rejects(
      () => verifyPublishedEvidence({ fetchImpl: publicFetch }),
      /byte length mismatch/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
