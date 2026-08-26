import { createHash, sign, verify } from "node:crypto";
import { mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { canonicalize, canonicalizeBytes } from "./jcs.mjs";
import { didFromKey, publicKeyFromDid } from "./identity.mjs";

export const DEFAULT_EVIDENCE_PATHS = Object.freeze({
  root: "public/evidence",
  report: ".local/last-report.json",
  status: "public/status.json",
  changes: "public/changes.json",
  trustRoots: "config/trust-roots.json",
  proof: "public/proof.json",
});

const MANIFEST_TYPE = "flop-sentinel-observation-manifest";
const ATTESTATION_TYPE = "flop-sentinel-reviewed-checkpoint";
const REVIEW_STATEMENT =
  "Reviewed source-provenance checkpoint; not FLOP endorsement, reward eligibility, or on-chain proof.";

export function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function isSha256(value) {
  return /^[a-f0-9]{64}$/.test(value ?? "");
}

function assertIsoTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} must be an ISO timestamp`);
  }
}

function publicRootFor(evidenceRoot) {
  const absolute = path.resolve(evidenceRoot);
  if (path.basename(absolute) !== "evidence") {
    throw new Error("evidence root directory must be named evidence");
  }
  return path.dirname(absolute);
}

function resolvePublicPath(publicRoot, relativePath) {
  if (
    typeof relativePath !== "string" ||
    !/^evidence\/[a-z0-9/_\-.]+$/.test(relativePath) ||
    relativePath.includes("..")
  ) {
    throw new Error(`unsafe evidence path: ${JSON.stringify(relativePath)}`);
  }
  const resolved = path.resolve(publicRoot, relativePath);
  const relative = path.relative(publicRoot, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("evidence path escaped public root");
  }
  return resolved;
}

async function readJson(filePath, label) {
  let parsed;
  try {
    parsed = JSON.parse(await readFile(filePath, "utf8"));
  } catch (error) {
    throw new Error(`${label} could not be read: ${error.message}`);
  }
  return parsed;
}

async function readIndex(filePath, type) {
  try {
    const value = await readJson(filePath, `${type} index`);
    if (value.schemaVersion !== 1 || value.type !== type || !Array.isArray(value.entries)) {
      throw new Error(`unsupported ${type} index`);
    }
    return value;
  } catch (error) {
    if (error.cause?.code === "ENOENT" || /ENOENT/.test(error.message)) {
      return { schemaVersion: 1, type, entries: [] };
    }
    throw error;
  }
}

async function writeJsonAtomic(filePath, value, mode = 0o644) {
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o755 });
  const temporary = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    mode,
  });
  await rename(temporary, filePath);
}

async function writeContentAddressed(filePath, bytes) {
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o755 });
  try {
    const handle = await open(filePath, "wx", 0o644);
    try {
      await handle.writeFile(bytes);
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const existing = await readFile(filePath);
    if (!existing.equals(bytes)) {
      throw new Error(`content-addressed file collision: ${filePath}`);
    }
  }
}

async function storeArtifact(publicRoot, sourcePath) {
  const bytes = await readFile(sourcePath);
  const sha256 = sha256Bytes(bytes);
  const relativePath = `evidence/artifacts/${sha256}.json`;
  await writeContentAddressed(resolvePublicPath(publicRoot, relativePath), bytes);
  return { path: relativePath, sha256, bytes: bytes.byteLength };
}

function validateReport(report) {
  if (report?.version !== 1 || !Array.isArray(report.sources)) {
    throw new Error("unsupported monitor report format");
  }
  if (report.counts?.error > 0) {
    throw new Error("manifest creation refused because an official-source observation failed");
  }
  assertIsoTimestamp(report.checkedAt, "report.checkedAt");
  for (const source of report.sources) {
    if (
      source.status === "error" ||
      !isSha256(source.contentHash) ||
      !isSha256(source.rawContentHash) ||
      !Number.isSafeInteger(source.rawByteLength) ||
      source.rawByteLength < 0 ||
      source.snapshotPath !== `evidence/snapshots/${source.rawContentHash}.snapshot`
    ) {
      throw new Error(
        `report source ${source.id ?? "unknown"} has no valid persisted snapshot; run web:data --refresh`,
      );
    }
  }
}

function sameObservation(manifest, candidate) {
  return (
    manifest.observedAt === candidate.observedAt &&
    canonicalize(manifest.sources) === canonicalize(candidate.sources) &&
    canonicalize(manifest.artifacts) === canonicalize(candidate.artifacts)
  );
}

export async function createObservationManifest({
  evidenceRoot = DEFAULT_EVIDENCE_PATHS.root,
  reportPath = DEFAULT_EVIDENCE_PATHS.report,
  statusPath = DEFAULT_EVIDENCE_PATHS.status,
  changesPath = DEFAULT_EVIDENCE_PATHS.changes,
  trustRootsPath = DEFAULT_EVIDENCE_PATHS.trustRoots,
  now = () => new Date(),
} = {}) {
  const absoluteEvidenceRoot = path.resolve(evidenceRoot);
  const publicRoot = publicRootFor(absoluteEvidenceRoot);
  const report = await readJson(path.resolve(reportPath), "monitor report");
  validateReport(report);

  const [status, changes, trustRoots, monitorReport] = await Promise.all([
    storeArtifact(publicRoot, path.resolve(statusPath)),
    storeArtifact(publicRoot, path.resolve(changesPath)),
    storeArtifact(publicRoot, path.resolve(trustRootsPath)),
    storeArtifact(publicRoot, path.resolve(reportPath)),
  ]);
  const sources = report.sources.map((source) => ({
    sourceId: source.id,
    kind: source.kind,
    url: source.url,
    finalUrl: source.finalUrl,
    httpStatus: source.httpStatus,
    contentType: source.contentType,
    raw: {
      path: source.snapshotPath,
      sha256: source.rawContentHash,
      bytes: source.rawByteLength,
    },
    normalizedSha256: source.contentHash,
  }));
  const artifacts = { status, changes, trustRoots, monitorReport };
  const indexPath = path.join(absoluteEvidenceRoot, "manifests", "index.json");
  const index = await readIndex(indexPath, "flop-sentinel-manifest-index");
  const latestEntry = index.entries.at(-1) ?? null;
  const candidate = { observedAt: report.checkedAt, sources, artifacts };

  if (latestEntry) {
    const latest = await readJson(
      resolvePublicPath(publicRoot, latestEntry.path),
      "latest manifest",
    );
    if (sameObservation(latest, candidate)) {
      return { created: false, hash: latestEntry.hash, path: latestEntry.path, manifest: latest };
    }
  }

  const createdAt = now().toISOString();
  const manifest = {
    schemaVersion: 1,
    type: MANIFEST_TYPE,
    sequence: index.entries.length + 1,
    observedAt: report.checkedAt,
    createdAt,
    previousManifestHash: latestEntry?.hash ?? null,
    collector: {
      name: "flop-local-agent-toolkit",
      evidenceFormatVersion: 1,
    },
    sources,
    artifacts,
  };
  const hash = sha256Bytes(canonicalizeBytes(manifest));
  const relativePath = `evidence/manifests/${String(manifest.sequence).padStart(6, "0")}-${hash}.json`;
  await writeContentAddressed(
    resolvePublicPath(publicRoot, relativePath),
    Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8"),
  );
  index.entries.push({
    sequence: manifest.sequence,
    hash,
    path: relativePath,
    observedAt: manifest.observedAt,
    createdAt,
    previousManifestHash: manifest.previousManifestHash,
  });
  await writeJsonAtomic(indexPath, index);
  return { created: true, hash, path: relativePath, manifest };
}

function decodeBase64url(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} is not base64url`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) throw new Error(`${label} is not canonical base64url`);
  return bytes;
}

export async function signReviewedCheckpoint({
  privateKey,
  reviewerDid,
  evidenceRoot = DEFAULT_EVIDENCE_PATHS.root,
  manifestHash,
  now = () => new Date(),
} = {}) {
  if (!privateKey) throw new Error("privateKey is required");
  if (didFromKey(privateKey) !== reviewerDid) {
    throw new Error("reviewer DID does not match the signing private key");
  }
  const absoluteEvidenceRoot = path.resolve(evidenceRoot);
  const publicRoot = publicRootFor(absoluteEvidenceRoot);
  const manifestIndex = await readIndex(
    path.join(absoluteEvidenceRoot, "manifests", "index.json"),
    "flop-sentinel-manifest-index",
  );
  if (manifestIndex.entries.length === 0) throw new Error("no observation manifest exists");
  const manifestEntry = manifestHash
    ? manifestIndex.entries.find((entry) => entry.hash === manifestHash)
    : manifestIndex.entries.at(-1);
  if (!manifestEntry) throw new Error(`manifest not found: ${manifestHash}`);

  const indexPath = path.join(absoluteEvidenceRoot, "attestations", "index.json");
  const index = await readIndex(indexPath, "flop-sentinel-attestation-index");
  const existing = index.entries.find(
    (entry) => entry.manifestHash === manifestEntry.hash && entry.reviewerDid === reviewerDid,
  );
  if (existing) {
    const envelope = await readJson(resolvePublicPath(publicRoot, existing.path), "attestation");
    return { created: false, hash: existing.hash, path: existing.path, envelope };
  }

  const previous = index.entries.at(-1) ?? null;
  const payload = {
    schemaVersion: 1,
    type: ATTESTATION_TYPE,
    manifestHash: manifestEntry.hash,
    manifestPath: manifestEntry.path,
    manifestSequence: manifestEntry.sequence,
    reviewedAt: now().toISOString(),
    reviewerDid,
    previousAttestationHash: previous?.hash ?? null,
    statement: REVIEW_STATEMENT,
  };
  const signature = sign(null, canonicalizeBytes(payload), privateKey);
  const envelope = {
    schemaVersion: 1,
    type: ATTESTATION_TYPE,
    payload,
    proof: {
      algorithm: "Ed25519",
      canonicalization: "RFC8785-JCS",
      signatureValue: signature.toString("base64url"),
    },
  };
  if (!verify(null, canonicalizeBytes(payload), publicKeyFromDid(reviewerDid), signature)) {
    throw new Error("newly created checkpoint signature failed self-verification");
  }
  const hash = sha256Bytes(canonicalizeBytes(envelope));
  const relativePath = `evidence/attestations/${String(index.entries.length + 1).padStart(6, "0")}-${hash}.json`;
  await writeContentAddressed(
    resolvePublicPath(publicRoot, relativePath),
    Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`, "utf8"),
  );
  index.entries.push({
    sequence: index.entries.length + 1,
    hash,
    path: relativePath,
    manifestHash: payload.manifestHash,
    reviewerDid,
    reviewedAt: payload.reviewedAt,
    previousAttestationHash: payload.previousAttestationHash,
  });
  await writeJsonAtomic(indexPath, index);
  return { created: true, hash, path: relativePath, envelope };
}

async function verifyFileReference(publicRoot, reference, label, allowedPattern) {
  if (
    !reference ||
    !isSha256(reference.sha256) ||
    !Number.isSafeInteger(reference.bytes) ||
    reference.bytes < 0 ||
    !allowedPattern.test(reference.path ?? "")
  ) {
    throw new Error(`${label} has an invalid file reference`);
  }
  const bytes = await readFile(resolvePublicPath(publicRoot, reference.path));
  if (bytes.byteLength !== reference.bytes) throw new Error(`${label} byte length mismatch`);
  if (sha256Bytes(bytes) !== reference.sha256) throw new Error(`${label} SHA-256 mismatch`);
}

export async function verifyEvidence({ evidenceRoot = DEFAULT_EVIDENCE_PATHS.root } = {}) {
  const absoluteEvidenceRoot = path.resolve(evidenceRoot);
  const publicRoot = publicRootFor(absoluteEvidenceRoot);
  const manifests = await readIndex(
    path.join(absoluteEvidenceRoot, "manifests", "index.json"),
    "flop-sentinel-manifest-index",
  );
  const attestations = await readIndex(
    path.join(absoluteEvidenceRoot, "attestations", "index.json"),
    "flop-sentinel-attestation-index",
  );
  if (manifests.entries.length === 0) throw new Error("manifest chain is empty");

  const manifestByHash = new Map();
  let previousManifestHash = null;
  let snapshotReferences = 0;
  let artifactReferences = 0;
  for (const [offset, entry] of manifests.entries.entries()) {
    const sequence = offset + 1;
    if (
      entry.sequence !== sequence ||
      !isSha256(entry.hash) ||
      entry.previousManifestHash !== previousManifestHash ||
      entry.path !== `evidence/manifests/${String(sequence).padStart(6, "0")}-${entry.hash}.json`
    ) {
      throw new Error(`manifest index chain is invalid at sequence ${sequence}`);
    }
    const manifest = await readJson(resolvePublicPath(publicRoot, entry.path), `manifest ${sequence}`);
    if (
      manifest.schemaVersion !== 1 ||
      manifest.type !== MANIFEST_TYPE ||
      manifest.sequence !== sequence ||
      manifest.previousManifestHash !== previousManifestHash ||
      !Array.isArray(manifest.sources) ||
      sha256Bytes(canonicalizeBytes(manifest)) !== entry.hash
    ) {
      throw new Error(`manifest ${sequence} failed canonical hash or chain validation`);
    }
    for (const source of manifest.sources) {
      if (source.raw?.path !== `evidence/snapshots/${source.raw?.sha256}.snapshot`) {
        throw new Error(`manifest ${sequence} source ${source.sourceId} has an invalid snapshot path`);
      }
      await verifyFileReference(
        publicRoot,
        source.raw,
        `manifest ${sequence} source ${source.sourceId}`,
        /^evidence\/snapshots\/[a-f0-9]{64}\.snapshot$/,
      );
      if (!isSha256(source.normalizedSha256)) {
        throw new Error(`manifest ${sequence} source ${source.sourceId} has an invalid normalized hash`);
      }
      snapshotReferences += 1;
    }
    for (const [name, artifact] of Object.entries(manifest.artifacts ?? {})) {
      if (artifact.path !== `evidence/artifacts/${artifact.sha256}.json`) {
        throw new Error(`manifest ${sequence} artifact ${name} has an invalid path`);
      }
      await verifyFileReference(
        publicRoot,
        artifact,
        `manifest ${sequence} artifact ${name}`,
        /^evidence\/artifacts\/[a-f0-9]{64}\.json$/,
      );
      artifactReferences += 1;
    }
    if (Object.keys(manifest.artifacts ?? {}).length !== 4) {
      throw new Error(`manifest ${sequence} must bind exactly four public artifacts`);
    }
    manifestByHash.set(entry.hash, { entry, manifest });
    previousManifestHash = entry.hash;
  }

  let previousAttestationHash = null;
  for (const [offset, entry] of attestations.entries.entries()) {
    const sequence = offset + 1;
    if (
      entry.sequence !== sequence ||
      !isSha256(entry.hash) ||
      entry.previousAttestationHash !== previousAttestationHash ||
      entry.path !== `evidence/attestations/${String(sequence).padStart(6, "0")}-${entry.hash}.json`
    ) {
      throw new Error(`attestation index chain is invalid at sequence ${sequence}`);
    }
    const envelope = await readJson(resolvePublicPath(publicRoot, entry.path), `attestation ${sequence}`);
    const payload = envelope.payload;
    const manifestRecord = manifestByHash.get(payload?.manifestHash);
    const signature = decodeBase64url(envelope.proof?.signatureValue, `attestation ${sequence} signature`);
    if (
      envelope.schemaVersion !== 1 ||
      envelope.type !== ATTESTATION_TYPE ||
      payload?.type !== ATTESTATION_TYPE ||
      envelope.proof?.algorithm !== "Ed25519" ||
      envelope.proof?.canonicalization !== "RFC8785-JCS" ||
      payload.previousAttestationHash !== previousAttestationHash ||
      payload.statement !== REVIEW_STATEMENT ||
      !manifestRecord ||
      payload.manifestPath !== manifestRecord.entry.path ||
      payload.manifestSequence !== manifestRecord.entry.sequence ||
      entry.manifestHash !== payload.manifestHash ||
      entry.reviewerDid !== payload.reviewerDid ||
      sha256Bytes(canonicalizeBytes(envelope)) !== entry.hash ||
      signature.byteLength !== 64 ||
      !verify(null, canonicalizeBytes(payload), publicKeyFromDid(payload.reviewerDid), signature)
    ) {
      throw new Error(`attestation ${sequence} failed hash, reference, or Ed25519 validation`);
    }
    previousAttestationHash = entry.hash;
  }

  return {
    ok: true,
    manifestCount: manifests.entries.length,
    attestationCount: attestations.entries.length,
    snapshotReferences,
    artifactReferences,
    latestManifest: manifests.entries.at(-1),
    latestAttestation: attestations.entries.at(-1) ?? null,
  };
}

export async function readEvidenceMonitorReports({
  evidenceRoot = DEFAULT_EVIDENCE_PATHS.root,
} = {}) {
  await verifyEvidence({ evidenceRoot });
  const absoluteEvidenceRoot = path.resolve(evidenceRoot);
  const publicRoot = publicRootFor(absoluteEvidenceRoot);
  const manifests = await readIndex(
    path.join(absoluteEvidenceRoot, "manifests", "index.json"),
    "flop-sentinel-manifest-index",
  );
  const reports = [];
  for (const entry of manifests.entries) {
    const manifest = await readJson(resolvePublicPath(publicRoot, entry.path), "manifest");
    const reportReference = manifest.artifacts?.monitorReport;
    if (!reportReference) throw new Error(`manifest ${entry.sequence} has no monitor report`);
    reports.push(await readJson(
      resolvePublicPath(publicRoot, reportReference.path),
      `manifest ${entry.sequence} monitor report`,
    ));
  }
  return reports;
}

export async function bootstrapMonitorState({
  evidenceRoot = DEFAULT_EVIDENCE_PATHS.root,
  statePath = ".local/monitor-state.json",
} = {}) {
  const reports = await readEvidenceMonitorReports({ evidenceRoot });
  const report = reports.at(-1);
  if (!report) throw new Error("cannot bootstrap monitor state from an empty evidence chain");
  validateReport(report);
  const sources = {};
  for (const source of report.sources) {
    sources[source.id] = {
      url: source.url,
      finalUrl: source.finalUrl,
      kind: source.kind,
      contentHash: source.contentHash,
      rawContentHash: source.rawContentHash,
      rawByteLength: source.rawByteLength,
      snapshotPath: source.snapshotPath,
      contentType: source.contentType,
      summary: source.summary,
      checkedAt: report.checkedAt,
    };
  }
  const state = { version: 1, sources };
  await writeJsonAtomic(path.resolve(statePath), state, 0o600);
  return { state, sourceCount: Object.keys(sources).length, checkedAt: report.checkedAt };
}

export async function writeProofDocument({
  evidenceRoot = DEFAULT_EVIDENCE_PATHS.root,
  proofPath = DEFAULT_EVIDENCE_PATHS.proof,
  now = () => new Date(),
} = {}) {
  const verification = await verifyEvidence({ evidenceRoot });
  const absoluteEvidenceRoot = path.resolve(evidenceRoot);
  const publicRoot = publicRootFor(absoluteEvidenceRoot);
  const manifest = await readJson(
    resolvePublicPath(publicRoot, verification.latestManifest.path),
    "latest manifest",
  );
  const attestation = verification.latestAttestation
    ? await readJson(
      resolvePublicPath(publicRoot, verification.latestAttestation.path),
      "latest attestation",
    )
    : null;
  const document = {
    schemaVersion: 1,
    type: "flop-sentinel-proof-discovery",
    generatedAt: now().toISOString(),
    manifestIndex: "evidence/manifests/index.json",
    attestationIndex: "evidence/attestations/index.json",
    latest: {
      manifest: {
        ...verification.latestManifest,
        sourceCount: manifest.sources.length,
        artifactCount: Object.keys(manifest.artifacts).length,
      },
      attestation: verification.latestAttestation
        ? {
          ...verification.latestAttestation,
          algorithm: attestation.proof.algorithm,
          canonicalization: attestation.proof.canonicalization,
        }
        : null,
    },
    verification: {
      ...verification,
      latestManifestReviewed:
        verification.latestAttestation?.manifestHash === verification.latestManifest.hash,
      latestManifest: undefined,
      latestAttestation: undefined,
    },
    limitation: REVIEW_STATEMENT,
  };
  delete document.verification.latestManifest;
  delete document.verification.latestAttestation;
  await writeJsonAtomic(path.resolve(proofPath), document);
  return document;
}
