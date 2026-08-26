import { canonicalizeBytes } from "../jcs.mjs";

const MANIFEST_INDEX_TYPE = "flop-sentinel-manifest-index";
const ATTESTATION_INDEX_TYPE = "flop-sentinel-attestation-index";
const MANIFEST_TYPE = "flop-sentinel-observation-manifest";
const ATTESTATION_TYPE = "flop-sentinel-reviewed-checkpoint";
const REVIEW_STATEMENT =
  "Reviewed source-provenance checkpoint; not FLOP endorsement, reward eligibility, or on-chain proof.";
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isHash(value) {
  return /^[a-f0-9]{64}$/.test(value ?? "");
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function decodeBase58(value) {
  assert(typeof value === "string" && value.length > 0, "empty base58 DID key");
  let numeric = 0n;
  for (const character of value) {
    const digit = BASE58_ALPHABET.indexOf(character);
    assert(digit >= 0, "invalid base58 DID key");
    numeric = numeric * 58n + BigInt(digit);
  }
  let hex = numeric.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  const numericBytes = numeric === 0n
    ? new Uint8Array()
    : Uint8Array.from(hex.match(/.{2}/g).map((pair) => Number.parseInt(pair, 16)));
  const leadingZeros = value.match(/^1*/)?.[0].length ?? 0;
  const result = new Uint8Array(leadingZeros + numericBytes.length);
  result.set(numericBytes, leadingZeros);
  return result;
}

function publicKeyBytesFromDid(did) {
  assert(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/.test(did ?? ""), "invalid reviewer DID");
  const decoded = decodeBase58(did.slice("did:key:z".length));
  assert(decoded.length === 34 && decoded[0] === 0xed && decoded[1] === 0x01, "DID is not Ed25519");
  return decoded.slice(2);
}

function decodeBase64url(value) {
  assert(typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value), "invalid base64url signature");
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const canonical = btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  assert(canonical === value, "non-canonical base64url signature");
  return bytes;
}

function safeEvidencePath(value, pattern, label) {
  assert(typeof value === "string" && pattern.test(value) && !value.includes(".."), `invalid ${label} path`);
  return `/${value}`;
}

async function fetchBytes(fetchImpl, url, label) {
  const response = await fetchImpl(url, { cache: "no-store", credentials: "omit" });
  if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function fetchJson(fetchImpl, url, label) {
  const bytes = await fetchBytes(fetchImpl, url, label);
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`${label} is not valid UTF-8 JSON`);
  }
  return { value, bytes };
}

async function verifyRawReference(fetchImpl, reference, label, pattern, cache) {
  assert(
    reference && isHash(reference.sha256) && Number.isSafeInteger(reference.bytes) && reference.bytes >= 0,
    `${label} has invalid metadata`,
  );
  const url = safeEvidencePath(reference.path, pattern, label);
  let result = cache.get(url);
  if (!result) {
    result = fetchBytes(fetchImpl, url, label).then(async (bytes) => ({
      bytes,
      hash: await sha256Hex(bytes),
    }));
    cache.set(url, result);
  }
  const { bytes, hash } = await result;
  assert(bytes.byteLength === reference.bytes, `${label} byte length mismatch`);
  assert(hash === reference.sha256, `${label} SHA-256 mismatch`);
}

async function verifyEd25519(payload, did, signatureValue) {
  const publicKey = await crypto.subtle.importKey(
    "raw",
    publicKeyBytesFromDid(did),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const signature = decodeBase64url(signatureValue);
  assert(signature.byteLength === 64, "invalid Ed25519 signature length");
  return crypto.subtle.verify("Ed25519", publicKey, signature, canonicalizeBytes(payload));
}

export async function verifyPublishedEvidence({
  fetchImpl = globalThis.fetch,
  baseUrl = "/",
} = {}) {
  const baseSegment = String(baseUrl).replace(/^\/+|\/+$/gu, "");
  const publicUrl = (relativePath) => {
    const cleanPath = String(relativePath).replace(/^\/+/, "");
    return `/${baseSegment ? `${baseSegment}/` : ""}${cleanPath}`;
  };
  const scopedFetch = (url, options) => fetchImpl(publicUrl(url), options);
  const [{ value: proof }, { value: manifestIndex }, { value: attestationIndex }] = await Promise.all([
    fetchJson(fetchImpl, publicUrl("proof.json"), "proof discovery"),
    fetchJson(fetchImpl, publicUrl("evidence/manifests/index.json"), "manifest index"),
    fetchJson(fetchImpl, publicUrl("evidence/attestations/index.json"), "attestation index"),
  ]);
  assert(proof.schemaVersion === 1 && proof.type === "flop-sentinel-proof-discovery", "unsupported proof discovery document");
  assert(manifestIndex.schemaVersion === 1 && manifestIndex.type === MANIFEST_INDEX_TYPE, "unsupported manifest index");
  assert(attestationIndex.schemaVersion === 1 && attestationIndex.type === ATTESTATION_INDEX_TYPE, "unsupported attestation index");
  assert(manifestIndex.entries.length > 0, "manifest chain is empty");

  const contentCache = new Map();
  const manifests = new Map();
  let previousManifestHash = null;
  let snapshotReferences = 0;
  let artifactReferences = 0;
  for (const [offset, entry] of manifestIndex.entries.entries()) {
    const sequence = offset + 1;
    assert(
      entry.sequence === sequence && isHash(entry.hash) && entry.previousManifestHash === previousManifestHash,
      `manifest index chain failed at #${sequence}`,
    );
    const expectedPath = `evidence/manifests/${String(sequence).padStart(6, "0")}-${entry.hash}.json`;
    assert(entry.path === expectedPath, `manifest #${sequence} path mismatch`);
    const { value: manifest } = await fetchJson(
      fetchImpl,
      publicUrl(safeEvidencePath(entry.path, /^evidence\/manifests\/[a-f0-9-]+\.json$/, "manifest")),
      `manifest #${sequence}`,
    );
    assert(
      manifest.schemaVersion === 1 &&
      manifest.type === MANIFEST_TYPE &&
      manifest.sequence === sequence &&
      manifest.previousManifestHash === previousManifestHash &&
      Array.isArray(manifest.sources),
      `manifest #${sequence} schema or chain mismatch`,
    );
    assert(await sha256Hex(canonicalizeBytes(manifest)) === entry.hash, `manifest #${sequence} JCS hash mismatch`);
    for (const source of manifest.sources) {
      assert(source.raw?.path === `evidence/snapshots/${source.raw?.sha256}.snapshot`, `snapshot path mismatch for ${source.sourceId}`);
      assert(isHash(source.normalizedSha256), `normalized hash missing for ${source.sourceId}`);
      await verifyRawReference(
        scopedFetch,
        source.raw,
        `snapshot ${source.sourceId}`,
        /^evidence\/snapshots\/[a-f0-9]{64}\.snapshot$/,
        contentCache,
      );
      snapshotReferences += 1;
    }
    const artifacts = Object.entries(manifest.artifacts ?? {});
    assert(artifacts.length === 4, `manifest #${sequence} does not bind four artifacts`);
    for (const [name, artifact] of artifacts) {
      assert(artifact.path === `evidence/artifacts/${artifact.sha256}.json`, `artifact path mismatch for ${name}`);
      await verifyRawReference(
        scopedFetch,
        artifact,
        `artifact ${name}`,
        /^evidence\/artifacts\/[a-f0-9]{64}\.json$/,
        contentCache,
      );
      artifactReferences += 1;
    }
    manifests.set(entry.hash, { entry, manifest });
    previousManifestHash = entry.hash;
  }

  let previousAttestationHash = null;
  let latestEnvelope = null;
  for (const [offset, entry] of attestationIndex.entries.entries()) {
    const sequence = offset + 1;
    assert(
      entry.sequence === sequence && isHash(entry.hash) && entry.previousAttestationHash === previousAttestationHash,
      `attestation index chain failed at #${sequence}`,
    );
    const expectedPath = `evidence/attestations/${String(sequence).padStart(6, "0")}-${entry.hash}.json`;
    assert(entry.path === expectedPath, `attestation #${sequence} path mismatch`);
    const { value: envelope } = await fetchJson(
      fetchImpl,
      publicUrl(safeEvidencePath(entry.path, /^evidence\/attestations\/[a-f0-9-]+\.json$/, "attestation")),
      `attestation #${sequence}`,
    );
    const payload = envelope.payload;
    const manifestRecord = manifests.get(payload?.manifestHash);
    assert(
      envelope.schemaVersion === 1 &&
      envelope.type === ATTESTATION_TYPE &&
      payload?.type === ATTESTATION_TYPE &&
      envelope.proof?.algorithm === "Ed25519" &&
      envelope.proof?.canonicalization === "RFC8785-JCS" &&
      payload.previousAttestationHash === previousAttestationHash &&
      payload.statement === REVIEW_STATEMENT &&
      manifestRecord &&
      payload.manifestPath === manifestRecord.entry.path &&
      payload.manifestSequence === manifestRecord.entry.sequence,
      `attestation #${sequence} schema or reference mismatch`,
    );
    assert(
      entry.manifestHash === payload.manifestHash && entry.reviewerDid === payload.reviewerDid,
      `attestation #${sequence} index metadata mismatch`,
    );
    assert(await sha256Hex(canonicalizeBytes(envelope)) === entry.hash, `attestation #${sequence} JCS hash mismatch`);
    assert(await verifyEd25519(payload, payload.reviewerDid, envelope.proof.signatureValue), `attestation #${sequence} Ed25519 signature failed`);
    latestEnvelope = envelope;
    previousAttestationHash = entry.hash;
  }
  assert(latestEnvelope, "no reviewed checkpoint exists");
  assert(proof.latest?.manifest?.hash === previousManifestHash, "proof discovery latest manifest mismatch");
  assert(proof.latest?.attestation?.hash === previousAttestationHash, "proof discovery latest attestation mismatch");

  const latestManifestReviewed = latestEnvelope.payload.manifestHash === previousManifestHash;
  return {
    ok: true,
    latestManifestReviewed,
    manifestCount: manifestIndex.entries.length,
    attestationCount: attestationIndex.entries.length,
    snapshotReferences,
    artifactReferences,
    latestManifest: manifests.get(previousManifestHash),
    latestAttestation: {
      entry: attestationIndex.entries.at(-1),
      envelope: latestEnvelope,
    },
  };
}
