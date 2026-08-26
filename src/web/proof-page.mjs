import { verifyPublishedEvidence } from "./proof-verifier.mjs";

const panel = document.querySelector("#proof-panel");
const state = document.querySelector("#proof-state");
const details = document.querySelector("#proof-details");
const errorBox = document.querySelector("#proof-error");

function setText(selector, value) {
  document.querySelector(selector).textContent = value;
}

try {
  const result = await verifyPublishedEvidence({ baseUrl: import.meta.env.BASE_URL });
  const manifest = result.latestManifest;
  const attestation = result.latestAttestation;
  const proofState = result.latestManifestReviewed ? "verified" : "verified-unreviewed";
  panel.dataset.proofState = proofState;
  state.dataset.state = proofState;
  setText("#proof-manifest-hash", manifest.entry.hash);
  setText("#proof-manifest-sequence", `#${manifest.entry.sequence}`);
  setText("#proof-observed-at", manifest.manifest.observedAt);
  setText("#proof-attestation-hash", attestation.entry.hash);
  setText("#proof-reviewed-manifest", attestation.envelope.payload.manifestHash);
  setText("#proof-reviewer-did", attestation.envelope.payload.reviewerDid);
  setText("#proof-reviewed-at", attestation.envelope.payload.reviewedAt);
  setText(
    "#proof-counts",
    `${result.manifestCount} manifest · ${result.attestationCount} checkpoint · ${result.snapshotReferences} snapshot refs · ${result.artifactReferences} artifact refs · latest reviewed: ${result.latestManifestReviewed ? "yes" : "no"}`,
  );
  details.hidden = false;
} catch (error) {
  panel.dataset.proofState = "failed";
  state.dataset.state = "failed";
  errorBox.textContent = error instanceof Error ? error.message : String(error);
  errorBox.hidden = false;
}
