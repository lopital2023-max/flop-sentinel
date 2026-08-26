#!/usr/bin/env node

import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import {
  KEYSTORE_DEFAULT_PATH,
  decryptPrivateKey,
  encryptPrivateKey,
  generateIdentityPrivateKey,
  readKeystore,
  writeNewKeystore,
} from "./identity.mjs";
import {
  deleteKeychainSecret,
  keychainReferenceForKeystore,
  loadKeychainSecret,
  storeKeychainSecret,
} from "./keychain.mjs";
import {
  DEFAULT_MONITOR_PATHS,
  formatMonitorReport,
  runMonitor,
} from "./monitor.mjs";
import { formatEnvironmentReport, inspectEnvironment } from "./environment.mjs";
import {
  buildChangesDocument,
  DEFAULT_CHANGES_PATH,
  formatChangesDocument,
  readChangesDocument,
  readMonitorHistory,
  writeChangesDocument,
} from "./changes.mjs";
import { NonceStore } from "./nonce-store.mjs";
import {
  buildStatusDocument,
  DEFAULT_STATUS_PATH,
  formatStatusDocument,
  readStatusDocument,
  writeStatusDocument,
} from "./status.mjs";
import {
  buildPublicProfile,
  buildSignedMessage,
  createMailboxName,
  didProfileLocation,
  sendSignedMessage,
  setPublicNote,
} from "./technocore.mjs";
import {
  analyzeClaim,
  DEFAULT_TRUST_ROOTS_PATH,
  formatClaimAnalysis,
  loadTrustModel,
} from "./verifier.mjs";
import {
  bootstrapMonitorState,
  createObservationManifest,
  DEFAULT_EVIDENCE_PATHS,
  signReviewedCheckpoint,
  readEvidenceMonitorReports,
  verifyEvidence,
  writeProofDocument,
} from "./evidence.mjs";
import {
  DEFAULT_PUBLICATION_PATHS,
  DEFAULT_PUBLIC_SITE_URL,
  writePublicationData,
} from "./publication.mjs";

const HELP = `FLOP / Technocore local toolkit

Safe commands (no secret generation, no remote write):
  node src/cli.mjs env:check [--json]
  node src/cli.mjs monitor [--no-write] [--json]
  node src/cli.mjs monitor:bootstrap [--state .local/monitor-state.json]
  node src/cli.mjs status:build [--refresh] [--output public/status.json]
  node src/cli.mjs status [--json] [--status-data public/status.json]
  node src/cli.mjs changes:build [--output public/changes.json]
  node src/cli.mjs changes [--json] [--changes-data public/changes.json]
  node src/cli.mjs web:data [--refresh]
  node src/cli.mjs publish:data [--site-url https://example/]
  node src/cli.mjs attest:manifest
  node src/cli.mjs attest:verify [--json] [--no-write]
  node src/cli.mjs check --input "URL or message" [--json]
  node src/cli.mjs check --file path/to/message.txt [--json]
  node src/cli.mjs identity:show [--keystore PATH]

Secret-generating command (NOT run during initial setup):
  node src/cli.mjs identity:init --acknowledge-secret-generation [--keystore PATH]
  node src/cli.mjs identity:init-keychain --acknowledge-secret-generation-and-keychain-storage

Signed-message preview (decrypts an existing keystore, but does not send):
  node src/cli.mjs say --room ROOM --text TEXT [--keystore PATH]

Reviewed evidence signature (local artifact write; no network operation):
  node src/cli.mjs attest:sign --acknowledge-reviewed-checkpoint [--manifest SHA256]

External write (public Technocore POST; requires the explicit final flag):
  node src/cli.mjs say --room ROOM --text TEXT --execute-external-write
  node src/cli.mjs checkin --execute-external-write

Safety properties:
  - passphrases are requested from an interactive hidden prompt, never CLI args/env
  - identity:init refuses to run without the long acknowledgement flag
  - say is preview-only unless --execute-external-write is present
  - writes are pinned to https://technocore.chat and use POST, not signed GET URLs
  - monitor only reads four pinned official URLs
  - snapshots and manifests are content-addressed and verified as an RFC 8785 hash-chain
  - attest:sign signs only a reviewed checkpoint; it never sends or publishes it
  - check never fetches a user-submitted URL and never connects a wallet
  - identity:init-keychain stores a random unlock key in macOS Keychain
`;

function parseArguments(argv) {
  const positional = [];
  const flags = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      positional.push(token);
      continue;
    }
    const key = token.slice(2);
    if ([
      "no-write",
      "json",
      "refresh",
      "acknowledge-secret-generation",
      "acknowledge-secret-generation-and-keychain-storage",
      "acknowledge-reviewed-checkpoint",
      "execute-external-write",
      "help",
    ].includes(key)) {
      flags[key] = true;
      continue;
    }
    const value = argv[index + 1];
    if (value == null || value.startsWith("--")) {
      throw new Error(`missing value for --${key}`);
    }
    flags[key] = value;
    index += 1;
  }
  return { positional, flags };
}

function localPath(candidate) {
  const root = process.cwd();
  const resolved = path.resolve(root, candidate);
  const relative = path.relative(root, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`path must stay inside this project: ${candidate}`);
  }
  return resolved;
}

async function promptHidden(label) {
  if (!process.stdin.isTTY || !process.stdout.isTTY || !process.stdin.setRawMode) {
    throw new Error("secret input requires an interactive terminal (TTY)");
  }
  process.stdout.write(label);
  const wasRaw = Boolean(process.stdin.isRaw);
  process.stdin.setRawMode(true);
  process.stdin.resume();

  return new Promise((resolve, reject) => {
    let value = "";
    const decoder = new StringDecoder("utf8");
    const cleanup = () => {
      process.stdin.off("data", onData);
      process.stdin.setRawMode(wasRaw);
      process.stdin.pause();
    };
    const onData = (chunk) => {
      for (const character of decoder.write(chunk)) {
        if (character === "\r" || character === "\n") {
          cleanup();
          process.stdout.write("\n");
          resolve(value);
          return;
        }
        if (character === "\u0003") {
          cleanup();
          process.stdout.write("\n");
          reject(new Error("cancelled"));
          return;
        }
        if (character === "\u007f" || character === "\b") {
          value = [...value].slice(0, -1).join("");
          continue;
        }
        if (character >= " ") value += character;
      }
    };
    process.stdin.on("data", onData);
  });
}

async function commandMonitor(flags) {
  const report = await runMonitor({
    configPath: localPath(flags.config ?? DEFAULT_MONITOR_PATHS.config),
    statePath: localPath(flags.state ?? DEFAULT_MONITOR_PATHS.state),
    reportPath: localPath(flags.report ?? DEFAULT_MONITOR_PATHS.report),
    historyPath: localPath(flags.history ?? DEFAULT_MONITOR_PATHS.history),
    snapshotDirectory: localPath(flags.snapshots ?? DEFAULT_MONITOR_PATHS.snapshots),
    noWrite: Boolean(flags["no-write"]),
  });
  console.log(flags.json ? JSON.stringify(report, null, 2) : formatMonitorReport(report));
  if (report.counts.error > 0) process.exitCode = 1;
}

async function commandMonitorBootstrap(flags) {
  const result = await bootstrapMonitorState({
    evidenceRoot: localPath(flags["evidence-root"] ?? DEFAULT_EVIDENCE_PATHS.root),
    statePath: localPath(flags.state ?? DEFAULT_MONITOR_PATHS.state),
  });
  console.log(`Bootstrapped ${result.sourceCount} source states from evidence at ${result.checkedAt}.`);
}

async function commandEnvironment(flags) {
  const report = await inspectEnvironment(process.cwd());
  console.log(flags.json ? JSON.stringify(report, null, 2) : formatEnvironmentReport(report));
  if (!report.ok) process.exitCode = 1;
}

async function readMonitorReport(reportPath) {
  const parsed = JSON.parse(await readFile(reportPath, "utf8"));
  if (parsed?.version !== 1 || !Array.isArray(parsed.sources)) {
    throw new Error("unsupported monitor report format");
  }
  return parsed;
}

async function commandStatusBuild(flags) {
  const reportPath = localPath(flags.report ?? DEFAULT_MONITOR_PATHS.report);
  const report = flags.refresh
    ? await runMonitor({
      configPath: localPath(flags.config ?? DEFAULT_MONITOR_PATHS.config),
      statePath: localPath(flags.state ?? DEFAULT_MONITOR_PATHS.state),
      reportPath,
      historyPath: localPath(flags.history ?? DEFAULT_MONITOR_PATHS.history),
      snapshotDirectory: localPath(flags.snapshots ?? DEFAULT_MONITOR_PATHS.snapshots),
    })
    : await readMonitorReport(reportPath);
  if (report.counts?.error > 0) {
    throw new Error("status build refused because one or more official-source observations failed");
  }
  const document = buildStatusDocument(report);
  const outputPath = localPath(flags.output ?? DEFAULT_STATUS_PATH);
  await writeStatusDocument(outputPath, document);
  console.log(`Generated ${outputPath} from observations at ${document.generatedAt}.`);
}

async function commandStatus(flags) {
  const document = await readStatusDocument(
    localPath(flags["status-data"] ?? DEFAULT_STATUS_PATH),
  );
  console.log(flags.json ? JSON.stringify(document, null, 2) : formatStatusDocument(document));
}

async function commandChangesBuild(flags) {
  const historyPath = localPath(flags.history ?? DEFAULT_MONITOR_PATHS.history);
  const localReports = await readMonitorHistory(historyPath);
  const evidenceReports = flags["evidence-history"]
    ? await readEvidenceMonitorReports({ evidenceRoot: localPath(flags["evidence-history"]) })
    : [];
  const reports = [...new Map(
    [...evidenceReports, ...localReports].map((report) => [report.checkedAt, report]),
  ).values()];
  const document = buildChangesDocument(reports);
  const outputPath = localPath(flags.output ?? DEFAULT_CHANGES_PATH);
  await writeChangesDocument(outputPath, document);
  console.log(`Generated ${outputPath} from ${document.observationCount} observations.`);
}

async function commandChanges(flags) {
  const document = await readChangesDocument(
    localPath(flags["changes-data"] ?? DEFAULT_CHANGES_PATH),
  );
  console.log(flags.json ? JSON.stringify(document, null, 2) : formatChangesDocument(document));
}

async function commandWebData(flags) {
  const statusOutput = flags["status-output"] ?? DEFAULT_STATUS_PATH;
  const changesOutput = flags["changes-output"] ?? DEFAULT_CHANGES_PATH;
  await commandStatusBuild({ ...flags, output: statusOutput });
  await commandChangesBuild({
    ...flags,
    output: changesOutput,
  });
  await commandPublishData({
    ...flags,
    "changes-data": changesOutput,
  });
}

async function commandPublishData(flags) {
  const result = await writePublicationData({
    reportPath: localPath(flags.report ?? DEFAULT_PUBLICATION_PATHS.report),
    changesPath: localPath(flags["changes-data"] ?? DEFAULT_PUBLICATION_PATHS.changes),
    trustRootsPath: localPath(flags["trust-config"] ?? DEFAULT_PUBLICATION_PATHS.trustRoots),
    sourcesPath: localPath(flags["sources-output"] ?? DEFAULT_PUBLICATION_PATHS.sources),
    feedPath: localPath(flags["feed-output"] ?? DEFAULT_PUBLICATION_PATHS.feed),
    siteUrl: flags["site-url"] ?? DEFAULT_PUBLIC_SITE_URL,
  });
  console.log(`Generated public source register with ${result.sources.monitoredSources.length} sources.`);
  console.log(`Generated Atom feed with ${result.sources.generatedAt} as the dataset timestamp.`);
}

function evidenceOptions(flags) {
  return {
    evidenceRoot: localPath(flags["evidence-root"] ?? DEFAULT_EVIDENCE_PATHS.root),
    reportPath: localPath(flags.report ?? DEFAULT_EVIDENCE_PATHS.report),
    statusPath: localPath(flags["status-data"] ?? DEFAULT_EVIDENCE_PATHS.status),
    changesPath: localPath(flags["changes-data"] ?? DEFAULT_EVIDENCE_PATHS.changes),
    trustRootsPath: localPath(flags["trust-config"] ?? DEFAULT_EVIDENCE_PATHS.trustRoots),
  };
}

async function commandAttestManifest(flags) {
  const options = evidenceOptions(flags);
  const result = await createObservationManifest(options);
  await writeProofDocument({
    evidenceRoot: options.evidenceRoot,
    proofPath: localPath(flags.proof ?? DEFAULT_EVIDENCE_PATHS.proof),
  });
  console.log(`${result.created ? "Created" : "Reused"} observation manifest #${result.manifest.sequence}.`);
  console.log(`JCS SHA-256: ${result.hash}`);
  console.log(`Public artifact: ${result.path}`);
}

async function commandAttestSign(flags) {
  if (!flags["acknowledge-reviewed-checkpoint"]) {
    throw new Error(
      "checkpoint signing blocked; review the latest manifest, then pass --acknowledge-reviewed-checkpoint",
    );
  }
  const options = evidenceOptions(flags);
  await verifyEvidence({ evidenceRoot: options.evidenceRoot });
  const keystorePath = localPath(flags.keystore ?? KEYSTORE_DEFAULT_PATH);
  const keystore = await readKeystore(keystorePath);
  const privateKey = await unlockPrivateKey(keystore, keystorePath);
  const result = await signReviewedCheckpoint({
    privateKey,
    reviewerDid: keystore.publicDid,
    evidenceRoot: options.evidenceRoot,
    manifestHash: flags.manifest,
  });
  await writeProofDocument({
    evidenceRoot: options.evidenceRoot,
    proofPath: localPath(flags.proof ?? DEFAULT_EVIDENCE_PATHS.proof),
  });
  console.log(`${result.created ? "Created" : "Reused"} reviewed checkpoint.`);
  console.log(`Reviewer DID: ${keystore.publicDid}`);
  console.log(`Attestation JCS SHA-256: ${result.hash}`);
  console.log("The private key and Keychain unlock secret were not written to the evidence artifacts.");
  console.log("No network write or on-chain transaction was performed.");
}

async function commandAttestVerify(flags) {
  const options = evidenceOptions(flags);
  const result = await verifyEvidence({ evidenceRoot: options.evidenceRoot });
  if (!flags["no-write"]) {
    await writeProofDocument({
      evidenceRoot: options.evidenceRoot,
      proofPath: localPath(flags.proof ?? DEFAULT_EVIDENCE_PATHS.proof),
    });
  }
  if (flags.json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  console.log("Evidence verification: PASS");
  console.log(`Manifests: ${result.manifestCount}; reviewed checkpoints: ${result.attestationCount}`);
  console.log(`Snapshot references: ${result.snapshotReferences}; artifact references: ${result.artifactReferences}`);
  console.log(`Latest manifest: ${result.latestManifest.hash}`);
  console.log(`Latest attestation: ${result.latestAttestation?.hash ?? "none"}`);
}

async function readCheckInput(flags) {
  const choices = [flags.input != null, flags.file != null].filter(Boolean).length;
  if (choices > 1) throw new Error("check accepts only one of --input or --file");
  let input;
  if (flags.input != null) {
    input = String(flags.input);
  } else if (flags.file != null) {
    input = await readFile(localPath(flags.file), "utf8");
  } else if (!process.stdin.isTTY) {
    input = await readFile(0, "utf8");
  } else {
    throw new Error("check requires --input, --file, or piped stdin");
  }
  if (Buffer.byteLength(input, "utf8") > 1024 * 1024) {
    throw new Error("check input exceeds the 1 MiB local limit");
  }
  return input;
}

async function commandCheck(flags) {
  const [trustModel, statusDocument, input] = await Promise.all([
    loadTrustModel(localPath(flags["trust-config"] ?? DEFAULT_TRUST_ROOTS_PATH)),
    readStatusDocument(localPath(flags["status-data"] ?? DEFAULT_STATUS_PATH)),
    readCheckInput(flags),
  ]);
  const result = analyzeClaim(input, { trustModel, statusDocument });
  console.log(flags.json ? JSON.stringify(result, null, 2) : formatClaimAnalysis(result));
}

async function commandIdentityInit(flags) {
  if (!flags["acknowledge-secret-generation"]) {
    throw new Error(
      "secret generation blocked; read SECURITY.md, then pass --acknowledge-secret-generation",
    );
  }
  const keystorePath = localPath(flags.keystore ?? KEYSTORE_DEFAULT_PATH);
  const first = await promptHidden("New keystore passphrase (12+ characters): ");
  const second = await promptHidden("Repeat passphrase: ");
  if (first !== second) throw new Error("passphrases did not match");
  const privateKey = generateIdentityPrivateKey();
  const keystore = encryptPrivateKey(privateKey, first);
  keystore.unlock = { provider: "interactive-passphrase" };
  await writeNewKeystore(keystorePath, keystore);
  console.log(`Created encrypted keystore: ${keystorePath}`);
  console.log(`Public DID: ${keystore.publicDid}`);
  console.log("No seed or private key was printed.");
}

async function commandIdentityInitKeychain(flags) {
  if (!flags["acknowledge-secret-generation-and-keychain-storage"]) {
    throw new Error(
      "Keychain-backed secret generation blocked; pass --acknowledge-secret-generation-and-keychain-storage",
    );
  }
  if (process.platform !== "darwin") {
    throw new Error("Keychain-backed identity generation is available only on macOS");
  }
  const keystorePath = localPath(flags.keystore ?? KEYSTORE_DEFAULT_PATH);
  const reference = keychainReferenceForKeystore(keystorePath);
  const unlockSecret = randomBytes(32).toString("base64url");
  const privateKey = generateIdentityPrivateKey();
  const keystore = encryptPrivateKey(privateKey, unlockSecret);
  keystore.unlock = reference;

  await storeKeychainSecret(reference, unlockSecret);
  try {
    await writeNewKeystore(keystorePath, keystore);
  } catch (error) {
    try {
      await deleteKeychainSecret(reference);
    } catch {
      // Preserve the original keystore-write error. The orphaned Keychain item
      // contains only an unlock key for a keystore that was never written.
    }
    throw error;
  }

  console.log(`Created encrypted keystore: ${keystorePath}`);
  console.log(`Stored its random unlock key in macOS Keychain: ${reference.service}`);
  console.log(`Public DID: ${keystore.publicDid}`);
  console.log("No seed, private key, or unlock secret was printed.");
}

async function commandIdentityShow(flags) {
  const keystorePath = localPath(flags.keystore ?? KEYSTORE_DEFAULT_PATH);
  const keystore = await readKeystore(keystorePath);
  console.log(keystore.publicDid);
}

async function unlockPrivateKey(keystore, keystorePath) {
  const passphrase = keystore.unlock?.provider === "macos-keychain"
    ? await loadKeychainSecret(keystore.unlock, keystorePath)
    : await promptHidden("Keystore passphrase: ");
  return decryptPrivateKey(keystore, passphrase);
}

async function commandSay(flags) {
  if (!flags.room || !flags.text) {
    throw new Error("say requires --room ROOM and --text TEXT");
  }
  const keystorePath = localPath(flags.keystore ?? KEYSTORE_DEFAULT_PATH);
  const noncePath = localPath(flags["nonce-state"] ?? ".local/nonces.json");
  const keystore = await readKeystore(keystorePath);
  const privateKey = await unlockPrivateKey(keystore, keystorePath);
  const nonceStore = new NonceStore(noncePath);
  const scope = `${keystore.publicDid}|room:${flags.room}`;
  const nonce = await nonceStore.next(scope);
  const payload = buildSignedMessage({
    privateKey,
    room: flags.room,
    nonce,
    text: flags.text,
  });

  if (!flags["execute-external-write"]) {
    console.log(JSON.stringify({
      mode: "preview-only",
      remoteWritePerformed: false,
      endpoint: `https://technocore.chat/r/${flags.room}`,
      method: "POST",
      body: {
        did: payload.did,
        sig: payload.sig,
        nonce: payload.nonce,
        text: payload.text,
      },
    }, null, 2));
    return;
  }

  const result = await sendSignedMessage({
    payload,
    room: flags.room,
    executeExternalWrite: true,
  });
  await nonceStore.record(scope, nonce);
  console.log(`Technocore accepted the signed POST (HTTP ${result.status}).`);
}

async function writeJsonAtomic(filePath, value) {
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.tmp-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await rename(temporary, filePath);
}

async function loadOrPrepareProfile(profilePath, did) {
  try {
    const existing = JSON.parse(await readFile(profilePath, "utf8"));
    if (existing.version !== 1 || existing.did !== did) {
      throw new Error("local profile state does not match this DID");
    }
    if (existing.status === "checked-in") {
      throw new Error("this DID has already completed its one-time check-in");
    }
    return existing;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const location = didProfileLocation(did);
  const profile = {
    version: 1,
    status: "prepared",
    did,
    mailbox: createMailboxName(),
    profilePath: location.path,
    namespace: location.namespace,
    key: location.key,
    preparedAt: new Date().toISOString(),
  };
  await writeJsonAtomic(profilePath, profile);
  return profile;
}

async function commandCheckIn(flags) {
  if (!flags["execute-external-write"]) {
    throw new Error("check-in performs two public writes; pass --execute-external-write");
  }
  const keystorePath = localPath(flags.keystore ?? KEYSTORE_DEFAULT_PATH);
  const profilePath = localPath(flags["profile-state"] ?? ".local/profile.json");
  const noncePath = localPath(flags["nonce-state"] ?? ".local/nonces.json");
  const keystore = await readKeystore(keystorePath);
  const privateKey = await unlockPrivateKey(keystore, keystorePath);
  const profile = await loadOrPrepareProfile(profilePath, keystore.publicDid);
  const profileValue = buildPublicProfile({
    did: keystore.publicDid,
    mailbox: profile.mailbox,
  });
  const checkInText = [
    "check-in: FLOP testnet preparation agent online;",
    `profile=${profile.profilePath};`,
    "capabilities=official-source monitoring and Technocore client testing;",
    "no faucet/token claim attempted.",
  ].join(" ");
  const nonceStore = new NonceStore(noncePath);
  const scope = `${keystore.publicDid}|room:lobby`;
  const nonce = await nonceStore.next(scope);
  const signedMessage = buildSignedMessage({
    privateKey,
    room: "lobby",
    nonce,
    text: checkInText,
  });

  const noteResult = await setPublicNote({
    namespace: profile.namespace,
    key: profile.key,
    value: profileValue,
    executeExternalWrite: true,
  });
  const messageResult = await sendSignedMessage({
    payload: signedMessage,
    room: "lobby",
    executeExternalWrite: true,
  });
  await nonceStore.record(scope, nonce);
  const completed = {
    ...profile,
    status: "checked-in",
    profileValue,
    checkInRoom: "lobby",
    checkInNonce: nonce,
    checkInText,
    checkedInAt: new Date().toISOString(),
    httpStatus: {
      profileNote: noteResult.status,
      signedMessage: messageResult.status,
    },
  };
  await writeJsonAtomic(profilePath, completed);
  console.log(JSON.stringify({
    did: completed.did,
    profilePath: completed.profilePath,
    mailbox: completed.mailbox,
    checkInRoom: completed.checkInRoom,
    checkInNonce: completed.checkInNonce,
    checkInText: completed.checkInText,
    httpStatus: completed.httpStatus,
    externalWritesPerformed: 2,
  }, null, 2));
}

async function main() {
  const { positional, flags } = parseArguments(process.argv.slice(2));
  if (flags.help) {
    console.log(HELP);
    return;
  }
  const command = positional[0] ?? "help";
  if (positional.length > 1) throw new Error("unexpected positional arguments");

  switch (command) {
    case "help":
      console.log(HELP);
      break;
    case "monitor":
      await commandMonitor(flags);
      break;
    case "monitor:bootstrap":
      await commandMonitorBootstrap(flags);
      break;
    case "env:check":
      await commandEnvironment(flags);
      break;
    case "status:build":
      await commandStatusBuild(flags);
      break;
    case "status":
      await commandStatus(flags);
      break;
    case "changes:build":
      await commandChangesBuild(flags);
      break;
    case "changes":
      await commandChanges(flags);
      break;
    case "web:data":
      await commandWebData(flags);
      break;
    case "publish:data":
      await commandPublishData(flags);
      break;
    case "attest:manifest":
      await commandAttestManifest(flags);
      break;
    case "attest:sign":
      await commandAttestSign(flags);
      break;
    case "attest:verify":
      await commandAttestVerify(flags);
      break;
    case "check":
      await commandCheck(flags);
      break;
    case "identity:init":
      await commandIdentityInit(flags);
      break;
    case "identity:init-keychain":
      await commandIdentityInitKeychain(flags);
      break;
    case "identity:show":
      await commandIdentityShow(flags);
      break;
    case "say":
      await commandSay(flags);
      break;
    case "checkin":
      await commandCheckIn(flags);
      break;
    default:
      throw new Error(`unknown command: ${command}\n\n${HELP}`);
  }
}

main().catch((error) => {
  console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
