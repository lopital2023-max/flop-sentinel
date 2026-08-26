import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import path from "node:path";

export const KEYCHAIN_SERVICE = "flop-technocore-agent-keystore-v1";
const SECURITY_TOOL = "/usr/bin/security";
const OUTPUT_LIMIT = 64 * 1024;

function runSecurity(argumentsList, { captureStdout = false, input = null } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(SECURITY_TOOL, argumentsList, {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let stdoutLength = 0;
    let stderrLength = 0;

    child.stdout.on("data", (chunk) => {
      stdoutLength += chunk.length;
      if (stdoutLength <= OUTPUT_LIMIT) stdout.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk) => {
      stderrLength += chunk.length;
      if (stderrLength <= OUTPUT_LIMIT) stderr.push(Buffer.from(chunk));
    });
    child.once("error", () => reject(new Error("could not start macOS Keychain tool")));
    child.once("close", (code) => {
      if (code !== 0) {
        // Do not include the command or arguments in errors.
        reject(new Error(`macOS Keychain operation failed with exit code ${code}`));
        return;
      }
      resolve(captureStdout ? Buffer.concat(stdout).toString("utf8") : "");
    });
    child.stdin.end(input == null ? undefined : input);
  });
}

export function keychainReferenceForKeystore(keystorePath) {
  const absolute = path.resolve(keystorePath);
  const digest = createHash("sha256").update(absolute, "utf8").digest("hex");
  return {
    provider: "macos-keychain",
    service: KEYCHAIN_SERVICE,
    account: `keystore-${digest.slice(0, 32)}`,
  };
}

function validateKeychainReferenceShape(reference) {
  if (
    reference?.provider !== "macos-keychain" ||
    reference.service !== KEYCHAIN_SERVICE ||
    !/^keystore-[a-f0-9]{32}$/.test(reference.account ?? "")
  ) {
    throw new Error("invalid Keychain reference shape");
  }
  return reference;
}

export function validateKeychainReference(reference, keystorePath) {
  validateKeychainReferenceShape(reference);
  const expected = keychainReferenceForKeystore(keystorePath);
  if (
    reference?.provider !== expected.provider ||
    reference?.service !== expected.service ||
    reference?.account !== expected.account
  ) {
    throw new Error("keystore contains an unexpected Keychain reference");
  }
  return expected;
}

export async function storeKeychainSecret(reference, secret) {
  validateKeychainReferenceShape(reference);
  if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) {
    throw new Error("Keychain unlock secret must be a 32-byte base64url value");
  }
  await runSecurity([
    "add-generic-password",
    "-a",
    reference.account,
    "-s",
    reference.service,
    "-l",
    "FLOP Technocore DID keystore unlock key",
    // Keeping -w last makes /usr/bin/security prompt for the value. Feeding
    // that prompt through stdin keeps the random secret out of argv.
    "-w",
  ], { input: `${secret}\n` });
}

export async function loadKeychainSecret(reference, keystorePath) {
  const checked = validateKeychainReference(reference, keystorePath);
  const secret = (await runSecurity([
    "find-generic-password",
    "-a",
    checked.account,
    "-s",
    checked.service,
    "-w",
  ], { captureStdout: true })).replace(/[\r\n]+$/g, "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(secret)) {
    throw new Error("macOS Keychain returned an invalid unlock secret");
  }
  return secret;
}

export async function deleteKeychainSecret(reference) {
  validateKeychainReferenceShape(reference);
  await runSecurity([
    "delete-generic-password",
    "-a",
    reference.account,
    "-s",
    reference.service,
  ]);
}
