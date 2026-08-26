#!/usr/bin/env node

import assert from "node:assert/strict";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const excludedDirectories = new Set([".git", ".local", ".astro", "dist", "node_modules"]);

async function filesUnder(relativeDirectory) {
  const results = [];
  async function visit(relativePath) {
    const absolute = path.join(root, relativePath);
    const entries = await readdir(absolute, { withFileTypes: true });
    for (const entry of entries) {
      const child = path.join(relativePath, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`publishable tree contains a symlink: ${child}`);
      if (entry.isDirectory()) {
        if (!excludedDirectories.has(entry.name)) await visit(child);
      } else if (entry.isFile()) {
        results.push(child);
      }
    }
  }
  await visit(relativeDirectory);
  return results;
}

const sourceFiles = (await filesUnder("src")).filter((file) => /\.(?:mjs|astro)$/u.test(file));
const sourceContents = new Map(
  await Promise.all(sourceFiles.map(async (file) => [file, await readFile(path.join(root, file), "utf8")])),
);

for (const [file, contents] of sourceContents) {
  assert.doesNotMatch(contents, /\beval\s*\(|new\s+Function\s*\(|shell\s*:\s*true/u, `${file} exposes dynamic code or shell execution`);
  assert.doesNotMatch(contents, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|set:html/u, `${file} exposes unsafe HTML insertion`);
}

const childProcessUsers = [...sourceContents]
  .filter(([, contents]) => /node:child_process/u.test(contents))
  .map(([file]) => file);
assert.deepEqual(childProcessUsers, ["src/keychain.mjs"]);
const keychain = sourceContents.get("src/keychain.mjs");
assert.match(keychain, /const SECURITY_TOOL = "\/usr\/bin\/security"/u);
assert.match(keychain, /spawn\(SECURITY_TOOL, argumentsList/u);
assert.doesNotMatch(keychain, /spawn\([^S]|exec(?:File|Sync)?\s*\(/u);

const monitor = sourceContents.get("src/monitor.mjs");
for (const url of [
  "https://technocore.chat/openapi.json",
  "https://technocore.chat/auth.md",
  "https://flop.finance/",
  "https://api.github.com/orgs/flop-labs/repos?per_page=100&type=public",
]) {
  assert.ok(monitor.includes(`"${url}"`), `monitor allowlist is missing ${url}`);
}
assert.match(monitor, /OFFICIAL_SOURCE_URLS\.has\(source\.url\)/u);
assert.match(monitor, /REDIRECT_HOSTS\.has\(current\.hostname\)/u);

const packageDocument = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
for (const [name, command] of Object.entries(packageDocument.scripts)) {
  assert.doesNotMatch(command, /\b(?:curl|wget|sudo|npx|bash|sh|zsh|rm)\b|eval|\$\(/u, `unsafe package script ${name}`);
}

const gitignore = await readFile(path.join(root, ".gitignore"), "utf8");
for (const ignored of [".local/", "*.keystore.json", "*.pem", "*.key", ".env*", "node_modules/", "dist/", ".astro/"]) {
  assert.ok(gitignore.split("\n").includes(ignored), `.gitignore is missing ${ignored}`);
}

const publicFiles = await filesUnder("public");
for (const file of publicFiles) {
  const stats = await lstat(path.join(root, file));
  assert.equal(stats.mode & 0o022, 0, `${file} is group/world writable`);
  assert.doesNotMatch(file, /(?:^|\/)(?:\.env|.*\.key|.*\.pem|.*keystore.*)(?:$|\.)/iu);
  const contents = await readFile(path.join(root, file));
  assert.doesNotMatch(
    contents.toString("utf8"),
    /flop-technocore-agent-keystore-v1|identity\.keystore|BEGIN (?:PRIVATE|OPENSSH) KEY|\/Users\/kaiwa/u,
    `${file} contains local secret metadata`,
  );
}

for (const file of publicFiles.filter((name) => name.includes("/evidence/snapshots/"))) {
  assert.match(file, /^public\/evidence\/snapshots\/[a-f0-9]{64}\.snapshot$/u);
}

const workflowDirectory = path.join(root, ".github", "workflows");
let workflowFiles = [];
try {
  workflowFiles = (await readdir(workflowDirectory)).filter((file) => /\.ya?ml$/u.test(file));
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}
for (const file of workflowFiles) {
  const contents = await readFile(path.join(workflowDirectory, file), "utf8");
  assert.doesNotMatch(contents, /pull_request_target|secrets\.|\beval\b|\bcurl\b|\bwget\b/u, `${file} has a high-risk workflow construct`);
  for (const match of contents.matchAll(/^\s*-\s+uses:\s*([^\s#]+)(?:\s+#.*)?$/gmu)) {
    assert.match(match[1], /^actions\/[a-z0-9-]+@[a-f0-9]{40}$/u, `${file} action is not pinned to a full SHA`);
  }
}

console.log(`Security audit passed: ${sourceFiles.length} source files, ${publicFiles.length} public files, ${workflowFiles.length} workflows.`);
