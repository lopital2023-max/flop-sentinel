import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(process.cwd(), "dist");
const pages = ["index.html", "verify/index.html", "changes/index.html", "proof/index.html", "methodology/index.html"];
const baseSegment = String(process.env.BASE_PATH ?? "/").replace(/^\/+|\/+$/gu, "");
const expectedPrefix = `/${baseSegment ? `${baseSegment}/` : ""}`;

for (const page of pages) {
  const contents = await readFile(path.join(root, page), "utf8");
  assert.match(contents, /<title>[^<]+<\/title>/, `${page} must have a title`);
  assert.match(contents, /data-set-language="ja"/, `${page} must include language controls`);
  assert.match(contents, /http-equiv="Content-Security-Policy"/, `${page} must include a CSP meta fallback`);
  assert.doesNotMatch(contents, /<style(?:\s|>)/i, `${page} must not use inline style blocks`);
  const scripts = [...contents.matchAll(/<script\b([^>]*)>/gi)];
  for (const script of scripts) {
    assert.match(script[1], /\bsrc="[^"]+"/, `${page} contains an inline script`);
  }
  const escapedPrefix = expectedPrefix.replaceAll("/", "\\/");
  const assetPattern = new RegExp(`(?:src|href)="(${escapedPrefix}assets\\/[^\"]+)"`, "g");
  for (const assetPath of [...contents.matchAll(assetPattern)].map((match) => match[1])) {
    await access(path.join(root, assetPath.slice(expectedPrefix.length)));
  }
}

const status = JSON.parse(await readFile(path.join(root, "status.json"), "utf8"));
const changes = JSON.parse(await readFile(path.join(root, "changes.json"), "utf8"));
const proof = JSON.parse(await readFile(path.join(root, "proof.json"), "utf8"));
const sources = JSON.parse(await readFile(path.join(root, "sources.json"), "utf8"));
const verdictSchema = JSON.parse(await readFile(path.join(root, "verdict-schema.json"), "utf8"));
assert.equal(status.schemaVersion, 1);
assert.equal(changes.schemaVersion, 1);
assert.equal(proof.schemaVersion, 1);
assert.equal(proof.verification.ok, true);
assert.equal(sources.type, "flop-sentinel-source-register");
assert.equal(sources.monitoredSources.length, 4);
assert.equal(verdictSchema.$schema, "https://json-schema.org/draft/2020-12/schema");
await access(path.join(root, proof.latest.manifest.path));
await access(path.join(root, proof.latest.attestation.path));
for (const source of sources.monitoredSources) await access(path.join(root, source.raw.path));
assert.match(await readFile(path.join(root, "feed.xml"), "utf8"), /<feed xmlns="http:\/\/www\.w3\.org\/2005\/Atom">/);

const headers = await readFile(path.join(root, "_headers"), "utf8");
assert.match(headers, /Content-Security-Policy:/);
assert.doesNotMatch(headers, /script-src[^\n]*'unsafe-inline'/);
assert.match(headers, /frame-ancestors 'none'/);
assert.match(headers, /form-action 'none'/);

for (const file of ["index.html", "proof.json", "sources.json"]) {
  const contents = await readFile(path.join(root, file), "utf8");
  assert.doesNotMatch(contents, /identity\.keystore|BEGIN PRIVATE|flop-technocore-agent-keystore|\/Users\//u);
}

console.log(`Verified ${pages.length} static pages, assets, public APIs, evidence, and CSP policy.`);
