import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";

const projectRoot = path.resolve(import.meta.dirname, "..");

test("identity generation refuses to start without the acknowledgement flag", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs", "identity:init"], {
    cwd: projectRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /secret generation blocked/);
});

test("help documents the remote-write safety boundary", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs", "help"], {
    cwd: projectRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /preview-only/);
  assert.match(result.stdout, /--execute-external-write/);
});

test("check-in refuses before reading a key unless public writes are acknowledged", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs", "checkin"], {
    cwd: projectRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /performs two public writes/);
});

test("Keychain identity generation has its own explicit acknowledgement", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs", "identity:init-keychain"], {
    cwd: projectRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Keychain-backed secret generation blocked/);
});

test("reviewed checkpoint signing refuses before reading a key without acknowledgement", () => {
  const result = spawnSync(process.execPath, ["src/cli.mjs", "attest:sign"], {
    cwd: projectRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /checkpoint signing blocked/);
});
