import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import {
  inspectEnvironment,
  REQUIRED_NODE_MAJOR,
  REQUIRED_NODE_MINOR,
} from "../src/environment.mjs";

test("local project environment satisfies the documented baseline", async () => {
  const report = await inspectEnvironment(path.resolve(import.meta.dirname, ".."));
  const [major, minor] = report.node.split(".").map(Number);
  assert.ok(major > REQUIRED_NODE_MAJOR || (major === REQUIRED_NODE_MAJOR && minor >= REQUIRED_NODE_MINOR));
  assert.equal(major % 2, 0);
  assert.equal(report.runtimeDependenciesRequired, false);
  assert.equal(report.ok, true);
});
