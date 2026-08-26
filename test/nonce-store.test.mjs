import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { NonceStore } from "../src/nonce-store.mjs";

test("keeps each room/key nonce strictly increasing", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "flop-nonce-test-"));
  try {
    const store = new NonceStore(path.join(directory, "nonces.json"));
    assert.equal(await store.next("did|room:lobby", 1000), "1000");
    await store.record("did|room:lobby", "1000");
    assert.equal(await store.next("did|room:lobby", 999), "1001");
    await assert.rejects(
      () => store.record("did|room:lobby", "1000"),
      /move nonce backwards/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
