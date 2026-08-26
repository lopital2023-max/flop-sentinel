import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import test from "node:test";
import { privateKeyFromSeed } from "../src/identity.mjs";
import {
  assertOfficialTechnocoreEndpoint,
  buildPublicProfile,
  buildSignedMessage,
  didProfileLocation,
  sendSignedMessage,
  setPublicNote,
  sweepText,
} from "../src/technocore.mjs";

const FIXTURE_KEY = privateKeyFromSeed(Buffer.alloc(32, 7));

test("applies Technocore's single-line sweep before signing", () => {
  assert.equal(sweepText("  hello\nworld\u200b!  "), "hello world !");
  assert.throws(() => sweepText("\n\u200b"), /nothing visible/);
});

test("builds a verifiable 86-character Ed25519 signature", () => {
  const payload = buildSignedMessage({
    privateKey: FIXTURE_KEY,
    room: "lobby",
    nonce: "1720000000000",
    text: "fixture message\nnot sent",
  });
  assert.equal(payload.sig.length, 86);
  assert.equal(payload.canonical, "lobby|1720000000000|fixture message not sent");
  assert.equal(
    verify(
      null,
      Buffer.from(payload.canonical),
      createPublicKey(FIXTURE_KEY),
      Buffer.from(payload.sig, "base64url"),
    ),
    true,
  );
});

test("blocks remote writes unless explicitly acknowledged", async () => {
  const payload = buildSignedMessage({
    privateKey: FIXTURE_KEY,
    room: "lobby",
    nonce: "1720000000001",
    text: "fixture only",
  });
  await assert.rejects(
    () => sendSignedMessage({ payload, room: "lobby" }),
    /external write blocked/,
  );
  assert.throws(
    () => assertOfficialTechnocoreEndpoint("https://example.com/"),
    /pinned/,
  );
  for (const disguised of [
    "https://attacker@technocore.chat/",
    "https://technocore.chat/?next=https://evil.example",
    "https://technocore.chat/#override",
  ]) {
    assert.throws(() => assertOfficialTechnocoreEndpoint(disguised), /pinned/);
  }
});

test("uses a JSON POST for an acknowledged write (mock transport only)", async () => {
  const payload = buildSignedMessage({
    privateKey: FIXTURE_KEY,
    room: "lobby",
    nonce: "1720000000002",
    text: "fixture only",
  });
  let captured;
  const fakeFetch = async (url, options) => {
    captured = { url, options };
    return {
      ok: true,
      status: 200,
      text: async () => "mock accepted",
    };
  };
  const result = await sendSignedMessage({
    payload,
    room: "lobby",
    executeExternalWrite: true,
    fetchImpl: fakeFetch,
  });
  assert.equal(captured.url, "https://technocore.chat/r/lobby");
  assert.equal(captured.options.method, "POST");
  assert.deepEqual(JSON.parse(captured.options.body), {
    did: payload.did,
    sig: payload.sig,
    nonce: payload.nonce,
    text: payload.text,
  });
  assert.deepEqual(result, { status: 200 });
});

test("refuses a locally tampered payload before transport", async () => {
  const payload = buildSignedMessage({
    privateKey: FIXTURE_KEY,
    room: "lobby",
    nonce: "1720000000003",
    text: "original fixture",
  });
  let called = false;
  await assert.rejects(
    () => sendSignedMessage({
      payload: { ...payload, text: "tampered fixture" },
      room: "lobby",
      executeExternalWrite: true,
      fetchImpl: async () => {
        called = true;
      },
    }),
    /does not verify/,
  );
  assert.equal(called, false);
});

test("derives the sharded DID-note path and builds a public profile", () => {
  const payload = buildSignedMessage({
    privateKey: FIXTURE_KEY,
    room: "lobby",
    nonce: "1720000000004",
    text: "fixture",
  });
  const location = didProfileLocation(payload.did);
  assert.match(location.path, /^\/kv\/did-[0-9a-f]{2}\/[0-9a-f]{14}$/);
  assert.equal(
    buildPublicProfile({ did: payload.did, mailbox: "mb-p-0123456789abcdef" }),
    `${payload.did} mailbox:mb-p-0123456789abcdef label:flop-local-agent`,
  );
});

test("publishes a DID profile as a JSON POST only with acknowledgement (mock only)", async () => {
  let captured;
  const fakeFetch = async (url, options) => {
    captured = { url, options };
    return { ok: true, status: 200 };
  };
  await assert.rejects(
    () => setPublicNote({ namespace: "did-aa", key: "0123456789abcd", value: "fixture" }),
    /external note write blocked/,
  );
  const result = await setPublicNote({
    namespace: "did-aa",
    key: "0123456789abcd",
    value: "fixture",
    executeExternalWrite: true,
    fetchImpl: fakeFetch,
  });
  assert.equal(captured.url, "https://technocore.chat/kv/did-aa/0123456789abcd");
  assert.equal(captured.options.method, "POST");
  assert.deepEqual(JSON.parse(captured.options.body), { value: "fixture" });
  assert.deepEqual(result, { status: 200 });
});
