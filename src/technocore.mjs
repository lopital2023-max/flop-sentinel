import { createHash, randomBytes, sign, verify } from "node:crypto";
import { didFromKey, isTechnocoreDid, publicKeyFromDid } from "./identity.mjs";

const ROOM_PATTERN = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const INVISIBLE_OR_CONTROL = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;
const OFFICIAL_ENDPOINT = "https://technocore.chat";

export function sweepText(text, limit = 4096) {
  if (typeof text !== "string") throw new TypeError("text must be a string");
  const cleaned = text.replace(INVISIBLE_OR_CONTROL, " ").trim();
  if (!cleaned) {
    throw new Error("nothing visible remains after Technocore's single-line sweep");
  }
  if ([...cleaned].length > limit) {
    throw new Error(`text exceeds Technocore's ${limit}-character limit`);
  }
  return cleaned;
}

export function validateRoom(room) {
  if (!ROOM_PATTERN.test(room)) {
    throw new Error("room must match ^[a-z0-9][a-z0-9_-]{0,47}$");
  }
  return room;
}

export function validateNonce(nonce) {
  const value = String(nonce);
  if (!/^[0-9]{1,19}$/.test(value)) {
    throw new Error("nonce must contain 1-19 ASCII digits");
  }
  return value;
}

export function buildSignedMessage({ privateKey, room, nonce, text }) {
  const safeRoom = validateRoom(room);
  const safeNonce = validateNonce(nonce);
  const safeText = sweepText(text);
  const did = didFromKey(privateKey);
  const canonical = `${safeRoom}|${safeNonce}|${safeText}`;
  const signature = sign(null, Buffer.from(canonical, "utf8"), privateKey).toString(
    "base64url",
  );
  if (signature.length !== 86) {
    throw new Error("unexpected Ed25519 signature length");
  }
  return {
    did,
    sig: signature,
    nonce: safeNonce,
    text: safeText,
    canonical,
  };
}

export function assertOfficialTechnocoreEndpoint(endpoint) {
  const parsed = new URL(endpoint);
  if (
    parsed.origin !== OFFICIAL_ENDPOINT ||
    parsed.pathname !== "/" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(`external writes are pinned to ${OFFICIAL_ENDPOINT}`);
  }
  return parsed.origin;
}

export function didProfileLocation(did) {
  if (!isTechnocoreDid(did)) throw new Error("invalid Technocore DID");
  const fingerprint = createHash("sha256").update(did, "utf8").digest("hex").slice(0, 16);
  return {
    fingerprint,
    namespace: `did-${fingerprint.slice(0, 2)}`,
    key: fingerprint.slice(2),
    path: `/kv/did-${fingerprint.slice(0, 2)}/${fingerprint.slice(2)}`,
  };
}

export function createMailboxName() {
  return `mb-p-${randomBytes(16).toString("hex")}`;
}

export function buildPublicProfile({ did, mailbox }) {
  if (!isTechnocoreDid(did)) throw new Error("invalid Technocore DID");
  validateRoom(mailbox);
  if (!mailbox.startsWith("mb-p-")) {
    throw new Error("profile mailbox must use the signed, unlisted mb-p- class");
  }
  return `${did} mailbox:${mailbox} label:flop-local-agent`;
}

async function discardResponseBody(response) {
  if (response.body?.cancel) await response.body.cancel();
}

async function readBoundedResponseText(response, maxBytes = 1024 * 1024) {
  const declaredLength = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    await discardResponseBody(response);
    return null;
  }

  if (typeof response.body?.getReader === "function") {
    const reader = response.body.getReader();
    const chunks = [];
    let receivedBytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      receivedBytes += value.byteLength;
      if (receivedBytes > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, receivedBytes).toString("utf8");
  }

  if (typeof response.text !== "function") {
    await discardResponseBody(response);
    return null;
  }

  const body = await response.text();
  if (Buffer.byteLength(body, "utf8") > maxBytes) return null;
  return body;
}

async function extractSignedMessageReceipt(response, { payload, room }) {
  const contentType = response.headers?.get?.("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    await discardResponseBody(response);
    return null;
  }

  const rawBody = await readBoundedResponseText(response);
  if (rawBody === null) return null;

  let envelope;
  try {
    envelope = JSON.parse(rawBody);
  } catch {
    return null;
  }

  if (envelope?.room !== room || !Array.isArray(envelope.messages)) return null;
  const matches = envelope.messages.filter((message) => (
    message?.from === payload.did
    && String(message?.nonce) === payload.nonce
    && message?.text === payload.text
    && Number.isSafeInteger(message?.seq)
    && message.seq >= 0
    && typeof message?.ts === "string"
  ));
  if (matches.length !== 1) return null;

  const [message] = matches;
  return {
    room,
    seq: message.seq,
    ts: message.ts,
    from: message.from,
    nonce: payload.nonce,
    text: message.text,
  };
}

export async function setPublicNote({
  namespace,
  key,
  value,
  executeExternalWrite = false,
  endpoint = OFFICIAL_ENDPOINT,
  fetchImpl = globalThis.fetch,
}) {
  if (!executeExternalWrite) {
    throw new Error("external note write blocked: pass the explicit execution acknowledgement");
  }
  if (!ROOM_PATTERN.test(namespace) || !ROOM_PATTERN.test(key)) {
    throw new Error("note namespace/key must match Technocore's name pattern");
  }
  const safeValue = sweepText(value, 8192);
  const origin = assertOfficialTechnocoreEndpoint(endpoint);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetchImpl(`${origin}/kv/${namespace}/${key}`, {
      method: "POST",
      redirect: "error",
      signal: controller.signal,
      headers: { "content-type": "application/json", accept: "text/plain" },
      body: JSON.stringify({ value: safeValue }),
    });
    await discardResponseBody(response);
    if (!response.ok) throw new Error(`Technocore note write failed (HTTP ${response.status})`);
    return { status: response.status };
  } finally {
    clearTimeout(timeout);
  }
}

export async function sendSignedMessage({
  payload,
  room,
  executeExternalWrite = false,
  endpoint = OFFICIAL_ENDPOINT,
  fetchImpl = globalThis.fetch,
}) {
  if (!executeExternalWrite) {
    throw new Error(
      "external write blocked: pass the explicit execution acknowledgement",
    );
  }
  validateRoom(room);
  if (!isTechnocoreDid(payload?.did)) throw new Error("payload DID is invalid");
  validateNonce(payload?.nonce);
  sweepText(payload?.text);
  if (!/^[A-Za-z0-9_-]{86}$/.test(payload?.sig ?? "")) {
    throw new Error("payload signature is invalid");
  }
  const canonical = `${room}|${payload.nonce}|${payload.text}`;
  if (!verify(
    null,
    Buffer.from(canonical, "utf8"),
    publicKeyFromDid(payload.did),
    Buffer.from(payload.sig, "base64url"),
  )) {
    throw new Error("payload signature does not verify for this room and text");
  }

  const origin = assertOfficialTechnocoreEndpoint(endpoint);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetchImpl(`${origin}/r/${room}`, {
      method: "POST",
      redirect: "error",
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        did: payload.did,
        sig: payload.sig,
        nonce: payload.nonce,
        text: payload.text,
      }),
    });
    if (!response.ok) {
      await discardResponseBody(response);
      throw new Error(`Technocore write failed (HTTP ${response.status})`);
    }
    const receipt = await extractSignedMessageReceipt(response, { payload, room });
    return { status: response.status, receipt };
  } finally {
    clearTimeout(timeout);
  }
}

export const TECHNOCORE_OFFICIAL_ENDPOINT = OFFICIAL_ENDPOINT;
