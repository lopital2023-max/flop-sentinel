// Real-browser E2E. Kept outside test/ so the default unit suite stays hermetic.
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";

const debugOrigin = process.env.FLOP_CHROME_DEBUG_URL ?? "http://127.0.0.1:9222";
const siteOrigin = process.env.FLOP_SITE_URL ?? "http://127.0.0.1:4321";

async function createTarget(url) {
  const response = await fetch(`${debugOrigin}/json/new?${encodeURIComponent(url)}`, { method: "PUT" });
  if (!response.ok) throw new Error(`Chrome target creation failed: HTTP ${response.status}`);
  return response.json();
}

class CdpClient {
  constructor(webSocketUrl) {
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
    this.socket = new WebSocket(webSocketUrl);
  }

  async connect() {
    await new Promise((resolve, reject) => {
      this.socket.addEventListener("open", resolve, { once: true });
      this.socket.addEventListener("error", reject, { once: true });
    });
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
        return;
      }
      for (const listener of this.listeners.get(message.method) ?? []) listener(message.params);
    });
  }

  send(method, params = {}) {
    const id = this.nextId;
    this.nextId += 1;
    this.socket.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }

  on(method, listener) {
    const listeners = this.listeners.get(method) ?? [];
    listeners.push(listener);
    this.listeners.set(method, listeners);
  }

  close() {
    this.socket.close();
  }
}

async function evaluate(client, expression) {
  const response = await client.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (response.exceptionDetails) {
    throw new Error(response.exceptionDetails.exception?.description ?? "browser evaluation failed");
  }
  return response.result.value;
}

async function waitFor(client, expression, label) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (await evaluate(client, expression)) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timed out waiting for ${label}`);
}

async function submitClaim(client, value) {
  await evaluate(client, `(() => {
    const input = document.querySelector('#claim-input');
    input.value = ${JSON.stringify(value)};
    input.dispatchEvent(new Event('input', { bubbles: true }));
    document.querySelector('#verify-form').requestSubmit();
    return true;
  })()`);
  await waitFor(
    client,
    `!document.querySelector('#result-content').hidden && !document.querySelector('#analyze-button').disabled`,
    "claim verdict",
  );
  return evaluate(client, `({
    verdict: document.querySelector('#verdict-banner').dataset.verdict,
    reasons: [...document.querySelectorAll('#indicator-list strong')].map((item) => item.textContent),
    hash: document.querySelector('#result-dataset').textContent,
  })`);
}

const target = await createTarget(`${siteOrigin}/verify/`);
const client = new CdpClient(target.webSocketDebuggerUrl);
await client.connect();
const exceptions = [];
const requestedUrls = [];
client.on("Runtime.exceptionThrown", (details) => exceptions.push(details));
client.on("Network.requestWillBeSent", (details) => requestedUrls.push(details.request.url));
await Promise.all([
  client.send("Runtime.enable"),
  client.send("Network.enable"),
  client.send("Page.enable"),
]);

try {
  await client.send("Page.navigate", { url: `${siteOrigin}/verify/` });
  await waitFor(
    client,
    `document.readyState === 'complete' && !document.querySelector('#analyze-button').disabled`,
    "status dataset",
  );

  const official = await submitClaim(client, "https://flop.finance/");
  assert.equal(official.verdict, "VERIFIED_OFFICIAL_ROOT");
  assert.match(official.hash, /SHA-256 [a-f0-9]{64}$/);

  const userContent = await submitClaim(client, "https://technocore.chat/r/lobby");
  assert.equal(userContent.verdict, "UNVERIFIED");
  assert.ok(userContent.reasons.some((reason) => reason.includes("USER_WRITABLE_OFFICIAL_SERVICE")));

  const maliciousUrl = "https://flop.finance.evil.invalid/claim";
  const malicious = await submitClaim(client, `Claim FLOP at ${maliciousUrl} and enter your seed phrase`);
  assert.equal(malicious.verdict, "HIGH_RISK_PATTERN");
  assert.ok(malicious.reasons.some((reason) => reason.includes("EMBEDDED_OFFICIAL_HOSTNAME")));
  assert.ok(malicious.reasons.some((reason) => reason.includes("SECRET_MATERIAL_REQUEST")));
  assert.ok(!requestedUrls.some((url) => url.startsWith(maliciousUrl)), "submitted URL was fetched");

  assert.equal(await evaluate(client, "document.documentElement.lang"), "en");
  assert.equal(await evaluate(client, "document.querySelector('#verdict-title').textContent"), "High-risk pattern");
  assert.equal(
    await evaluate(client, `!/[\\p{Script=Hiragana}\\p{Script=Katakana}\\p{Script=Han}]/u.test(document.body.innerText)`),
    true,
    "verifier rendered non-English public copy",
  );

  await client.send("Emulation.setDeviceMetricsOverride", {
    width: 375,
    height: 812,
    deviceScaleFactor: 2,
    mobile: true,
  });
  assert.equal(
    await evaluate(client, "document.documentElement.scrollWidth <= window.innerWidth + 1"),
    true,
    "mobile layout has horizontal page overflow",
  );
  const mobileBounds = await evaluate(client, `({
    viewport: window.innerWidth,
    elements: ['.site-header', '.page-intro', '.verifier-layout', '.verify-panel', '#claim-input', '.result-panel']
      .map((selector) => {
        const rect = document.querySelector(selector).getBoundingClientRect();
        return { selector, left: rect.left, right: rect.right, width: rect.width };
      }),
  })`);
  for (const bounds of mobileBounds.elements) {
    assert.ok(bounds.left >= -1, `${bounds.selector} starts outside the mobile viewport: ${JSON.stringify(mobileBounds)}`);
    assert.ok(bounds.right <= mobileBounds.viewport + 1, `${bounds.selector} exceeds the mobile viewport: ${JSON.stringify(mobileBounds)}`);
  }
  await client.send("Page.navigate", { url: `${siteOrigin}/proof/` });
  await waitFor(
    client,
    `document.readyState === 'complete' && document.querySelector('#proof-panel').dataset.proofState !== 'loading'`,
    "published proof verification",
  );
  assert.ok(
    ["verified", "verified-unreviewed"].includes(
      await evaluate(client, "document.querySelector('#proof-panel').dataset.proofState"),
    ),
  );
  assert.match(await evaluate(client, "document.querySelector('#proof-manifest-hash').textContent"), /^[a-f0-9]{64}$/);
  assert.match(await evaluate(client, "document.querySelector('#proof-attestation-hash').textContent"), /^[a-f0-9]{64}$/);
  assert.match(await evaluate(client, "document.querySelector('#proof-reviewer-did').textContent"), /^did:key:z6Mk/);
  assert.equal(
    await evaluate(client, `!/[\\p{Script=Hiragana}\\p{Script=Katakana}\\p{Script=Han}]/u.test(document.body.innerText)`),
    true,
    "proof page rendered non-English public copy",
  );
  assert.equal(
    await evaluate(client, "document.documentElement.scrollWidth <= window.innerWidth + 1"),
    true,
    "proof page has horizontal mobile overflow",
  );
  if (process.env.FLOP_SCREENSHOT_PATH) {
    const screenshot = await client.send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: false,
    });
    await writeFile(process.env.FLOP_SCREENSHOT_PATH, Buffer.from(screenshot.data, "base64"));
  }
  assert.deepEqual(exceptions, []);
  console.log("Browser E2E passed: English-only UI, claim checks, no user-URL fetch, mobile layout, and published Ed25519 proof.");
} finally {
  client.close();
}
