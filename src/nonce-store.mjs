import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const MAX_NONCE = 9_999_999_999_999_999_999n;

function validateNonce(value) {
  const text = String(value);
  if (!/^[0-9]{1,19}$/.test(text)) {
    throw new Error(`nonce must be 1-19 ASCII digits, got ${JSON.stringify(text)}`);
  }
  return BigInt(text);
}

export class NonceStore {
  constructor(filePath = ".local/nonces.json") {
    this.filePath = path.resolve(filePath);
  }

  async load() {
    try {
      const parsed = JSON.parse(await readFile(this.filePath, "utf8"));
      if (parsed.version !== 1 || typeof parsed.values !== "object") {
        throw new Error("unsupported nonce-state format");
      }
      return parsed;
    } catch (error) {
      if (error.code === "ENOENT") return { version: 1, values: {} };
      throw error;
    }
  }

  async next(scope, nowMilliseconds = Date.now()) {
    if (typeof scope !== "string" || scope.length === 0) {
      throw new Error("nonce scope must be a non-empty string");
    }
    const state = await this.load();
    const previous = state.values[scope]
      ? validateNonce(state.values[scope])
      : 0n;
    const clock = validateNonce(nowMilliseconds);
    const next = clock > previous ? clock : previous + 1n;
    if (next > MAX_NONCE) throw new Error("nonce space exhausted");
    return next.toString();
  }

  async record(scope, nonce) {
    const numeric = validateNonce(nonce);
    const state = await this.load();
    const previous = state.values[scope]
      ? validateNonce(state.values[scope])
      : 0n;
    if (numeric <= previous) {
      throw new Error(`refusing to move nonce backwards for ${scope}`);
    }
    state.values[scope] = numeric.toString();
    await mkdir(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    const temporary = `${this.filePath}.tmp-${process.pid}`;
    await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporary, this.filePath);
  }
}
