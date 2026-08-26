import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { mkdir, open, readFile } from "node:fs/promises";
import path from "node:path";

const DID_PREFIX = "did:key:z";
const MULTICODEC_ED25519 = Buffer.from([0xed, 0x01]);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_SEED_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const KEYSTORE_FORMAT = "flop-technocore-keystore";
const KEYSTORE_VERSION = 1;
const KEYSTORE_AAD = Buffer.from(`${KEYSTORE_FORMAT}:v${KEYSTORE_VERSION}`);
const SCRYPT_PARAMS = Object.freeze({ N: 32768, r: 8, p: 1 });

export function privateKeyFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) {
    throw new TypeError("Ed25519 seed must be exactly 32 bytes");
  }
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

export function generateIdentityPrivateKey() {
  return privateKeyFromSeed(randomBytes(32));
}

export function publicKeyBytes(privateOrPublicKey) {
  const publicKey = privateOrPublicKey?.type === "public"
    ? privateOrPublicKey
    : createPublicKey(privateOrPublicKey);
  const der = publicKey.export({
    format: "der",
    type: "spki",
  });
  if (
    der.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new Error("key is not an Ed25519 public key");
  }
  return der.subarray(ED25519_SPKI_PREFIX.length);
}

export function encodeBase58(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new TypeError("base58 input must be a Buffer");
  }
  if (buffer.length === 0) return "";

  let value = BigInt(`0x${buffer.toString("hex") || "0"}`);
  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % 58n);
    encoded = BASE58_ALPHABET[remainder] + encoded;
    value /= 58n;
  }

  let leadingZeros = 0;
  while (leadingZeros < buffer.length && buffer[leadingZeros] === 0) {
    leadingZeros += 1;
  }
  return "1".repeat(leadingZeros) + (encoded || "");
}

export function decodeBase58(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError("base58 input must be a non-empty string");
  }
  let numeric = 0n;
  for (const character of value) {
    const digit = BASE58_ALPHABET.indexOf(character);
    if (digit < 0) throw new Error("invalid base58 character");
    numeric = numeric * 58n + BigInt(digit);
  }
  let hex = numeric.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  const decoded = numeric === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  const leadingZeros = value.match(/^1*/)?.[0].length ?? 0;
  return Buffer.concat([Buffer.alloc(leadingZeros), decoded]);
}

export function didFromKey(privateOrPublicKey) {
  const multicodecKey = Buffer.concat([
    MULTICODEC_ED25519,
    publicKeyBytes(privateOrPublicKey),
  ]);
  const did = `${DID_PREFIX}${encodeBase58(multicodecKey)}`;
  if (!isTechnocoreDid(did)) {
    throw new Error("generated DID does not match the Technocore did:key format");
  }
  return did;
}

export function isTechnocoreDid(value) {
  return /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/.test(value);
}

export function publicKeyFromDid(did) {
  if (!isTechnocoreDid(did)) throw new Error("invalid Technocore Ed25519 DID");
  const decoded = decodeBase58(did.slice(DID_PREFIX.length));
  if (
    decoded.length !== 34 ||
    !decoded.subarray(0, MULTICODEC_ED25519.length).equals(MULTICODEC_ED25519)
  ) {
    throw new Error("DID does not contain an Ed25519 multicodec key");
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, decoded.subarray(2)]),
    format: "der",
    type: "spki",
  });
}

function deriveEncryptionKey(passphrase, salt, params = SCRYPT_PARAMS) {
  if (typeof passphrase !== "string" || passphrase.length < 12) {
    throw new Error("keystore passphrase must be at least 12 characters");
  }
  return scryptSync(passphrase, salt, 32, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: 128 * 1024 * 1024,
  });
}

export function encryptPrivateKey(privateKey, passphrase) {
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const encryptionKey = deriveEncryptionKey(passphrase, salt);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  cipher.setAAD(KEYSTORE_AAD);
  const ciphertext = Buffer.concat([cipher.update(pkcs8), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    format: KEYSTORE_FORMAT,
    version: KEYSTORE_VERSION,
    publicDid: didFromKey(privateKey),
    crypto: {
      kdf: {
        name: "scrypt",
        ...SCRYPT_PARAMS,
        salt: salt.toString("base64url"),
      },
      cipher: {
        name: "aes-256-gcm",
        iv: iv.toString("base64url"),
        tag: tag.toString("base64url"),
        ciphertext: ciphertext.toString("base64url"),
      },
    },
  };
}

function validateKeystoreShape(keystore) {
  if (
    !keystore ||
    keystore.format !== KEYSTORE_FORMAT ||
    keystore.version !== KEYSTORE_VERSION ||
    !isTechnocoreDid(keystore.publicDid) ||
    keystore.crypto?.kdf?.name !== "scrypt" ||
    keystore.crypto?.cipher?.name !== "aes-256-gcm"
  ) {
    throw new Error("unsupported or malformed Technocore keystore");
  }

  const { N, r, p } = keystore.crypto.kdf;
  if (N !== SCRYPT_PARAMS.N || r !== SCRYPT_PARAMS.r || p !== SCRYPT_PARAMS.p) {
    throw new Error("unsupported keystore KDF parameters");
  }
}

export function decryptPrivateKey(keystore, passphrase) {
  validateKeystoreShape(keystore);
  const { kdf, cipher: encrypted } = keystore.crypto;
  const salt = Buffer.from(kdf.salt, "base64url");
  const iv = Buffer.from(encrypted.iv, "base64url");
  const tag = Buffer.from(encrypted.tag, "base64url");
  const ciphertext = Buffer.from(encrypted.ciphertext, "base64url");
  const encryptionKey = deriveEncryptionKey(passphrase, salt, kdf);

  try {
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey, iv);
    decipher.setAAD(KEYSTORE_AAD);
    decipher.setAuthTag(tag);
    const pkcs8 = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    const privateKey = createPrivateKey({
      key: pkcs8,
      format: "der",
      type: "pkcs8",
    });
    if (didFromKey(privateKey) !== keystore.publicDid) {
      throw new Error("keystore public DID does not match its private key");
    }
    return privateKey;
  } catch (error) {
    if (error.message.includes("public DID")) throw error;
    throw new Error("could not decrypt keystore (wrong passphrase or corrupt file)");
  }
}

export async function writeNewKeystore(filePath, keystore) {
  validateKeystoreShape(keystore);
  const absolutePath = path.resolve(filePath);
  await mkdir(path.dirname(absolutePath), { recursive: true, mode: 0o700 });
  const handle = await open(absolutePath, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(keystore, null, 2)}\n`, "utf8");
  } finally {
    await handle.close();
  }
  return absolutePath;
}

export async function readKeystore(filePath) {
  const parsed = JSON.parse(await readFile(path.resolve(filePath), "utf8"));
  validateKeystoreShape(parsed);
  return parsed;
}

export const KEYSTORE_DEFAULT_PATH = ".local/identity.keystore.json";
