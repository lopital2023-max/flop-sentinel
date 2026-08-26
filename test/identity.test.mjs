import assert from "node:assert/strict";
import { stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import test from "node:test";
import {
  decryptPrivateKey,
  didFromKey,
  encryptPrivateKey,
  privateKeyFromSeed,
  publicKeyBytes,
  publicKeyFromDid,
  readKeystore,
  writeNewKeystore,
} from "../src/identity.mjs";

const RFC8032_SEED = Buffer.from(
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "hex",
);
const RFC8032_PUBLIC =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const TEST_PASSPHRASE = "public-test-passphrase";

test("derives the RFC 8032 Ed25519 public key and a Technocore DID", () => {
  const privateKey = privateKeyFromSeed(RFC8032_SEED);
  assert.equal(publicKeyBytes(privateKey).toString("hex"), RFC8032_PUBLIC);
  const did = didFromKey(privateKey);
  assert.match(did, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
  assert.equal(did.length, 56);
  assert.equal(publicKeyBytes(publicKeyFromDid(did)).toString("hex"), RFC8032_PUBLIC);
});

test("encrypts and decrypts a fixture private key without serializing its seed", () => {
  const privateKey = privateKeyFromSeed(RFC8032_SEED);
  const keystore = encryptPrivateKey(privateKey, TEST_PASSPHRASE);
  const serialized = JSON.stringify(keystore);
  assert.equal(serialized.includes(RFC8032_SEED.toString("hex")), false);
  assert.equal(didFromKey(decryptPrivateKey(keystore, TEST_PASSPHRASE)), keystore.publicDid);
  assert.throws(
    () => decryptPrivateKey(keystore, "incorrect-but-long-passphrase"),
    /wrong passphrase or corrupt file/,
  );
});

test("writes a new keystore with owner-only permissions and refuses overwrite", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "flop-keystore-test-"));
  try {
    const filePath = path.join(directory, "identity.keystore.json");
    const keystore = encryptPrivateKey(
      privateKeyFromSeed(RFC8032_SEED),
      TEST_PASSPHRASE,
    );
    await writeNewKeystore(filePath, keystore);
    assert.equal((await stat(filePath)).mode & 0o777, 0o600);
    assert.equal((await readKeystore(filePath)).publicDid, keystore.publicDid);
    await assert.rejects(() => writeNewKeystore(filePath, keystore), /EEXIST/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
