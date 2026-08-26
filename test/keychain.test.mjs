import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import {
  KEYCHAIN_SERVICE,
  keychainReferenceForKeystore,
  validateKeychainReference,
} from "../src/keychain.mjs";

test("binds a Keychain item to the absolute keystore path", () => {
  const first = keychainReferenceForKeystore(".local/identity.keystore.json");
  const second = keychainReferenceForKeystore(path.resolve(".local/identity.keystore.json"));
  assert.deepEqual(first, second);
  assert.equal(first.service, KEYCHAIN_SERVICE);
  assert.match(first.account, /^keystore-[0-9a-f]{32}$/);
  assert.deepEqual(
    validateKeychainReference(first, ".local/identity.keystore.json"),
    first,
  );
  assert.throws(
    () => validateKeychainReference({ ...first, account: `keystore-${"0".repeat(32)}` }, ".local/identity.keystore.json"),
    /unexpected Keychain reference/,
  );
  assert.throws(
    () => validateKeychainReference({ ...first, account: "-w" }, ".local/identity.keystore.json"),
    /invalid Keychain reference shape/,
  );
});
