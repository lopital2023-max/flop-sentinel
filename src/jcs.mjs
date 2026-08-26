// RFC 8785 JSON Canonicalization Scheme (JCS) for I-JSON values.
// This module intentionally has no Node.js imports so the same implementation
// can be used by the CLI and by the browser verifier.

function assertUnicodeScalarString(value, label) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`${label} contains an unpaired UTF-16 surrogate`);
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError(`${label} contains an unpaired UTF-16 surrogate`);
    }
  }
}

function serialize(value, stack) {
  if (value === null) return "null";

  if (typeof value === "string") {
    assertUnicodeScalarString(value, "JSON string");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("JCS does not permit NaN or infinite numbers");
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new TypeError(`JCS does not permit values of type ${typeof value}`);
  }
  if (stack.has(value)) throw new TypeError("JCS does not permit cyclic values");

  stack.add(value);
  try {
    if (Array.isArray(value)) {
      const items = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) {
          throw new TypeError("JCS does not permit sparse arrays");
        }
        items.push(serialize(value[index], stack));
      }
      return `[${items.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("JCS accepts only plain JSON objects");
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new TypeError("JCS does not permit symbol keys");
    }

    const entries = [];
    for (const key of Object.keys(value).sort()) {
      assertUnicodeScalarString(key, "JSON object key");
      entries.push(`${JSON.stringify(key)}:${serialize(value[key], stack)}`);
    }
    return `{${entries.join(",")}}`;
  } finally {
    stack.delete(value);
  }
}

export function canonicalize(value) {
  return serialize(value, new WeakSet());
}

export function canonicalizeBytes(value) {
  return new TextEncoder().encode(canonicalize(value));
}
