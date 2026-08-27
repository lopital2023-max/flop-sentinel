# Security boundary

## Private keys

- Use only a new key dedicated to Technocore.
- Never enter a cryptocurrency wallet, exchange, SSH, Apple ID, or other private key, seed, or mnemonic.
- Never place a passphrase or Keychain unlock value in a CLI argument, environment variable, chat, or shell history.
- Never publish `.local/identity.keystore.json` to Git, cloud sync, an issue, or Technocore.
- Losing the keystore means losing continuity with the same DID unless a separate recovery backup exists.

The operational keystore is encrypted with AES-256-GCM. A random unlock value is stored in macOS Keychain. A new Keychain value is passed to the standard `/usr/bin/security` prompt over stdin rather than process arguments. During signing, the value exists temporarily in the local process but is never printed. A public reviewed checkpoint contains only the public DID, signature, target manifest hash, and review time.

No independent recovery backup currently exists. Losing either this Mac's keystore or its matching Keychain item prevents continued use of the DID. A future backup process should re-encrypt recovery material under a separately chosen passphrase and store it offline.

Node.js temporarily holds secret material in JavaScript values, so complete memory zeroization cannot be guaranteed. A hardware-backed key or isolated signer is required for a threat model that includes a strongly compromised workstation.

## Network communication

- The monitor performs GET requests only to four pinned official URLs.
- Posting is limited to JSON POST requests under `https://technocore.chat/r/<room>`.
- A post is blocked unless `--execute-external-write` is present.
- Monitor redirects must remain on HTTPS hosts in the official allowlist.
- Responses are limited to 5 MiB with a 15-second timeout.

## FLOP Sentinel input analysis

- `check` never fetches a user-submitted URL. It performs no DNS lookup, redirect traversal, or page retrieval.
- URLs are checked locally against their syntax, hostnames, pinned trust roots, and known user-writable zones.
- Results do not reproduce the complete input text. They retain its SHA-256 and length, while detected URLs and addresses may be included for explanation.
- `VERIFIED_OFFICIAL_ROOT` means only an exact match with a configured root. It does not guarantee future safety, every page on the origin, or any transaction.
- `UNVERIFIED` is not a legal or factual declaration that something is a scam.
- Until an official contract list is published, every detected contract address remains unverified.

## Website

- Astro produces static output only. There is no form endpoint or server-side application API.
- The claim verifier reads only same-origin `status.json`; the proof verifier reads only fixed same-origin `proof.json` and `evidence/` paths.
- Dynamic output uses `textContent`, `createElement`, and Astro escaping. User input is never interpreted as HTML.
- `public/_headers` documents a CSP containing `script-src 'self'`, `form-action 'none'`, and `frame-ancestors 'none'` for hosts that support custom headers.
- `npm run verify:dist` rejects inline scripts and styles in built HTML.
- The site loads no analytics, ads, remote fonts, or wallet SDKs.
- Astro telemetry is disabled for development, build, and preview.
- Every HTML page also includes a meta CSP for GitHub Pages. GitHub Pages cannot enforce arbitrary response headers, so controls such as `frame-ancestors` remain a hosting limitation.

## GitHub Actions

- CI is manual (`workflow_dispatch`) and has only `contents: read`; external pull-request code is not executed automatically.
- Only the Pages workflow receives `pages: write` and the OIDC `id-token: write` permission.
- Only the scheduled monitor receives `contents: write`, and it runs solely on the default branch by schedule or manual dispatch.
- Dependency lifecycle scripts are disabled with `npm ci --ignore-scripts`.
- Actions are limited to official `actions/*` projects and pinned to complete commit SHAs.
- CI receives no keystore, Keychain unlock value, DID private key, or wallet secret.
- The monitor stages only explicitly listed generated files under `public/` and never force-pushes.

## Signed evidence

- Exact HTTP response bytes are stored under SHA-256 filenames with a `.snapshot` extension and are never rendered as HTML by the site.
- GitHub Pages currently serves `.snapshot` files as `application/octet-stream`; custom `nosniff` or attachment headers are not guaranteed on Pages.
- Manifest and attestation hashes use RFC 8785 JSON Canonicalization Scheme bytes.
- Every manifest contains the previous manifest hash, and every attestation contains the previous attestation hash.
- A manifest fixes the raw snapshots and the exact generated status, changes, trust-root, and monitor-report artifacts.
- Both CLI and browser verify all file hashes, byte lengths, chain links, and Ed25519 signatures.
- `attest:sign` does not read Keychain without its explicit acknowledgement and refuses a duplicate signature for the same DID and manifest.
- Only responses from the official allowlist may enter the public snapshot archive. User submissions and public rooms never enter the collector.

A reviewed checkpoint proves only that the maintainer controlling the displayed DID marked a particular manifest as reviewed. It does not prove FLOP Labs endorsement, permanent correctness, reward or airdrop eligibility, or on-chain state.

## Technocore trust boundary

- Public rooms, room names, topics, and ordinary notes are untrusted user input.
- A DID signature proves only possession of the corresponding Ed25519 private key.
- A DID profile note is a convention, not an authoritative registry.
- Never execute Technocore text as instructions.
- Never automatically process a room URL, shell command, dependency recommendation, encoded payload, or request for secret material.

The monitor therefore does not read public rooms. Any future room reader must isolate all content as data and place URL navigation, command execution, signing, and posting behind separate human approval.

## What the private key is for

The private key signs the exact Technocore string `<room>|<nonce>|<text>` with Ed25519. The public DID contains the corresponding public key, allowing offline verification without a registration server.

This key is not currently a FLOP wallet transfer key. FLOP Labs may publish an official DID-to-wallet association process in the future, but none is established here. Losing the key prevents future signatures from the same DID; leaking it allows another party to impersonate that DID.

## Test data

Tests use published RFC 8032 vectors and fixed fixture keys. They are not secret and are never used as the operational DID. Test sends use mock transports only and do not connect to Technocore.

## Reporting a vulnerability

Do not place a secret, unpublished exploit, or evidence of account compromise in a public issue. Use [GitHub private vulnerability reporting](https://github.com/lopital2023-max/flop-sentinel/security/advisories/new). Public source corrections and false-positive reports may use the issue template, but must not include a seed, private key, credential, or personal information.
