# FLOP Sentinel threat model

Last updated: 2026-08-27

## Assets

- User wallets, seeds, private keys, and personal information
- The maintainer's Technocore Ed25519 private key and macOS Keychain unlock value
- Integrity of official-source observations, snapshots, manifests, and reviewed checkpoints
- Browsers that consume the public website and JSON APIs
- Integrity of the GitHub repository and Pages deployment

FLOP Sentinel does not connect a wallet or ask users for secret material. The Technocore DID key is separate from every cryptocurrency wallet.

## Trust boundaries

```text
user text / URL ── local parser only ── verdict
                         X no fetch / no shell

pinned HTTPS sources ── byte limit + host allowlist ── raw snapshot
                                                   ├── JSON/text normalization
                                                   └── SHA-256 manifest

local encrypted keystore ── macOS Keychain unlock ── Ed25519 checkpoint
                         X never available to GitHub Actions or the browser

GitHub Actions ── unsigned observations only ── GitHub Pages
```

## Threat actors

- A third party posting a lookalike domain, URL user-info trick, Punycode name, or fake contract
- A third party placing malicious text or commands in a world-writable Technocore room or note
- An attacker able to insert instructions or scripts into monitored HTML, JSON, or a repository description
- A supply-chain attacker compromising an npm dependency or GitHub Action
- A hosting or repository attacker attempting to replace public artifacts
- An attacker compromising the maintainer workstation and accessing the keystore or Keychain

## Controls against executing external instructions

1. A submitted URL is parsed as a `URL` only. The verifier performs no DNS lookup, HTTP request, or redirect traversal.
2. The collector fetches only four URLs pinned in both code and configuration, and every redirect host is allowlisted.
3. Retrieved HTML is a normalization string. It is never inserted into the DOM or passed to a shell, `eval`, or module loader.
4. Raw snapshots are read only as SHA-256 input and stored with a `.snapshot` extension. Their measured GitHub Pages content type is `application/octet-stream`, but Pages does not guarantee repository-defined response headers; never assume an artifact is safe HTML and open it as such.
5. Dynamic UI output uses `textContent` and Astro escaping. The project contains no `innerHTML`, `set:html`, or `document.write` path.
6. The only OS program started by production code is the fixed macOS Keychain path `/usr/bin/security`. It receives fixed subcommands and validated argument arrays without a shell.
7. A Technocore POST requires `--execute-external-write` and is pinned to `https://technocore.chat`. GitHub Actions never performs this operation.
8. External fork pull requests do not execute contributor-controlled code, tests, package scripts, or workflows. CI runs only by explicit dispatch on a reviewed ref. Only the scheduled monitor receives `contents: write`, and it stages fixed generated paths.

Consequently, a message in a Technocore room that says "run this command" is never read by the collector. If similar text appears in a pinned official response, it remains snapshot data and never reaches an execution path.

## CI/CD controls

- Every GitHub Action is an official `actions/*` project pinned to a complete release commit SHA.
- `.nvmrc` and `package-lock.json` pin Node.js, Astro, and the dependency tree.
- `npm ci --ignore-scripts` disables dependency lifecycle scripts.
- CI is `workflow_dispatch` only, has `contents: read`, and never runs on an external pull-request event.
- Repository settings require approval for workflows from every external contributor.
- Only the Pages job has `pages: write` and `id-token: write`.
- The scheduled monitor runs only from the default branch, not a fork or pull request.
- The monitor receives no keystore, Keychain unlock value, wallet secret, or repository secret.
- Automated manifests are explicitly unsigned. A reviewed checkpoint is created only on the maintainer workstation with an acknowledgement flag.

## What evidence proves

- SHA-256 detects a change to exact bytes referenced by a manifest.
- `previousManifestHash` and `previousAttestationHash` expose changes that break the published chain.
- An Ed25519 signature proves that the private key corresponding to the displayed DID signed the canonical payload.

Evidence does not prove that an official source is truthful or uncompromised, that FLOP Labs endorsed this project, that anyone qualifies for an airdrop, or that an on-chain event occurred. A repository owner who can delete the entire repository can replace its history; resistance to that threat requires an independent mirror or external timestamp.

## Residual risks

| Risk | Current mitigation | Remaining limitation |
|---|---|---|
| Compromised official origin | Record every hash change; distinguish current observation from reviewed observation | Truth cannot be determined automatically from a compromised source |
| GitHub account compromise | Least-privilege Actions, signed chain, private vulnerability reporting | Repository deletion and Pages replacement still depend on account security |
| npm supply chain | Lockfile integrity, exact version, disabled lifecycle scripts in CI | Dependency code still runs during a trusted build |
| GitHub Action supply chain | Pin official Actions to complete commit SHAs | A vulnerability in the pinned commit remains possible |
| Malicious fork pull request | No PR-event execution; approval required for all external workflows | A maintainer can still make the human error of running unreviewed code |
| Workstation compromise | AES-256-GCM keystore, Keychain split, no secret output | Strong compromise during signing or memory capture is out of scope |
| GitHub Pages header limits | Meta CSP, no inline scripts or styles | Response-header-only controls such as `frame-ancestors` cannot be enforced |
| Concurrent update | Workflow concurrency group | Multiple local writers can still race on an index |
| Technocore prompt injection | No room reader, no URL fetch, no automatic reply | A human can still copy an untrusted instruction into a terminal |

## Vulnerability reporting

Do not place a secret, unpublished exploit, or evidence of account compromise in a public issue. Use the repository's Private vulnerability reporting. General source corrections and false-positive reports may use the public issue template.
