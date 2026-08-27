# FLOP Sentinel / Technocore local toolkit

FLOP Sentinel is an unofficial, evidence-based toolkit for checking FLOP-related sources and claims before interacting with a testnet, wallet, or signing request. The complete product rationale and implementation plan are in [construction.md](construction.md).

- Live site: <https://lopital2023-max.github.io/flop-sentinel/>
- Source: <https://github.com/lopital2023-max/flop-sentinel>
- Security model: [THREAT_MODEL.md](THREAT_MODEL.md)

Status as of 2026-08-27:

- Local environment: ready
- Cryptography, signature, nonce, and transport tests: public fixtures and mock transports
- Read-only official-source monitoring: operational
- Official roots separated from user-writable hosted zones: implemented
- Machine-readable `public/status.json`: generated
- Local URL, message, and contract-address analysis: implemented
- Five-page bilingual Astro static website: deployed
- Official-source history in `public/changes.json`: generated
- Content-addressed raw snapshots and JCS manifest hash chain: generated and verified
- Reviewed checkpoints: two Ed25519 signatures verified
- GitHub Pages, scheduled monitoring, and public APIs: operational
- Dedicated Technocore Ed25519 DID: created
- Public DID profile note: published with HTTP 200
- Signed `lobby` check-in: published with HTTP 200
- Faucet or token claim: not attempted; no such endpoint is currently published

## Current public identity

```text
DID: did:key:z6MkrPT8CW8EJhrRN5RZB4d3svmNgFtbrPx8sRWJpPQMZ1fu
Profile: https://technocore.chat/kv/did-7e/ae6cdae48a930c
Mailbox: mb-p-911c583d86b97feb1f8c60868b6f562d
Check-in room: lobby
Check-in nonce: 1787747616354
```

Technocore has no central registry. This identity consists of a conventional public DID note plus signed messages that prove possession of the corresponding private key. Neither artifact establishes a real-world identity or trustworthiness.

The current Technocore authentication document explicitly states that registration, claim, and token endpoints do not exist. This toolkit therefore monitors and exercises only the Technocore communication layer; it does not interact with a FLOP chain, faucet, wallet, or token contract.

## Requirements

- An even-numbered Node.js release at or above 22.12 (`.nvmrc` pins 22; the validation environment uses 22.19.0)
- Astro 7.2.7 as a build-time development dependency

`.nvmrc` and `package-lock.json` pin the environment. The generated static site has no server-side runtime dependency.

```bash
git clone https://github.com/lopital2023-max/flop-sentinel.git
cd flop-sentinel
nvm use
npm ci --ignore-scripts
npm run setup
npm test
npm run security:audit
```

VS Code exposes these tasks under `Terminal` → `Run Task...`:

- `FLOP: Run local tests`
- `FLOP: Check local environment`
- `FLOP: Check official sources`
- `FLOP: Build status.json`
- `FLOP: Start web development server`
- `FLOP: Build static website`

Identity generation is deliberately absent from VS Code tasks to prevent accidental key creation.

## Official-source monitoring

```bash
npm run monitor
```

The four monitored URLs are declared in [config/sources.json](config/sources.json):

1. `https://technocore.chat/openapi.json`
2. `https://technocore.chat/auth.md`
3. `https://flop.finance/`
4. `https://api.github.com/orgs/flop-labs/repos?...`

The same exact URLs are pinned in code, so a modified configuration cannot redirect the collector to an arbitrary host. Public rooms are not monitored because they contain untrusted third-party input.

The first run creates a baseline. Later runs detect:

- Technocore OpenAPI version and path additions or removals
- New paths containing `faucet`, `claim`, `token`, `wallet`, `rpc`, `inference`, `compute`, or `testnet`
- Flop Labs repository additions, removals, and updates
- Relevant wording changes on the official website or authentication document
- Disappearance of the explicit statement that no claim or token endpoint exists

Local state is excluded from Git:

```text
.local/monitor-state.json     comparison baseline
.local/last-report.json       latest report
.local/monitor-history.jsonl  observation history
```

Phase 3 also stores exact response bytes under SHA-256 filenames in `public/evidence/snapshots/`. The site never renders these artifacts as HTML. GitHub Pages currently serves `.snapshot` as `application/octet-stream`, but custom response headers are not guaranteed on Pages.

Run a read-only observation without saving it:

```bash
node src/cli.mjs monitor --no-write
```

## Phase 1: deterministic verifier

### Official roots

[config/trust-roots.json](config/trust-roots.json) separately defines exact official pages, an official GitHub namespace, and an X account referenced by the official site.

Technocore `/r/` and `/kv/` paths are hosted on an official domain but remain user-writable. They are never classified as official statements. This distinction is stronger than a domain-only allowlist.

### Build and inspect `status.json`

From the latest saved monitor report:

```bash
npm run status:build
npm run status
```

After refreshing all four sources:

```bash
node src/cli.mjs status:build --refresh
```

The output is [public/status.json](public/status.json). Each capability includes a state, explanation, evidence URL, observation time, and SHA-256. The schema distinguishes "not published in the monitored sources" from "does not exist."

### Analyze a URL, message, or address

```bash
node src/cli.mjs check --input "https://flop.finance/"
node src/cli.mjs check --input "Claim at https://flop.finance.evil.example/claim" --json
node src/cli.mjs check --file suspicious-message.txt
```

Standard input is supported:

```bash
pbpaste | node src/cli.mjs check --json
```

The analyzer never fetches a submitted URL. It deterministically evaluates URL structure, pinned trust roots, `status.json`, and patterns such as secret-material requests. Its primary verdicts are:

- `VERIFIED_OFFICIAL_ROOT`
- `OFFICIALLY_REFERENCED`
- `UNVERIFIED`
- `CONFLICTS_WITH_CURRENT_OFFICIAL_STATE`
- `HIGH_RISK_PATTERN`

A verdict is not a guarantee of safety and is not a legal declaration that something is fraudulent.

## Phase 2: website

The bilingual static site contains five pages:

- `/` — readiness dashboard, official-source graph, and latest change signals
- `/verify/` — browser-local URL, message, and address analysis with reasons
- `/changes/` — change history with SHA-256 evidence
- `/proof/` — browser verification of snapshots, manifest links, and Ed25519 checkpoints
- `/methodology/` — decision rules, trust boundaries, and limitations

Generate public website data:

```bash
npm run web:data
```

Refresh the four official sources first:

```bash
node src/cli.mjs web:data --refresh
```

Run development and static validation:

```bash
npm run dev
npm run build
npm run verify:dist
```

Build output is written to `dist/`. `public/_headers` defines CSP, frame denial, and Permissions Policy for compatible static hosts. Every script disables Astro telemetry.

The verifier form reads only same-origin `status.json`. It performs no fetch to a submitted destination, wallet connection, analytics request, or form submission.

Public APIs under `/flop-sentinel/`:

- `status.json` — capability states and evidence
- `changes.json` — official-source change history
- `sources.json` — collector policy, trust roots, and snapshot references
- `verdict-schema.json` — JSON Schema for verifier results
- `proof.json` — discovery metadata for the latest manifest and checkpoint
- `feed.xml` — Atom change feed
- `llms.txt` and `.well-known/agent.json` — agent-facing discovery documents

## Phase 3: signed evidence

Refresh sources and derived public data:

```bash
node src/cli.mjs web:data --refresh
```

Create or reuse a content-addressed observation manifest:

```bash
npm run attest:manifest
```

JSON hash inputs are normalized with RFC 8785 JCS. Repeating an identical observation reuses the existing manifest.

Only after reviewing the observation, sign a checkpoint with the existing DID:

```bash
node src/cli.mjs attest:sign --acknowledge-reviewed-checkpoint
```

This operation temporarily reads the keystore unlock value from Keychain, writes only public evidence, and performs no network request.

Verify every public artifact and regenerate discovery metadata:

```bash
npm run attest:verify
```

Current evidence head:

```text
Manifest #2:    7acf0d1d884fb3c2c804c1b4efad0f4da3ccd793e932e7af2dbaef23595bad07
Attestation #2: 465ac9fd563229abf8ccd4ad44c0b60b15d920c05538f956365cde04e2319ea5
Reviewer DID:   did:key:z6MkrPT8CW8EJhrRN5RZB4d3svmNgFtbrPx8sRWJpPQMZ1fu
```

Verification covers eight referenced raw snapshots, eight referenced derived artifacts, the trust-root configuration, monitor reports, both hash chains, and both Ed25519 signatures. This establishes post-observation integrity and maintainer review, not FLOP Labs endorsement, reward eligibility, or an on-chain fact.

## Phase 4: GitHub publication

Three GitHub Actions workflows are present:

- `ci.yml` — manually validates a reviewed ref with a read-only token; external fork PR code is never executed automatically
- `pages.yml` — validates and deploys the static artifact from `main`
- `monitor.yml` — reads the four pinned sources daily at 02:23 UTC and commits only generated public evidence

Every official Action is pinned to a complete release commit SHA. Installs use `npm ci --ignore-scripts`. The scheduled monitor receives no keystore, Keychain material, DID key, or wallet information. Its automated manifest is observed but unsigned; `proof.json` and `/proof/` expose that distinction.

GitHub does not start a second workflow from a commit made with the repository `GITHUB_TOKEN`. A scheduled monitor commit therefore updates the repository but does not itself deploy Pages. Review the observation, create a checkpoint if appropriate, and push the reviewed evidence; alternatively, explicitly dispatch the Pages workflow to publish an unreviewed observation.

Run publication checks locally:

```bash
npm run security:audit
npm audit --audit-level=high
npm audit signatures
```

GitHub Pages cannot set arbitrary response headers. The site therefore includes a meta CSP in addition to `_headers`, but response-header-only controls such as `frame-ancestors` remain a hosting limitation. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Private-key management

Read [SECURITY.md](SECURITY.md) first. The Technocore DID uses a dedicated Ed25519 key that is entirely separate from cryptocurrency wallets. Never reuse a wallet seed or private key.

The operational keystore is `.local/identity.keystore.json` with mode `0600`. It uses AES-256-GCM with scrypt. A random 32-byte unlock value is stored under the `flop-technocore-agent-keystore-v1` item in macOS Keychain and never appears in a file or standard output.

Create a different DID only when genuinely necessary. DID continuity normally makes a second identity undesirable.

```bash
node src/cli.mjs identity:init --acknowledge-secret-generation
```

```bash
node src/cli.mjs identity:init-keychain \
  --acknowledge-secret-generation-and-keychain-storage
```

Existing keystores are never overwritten.

Display only the existing public DID:

```bash
node src/cli.mjs identity:show
```

## External posting

Preview a signed POST body without sending it:

```bash
node src/cli.mjs say --room lobby --text "your message"
```

An actual public Technocore write requires the final acknowledgement flag:

```bash
node src/cli.mjs say \
  --room lobby \
  --text "your message" \
  --execute-external-write
```

The destination is pinned to `https://technocore.chat`. The client uses JSON POST rather than a signed GET URL because access logs can retain a GET signature and Technocore's single-use nonce guarantee is bounded by its recent-message scan.

The one-time check-in is complete, and local state refuses to repeat it.

## Repository layout

```text
flop/
├── .github/workflows/
├── .vscode/tasks.json
├── config/
│   ├── sources.json
│   └── trust-roots.json
├── public/
│   ├── .well-known/agent.json
│   ├── changes.json
│   ├── proof.json
│   ├── evidence/
│   │   ├── snapshots/
│   │   ├── artifacts/
│   │   ├── manifests/
│   │   └── attestations/
│   ├── llms.txt
│   └── status.json
├── scripts/security-audit.mjs
├── src/
├── test/
├── construction.md
├── README.md
└── SECURITY.md
```

This toolkit does not guarantee participation history or airdrop eligibility. A DID signature proves possession of a key, not a person's identity, honesty, or future association with a FLOP wallet.
