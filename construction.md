# FLOP Sentinel product and implementation plan

The strongest differentiator is not another FLOP link directory. It is a site that lets a person or agent verify **which official source supports a claim and whether that claim conflicts with the currently published specification**.

> **FLOP Sentinel**
>
> Unofficial, evidence-based verifier
> Check the source before you sign.

The project never calls itself an official FLOP site. It is published as unofficial open-source infrastructure for verifying FLOP-related official information.

## 1. Why this project exists

As of 2026-08-27, the Technocore authentication specification says there is no registration, provisioning, claim, token, API-key, or OAuth endpoint. It also explains that a DID signature proves possession of a key, not the honesty of its holder or the truth of a message. See the [Technocore authentication specification](https://technocore.chat/auth.md).

The currently monitored API is Technocore Chat/Notes v0.9.7. See the [official OpenAPI document](https://technocore.chat/openapi.json).

The monitored sources therefore do not currently establish claims such as:

- "Claim a token from this Technocore page."
- "Connect a wallet here to receive FLOP."
- "Enter a private key to register a DID."
- "This contract address is the official FLOP token."

Existing community projects already cover availability monitoring, DID creation, signature verification, and onboarding guides. The more useful gap is **official-source provenance, contradiction detection, and signed history** rather than another DID generator.

## 2. Core capabilities

### A. FLOP Readiness Dashboard

The dashboard answers what is currently published in monitored official sources.

| Capability | Example state |
|---|---|
| Technocore | Available / v0.9.7 |
| DID signatures | Available |
| Profile publication | Available as a convention |
| Chat / Notes | Available |
| Testnet RPC | Not published in monitored sources |
| Chain ID | Not published in monitored sources |
| Faucet | Not published in monitored sources |
| Token claim | Not offered by the current Technocore service |
| Official contracts | Not published in monitored sources |
| DID-to-wallet association | Not established by a monitored specification |

Each state includes:

- Evidence URL
- Last observation time
- SHA-256 of the observed document
- Changes from the preceding observation
- A distinction between "not found in monitored sources" and "explicitly not offered"

That distinction prevents an absence of evidence from becoming an unsupported claim of nonexistence.

### B. Official Source Graph

Official status is represented as a provenance path rather than a single boolean.

```text
Pinned official root
├── flop.finance
├── technocore.chat
└── github.com/flop-labs
        │
        ├── information published directly at the root
        └── an external page linked by an official root
```

Trust levels:

1. `VERIFIED_OFFICIAL_ROOT` — the exact configured root
2. `OFFICIALLY_REFERENCED` — an external location directly referenced by an official root
3. `UNVERIFIED` — no established path from an official source
4. `CONFLICTS_WITH_CURRENT_OFFICIAL_STATE` — explicit conflict with a current monitored specification
5. `HIGH_RISK_PATTERN` — secret requests, lookalike domains, or other configured high-risk indicators

The site reports evidence and risk indicators. It does not make an absolute declaration that an artifact is safe or fraudulent.

### C. URL, message, and address analysis

A user can paste:

- A URL
- The text of an X or other social post
- A wallet or contract address
- A Discord, Telegram, or Technocore message
- A claimed faucet or token procedure

Checks include:

- Exact official-domain matching
- Subdomain and embedded-host impersonation
- URL user-info such as `user:password@host`
- Direct IP hosts
- Punycode and mixed-script confusables
- Non-standard ports
- Requests for a seed, private key, mnemonic, or recovery phrase
- Claim, faucet, airdrop, or wallet-connect language
- Comparison with contract addresses published by monitored official sources
- Contradictions with the current capability dataset

Example output:

```json
{
  "verdict": "CONFLICTS_WITH_CURRENT_OFFICIAL_STATE",
  "confidence": "high",
  "summary": "The message claims a Technocore token endpoint that is absent from the current service specification.",
  "indicators": [
    "CLAIM_CONFLICTS_WITH_CURRENT_SERVICE"
  ],
  "evidence": [
    {
      "source": "https://technocore.chat/auth.md",
      "observedAt": "2026-08-26T...",
      "sha256": "..."
    }
  ],
  "limitations": [
    "A future official change may not appear until the next observation."
  ]
}
```

### D. Change history and alerts

Pinned documents are observed on a schedule. The system records changes such as:

- A new endpoint
- A faucet or testnet page
- A new Flop Labs repository
- An OpenAPI version change
- New claim or token language
- A new outbound link from an official page
- Removal of a previously explicit limitation

This makes it possible to show when a term such as `faucet` first appeared in a monitored official source.

### E. Agent-facing APIs

The project exposes machine-readable data in addition to a human website:

```text
/status.json
/sources.json
/changes.json
/verdict-schema.json
/proof.json
/llms.txt
/.well-known/agent.json
/feed.xml
```

Another agent can check `status.json` and the source graph before presenting a wallet or signing interaction to its user. This is a direct contribution to an agent-oriented ecosystem without giving an agent arbitrary execution authority.

## 3. Signed evidence

Evidence follows this structure:

```text
exact response bytes
  ↓ SHA-256
observation manifest
  ↓ previousManifestHash
hash-chained history
  ↓ Ed25519 signature
reviewed checkpoint
```

JSON is canonicalized with [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785) before hashing or signing, so the same data yields the same canonical byte sequence across environments.

The dedicated Ed25519 DID is used only for:

- Reviewed observation checkpoints
- Future release or contribution receipts
- Future trust-root approvals
- Explicitly approved Technocore messages

The private key remains in a local encrypted keystore unlocked through macOS Keychain. It is never available to GitHub Actions, the website, or the repository. Automated observations and human-reviewed signatures are visibly different states.

A signature means only that the project's maintainer approved a particular canonical payload. It is not FLOP Labs endorsement, an airdrop right, or an on-chain proof.

## 4. Architecture

The implementation is intentionally static-first.

```text
FLOP official sources
        │
        ▼
strict allowlisted collector
        │
        ├── raw snapshots
        ├── normalized facts
        └── provenance graph
                 │
                 ▼
        deterministic verifier
          ├── Web UI
          ├── JSON feeds
          ├── CLI
          └── signed manifests
```

Current technology:

- Node.js 22
- Astro 7
- JavaScript modules with TypeScript checking
- JSON Schema
- Node standard cryptography
- RFC 8785-compatible canonicalization
- Node test runner
- Chrome DevTools Protocol browser tests
- GitHub Actions
- GitHub Pages

The implementation reuses a single deterministic verifier in Node.js and a dependency-free browser counterpart tested against the same malicious-input corpus.

## 5. Security decisions

The MVP never asks a server to retrieve a user-submitted URL. Browser-local analysis covers:

- URL structure
- Comparison with pinned official data
- Message-language risk indicators

A generic server-side URL fetcher would introduce SSRF, DNS rebinding, internal-IP access, redirect abuse, and content-execution risks. The official collector instead uses a strict allowlist. See [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

Additional decisions:

- No wallet connection
- No transaction signing
- No field for a seed or private key
- No ads or tracking
- Retrieved HTML is data, never an instruction
- Raw HTML is never rendered by the application
- Redirect, size, time, and content-type limits
- Manual review and DID signature for reviewed checkpoints
- No public-room reader
- No automatic reply or tool execution from a Technocore message

## 6. Differentiation

| Existing direction | FLOP Sentinel |
|---|---|
| Technocore availability monitoring | Verifies the meaning and source of official information |
| DID creation guide | Prevents a valid DID signature from being mistaken for safety |
| Offline signature verifier | Verifies the complete official-source evidence history |
| Generic scam blacklist | Publishes deterministic rules and primary evidence |
| Human dashboard | Also exposes agent-readable JSON |
| Faucet directory | Refuses to list an unverified faucet as official |
| Binary safe/scam verdict | Separates evidence, contradictions, indicators, and limitations |

The project complements network-observation tools such as [Technocore Pulse](https://github.com/floppy-labs-eightfivetwo/technocore-pulse) rather than reproducing them.

## 7. Delivery phases

### Phase 1: Local MVP — complete

- Pinned official roots
- Allowlisted collector
- `status.json`
- Local URL and message analysis
- Malicious-input corpus
- `check` and `status` CLI commands

### Phase 2: Website — complete

- Bilingual readiness dashboard
- Browser-local URL and text analysis
- Reasoned verdict display
- Source graph
- Change history
- Responsive design verified in a real browser

### Phase 3: Evidence — complete

- Content-addressed exact-byte snapshots
- Manifest hash chain covering sources and four derived artifacts
- RFC 8785-compatible JCS in Node and browser
- Ed25519 verification in CLI and browser
- Two reviewed checkpoints made by the existing DID

Public paths are `/evidence/snapshots/`, `/evidence/artifacts/`, `/evidence/manifests/`, and `/evidence/attestations/`. `/proof.json` is discovery metadata; `/proof/` reloads and verifies every artifact from the same origin.

Current evidence head:

```text
Manifest #2:    7acf0d1d884fb3c2c804c1b4efad0f4da3ccd793e932e7af2dbaef23595bad07
Attestation #2: 465ac9fd563229abf8ccd4ad44c0b60b15d920c05538f956365cde04e2319ea5
```

### Phase 4: Publication — complete

- Public GitHub repository
- Validated GitHub Pages deployment
- Daily monitoring of exactly four sources at 02:23 UTC
- `llms.txt`, Atom feed, and JSON APIs
- Public threat model and automated security audit
- Issue template and Private vulnerability reporting

Publication locations:

- <https://lopital2023-max.github.io/flop-sentinel/>
- <https://github.com/lopital2023-max/flop-sentinel>

GitHub Actions use least privilege and pin official Actions to complete release commit SHAs. The scheduled monitor receives no private key or Keychain credential, and automated manifests remain distinct from reviewed Ed25519 checkpoints.

### Phase 5: Contribution attribution — current next step

- Publish a concise signed Technocore announcement linking the live site, source repository, and proof page
- Read back the exact DID, nonce, server sequence, and stored text
- Preserve a public contribution receipt without secret material
- Announce the contribution through an appropriate human-facing channel without claiming official endorsement or reward eligibility

## Completion criteria

The project is a substantive contribution when:

- Every displayed claim has an evidence URL, time, and hash
- Identical input and data always yield the same verdict
- A third party can verify every signed manifest
- No private key exists in Git, CI, or the browser
- Every feature works without a wallet connection
- Lookalike domains, Punycode, and secret requests are detected
- Another agent can consume `status.json`
- The site clearly says it is unofficial and guarantees no reward
- Missing official evidence is never confused with proof of fraud

This design is not merely a convenience site. It is public infrastructure that improves information hygiene around FLOP and protects both humans and agents. Airdrop evaluation remains unknown, but the work has clear technical originality, direct utility, verifiability, and a sustainable operating model.
