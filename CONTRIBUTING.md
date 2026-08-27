# Contributing

FLOP Sentinel is an unofficial safety tool. Changes should make evidence and limitations clearer rather than make stronger unsupported claims.

## Pull requests

1. Use Node.js 22.
2. Run `npm ci --ignore-scripts`, `npm test`, `npm run build`, and `npm run verify:dist`.
3. Do not add any path that executes user input or monitored responses as shell commands, JavaScript, or HTML.
4. Update the threat model and tests whenever adding a network destination, dependency, GitHub Action, or wallet integration.
5. A trust-root change must cite a primary source and receive maintainer review.

Code, tests, package scripts, and workflows from external fork pull requests are not executed automatically. A maintainer first reviews the diff on GitHub, copies only reviewed changes to a repository-controlled branch, and then runs the manual CI workflow. Never check out and execute an unreviewed fork branch locally.

Manual CI receives no repository write permission, DID private key, Keychain material, or deployment credential. Repository settings also require approval before any workflow from an external contributor can run.

## Evidence

A manifest created by automation is an automated observation, not a reviewed signature. A maintainer creates an Ed25519 reviewed checkpoint only after inspecting the observation. Never ask anyone to disclose a private key or seed in order to obtain a signature.
