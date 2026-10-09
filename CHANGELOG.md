# Changelog

All notable changes follow [Semantic Versioning](https://semver.org).

## [Unreleased]

## [0.3.0] - 2026-10-10

MVP release: closes every failing case from the v0.2.0 review (adversarial suite: 0 todo).

### Added
- `test/adversarial.test.ts`: the review's 39-check attack simulation, with mocked network. Open attacks are `todo` until fixed.
- `publish --to-dir <dir>` writes the signed files into a local registry copy instead of opening a PR.

### Release
- `release` workflow on `v*` tags: tests, `npm pack`, `SHA256SUMS`, build-provenance attestation, GitHub Release with assets, and `npm publish --provenance` when `NPM_TOKEN` is set. Tags are GPG-signed; the public key is in `.github/release-signing-key.asc`. See RELEASING.md.

### Docs and governance
- `docs/`: quickstart, how it works, threat model, spec, API, platforms, consumers, keys, FAQ. New README, SECURITY.md, CODEOWNERS, Dependabot (npm + actions). All actions are pinned by commit SHA.
- Badges show the proof label (`✓ challenge-passed`, `✓ verified creator`); the score stays in the API.

### For consumers
- GitHub Action (`uses: ao3575911/botproof@v0.3.0`): inputs `bot`, `min-strength`, `registry`, `trust`; outputs `strength`, `score`, `hash`; fails the job below the threshold.
- `verify --min-strength <s>` exits 3 below it. Exit codes are documented in `--help`.

### Trust
- Reviews from GitHub accounts under 90 days old, or with no repos and no followers, count 0 (review A6). Creator GitHub links weigh by account age: 50 (1y+), 35 (90 days+), 15 (new or unknown).
- `verify --trust <handles|file>` counts only reviews from your own list.

### Registry API
- `api/index.json` adds `schemaVersion`, `registryCommit` and a sha256 for every signed document. `verify` checks the bot's documents against those hashes and prints the commit.
- `verify --git` checks a bot from a fresh clone of the registry, without trusting the API.
- Each URL is fetched once per Pages build.

### Security
- Challenge codes are bound to the bot and the creator's key: `botproof-challenge:<platform>/<botId>:<keyId>:<nonce>`. A copied code no longer passes for another bot or key (review A2, N2).
- `web` challenges must be on the creator's own gist or a DNS-proven domain. Only `grok` and `web` platforms are accepted.
- `registry check` rejects a challenge nonce used by another bot or key.
- First-come bot ownership: `registry check --base <ref> --author <login>` rejects a PR that changes another creator's bot, deletes signed files, or carries signatures from anyone but the PR author (review A3).
- Anti-rollback: manifests carry a monotonic `seq` (set by `sign`). CI requires it to increase, and `verify` rejects a manifest older than any signed version in `versions/` (review A7).
- Reviews carry the `versionHash` they reviewed. Reviews of earlier versions are shown but not counted, so a takeover can't inherit them (review A3).
- Key lifecycle: `revoke --key [--since]` voids everything the key signs from then on, and CI rejects new signatures from a revoked key (review A8). `rotate` moves to a new key with a rotation doc signed by both keys, and your bots stay yours. `key` shows your key; `key export` prints it for backup.
- Keys are stored encrypted by default (PKCS#8, AES-256-CBC, mode 0600). The passphrase is prompted, or read from `BOTPROOF_PASSPHRASE`. Existing plaintext keys still load.
- Web Bot Auth evidence counts only from allowlisted platform directories (built in: chatgpt.com; the registry's `platforms.json` extends it by PR). The request path must contain the bound challenge code, and evidence only upgrades a claim whose own challenge passed (review N6, N8).
- `verify` never takes the platform allowlist from the API mirror.
- `transfer <platform>/<botId> --to github:<user> --to-key <key>`: the owner signs a hand-over before the new owner publishes.
- Grok share pages: only the title and description tags are read.

- One rule set (`src/rules.ts`) for CI and `verify`: `verify` now rejects a tampered creator profile (A9) and a handle that doesn't match its proven GitHub account (A10b).
- `platform` must be `grok` or `web`; all HTML in the Pages index is escaped (A12c, stored XSS).
- Network reads are https only, with a 10 s timeout, a 2 MB cap and no redirects.
- Canonical JSON follows RFC 8785 for strings and key order, and rejects non-integer or unsafe numbers.

### Fixed
- Installing from git or a tarball builds the CLI (`prepare` script), so `botproof` exists after install (review H0). CI installs the packed tarball and runs `botproof --version`.
- A bad JSON file in the registry is reported by path, and the check fails closed (A12b).
- Evidence signed in the same second the code was issued is accepted.
- `init --bot https://x.ai/bot/<id>` works without `--platform`, as the README shows.

## [0.2.0] - 2026-10-09

### Added
- Grok Bot share pages: `challenge` reads the code from the bot's name and description on `x.ai/bot/<id>`. `init --bot <share link>` fills in the platform and id. (#5)
- X links are verified: the post must be by that handle and contain the proof text. Checked through X's free embed endpoint; if X can't be reached the link stays self-claimed. (#3)
- `evidence`: attach a Web Bot Auth signed request (RFC 9421). The platform's key directory and the request signature are both verified, making the claim **platform-signed**. (#6)

### Changed
- Grok claims only pass when the code is on that bot's own share page, so nobody can claim a bot from a page they control.
- `verify` explains the ownership result.

## [0.1.0] - 2026-10-09

### Added
- CLI: `init`, `link`, `challenge`, `sign`, `publish`, `verify`, `attest`, `revoke`.
- Ed25519 signatures over canonical JSON (node:crypto, no runtime dependencies).
- GitHub link proofs via a public gist or profile README, checked live through the GitHub API.
- DNS link proofs via a `_botproof.<domain>` TXT record.
- X links recorded as self-claimed.
- Bot challenge: a one-time code on the bot's public page.
- Proof strength labels: self-claimed, challenge-passed, platform-signed (stub), revoked.
- Score with a visible breakdown: identity, ownership, reviews. Reviews are weighted by reviewer trust; self-reviews are rejected.
- `registry check` and `registry build` for the registry's CI and Pages site.

[Unreleased]: https://github.com/ao3575911/botproof/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ao3575911/botproof/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ao3575911/botproof/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ao3575911/botproof/releases/tag/v0.1.0
