# Changelog

All notable changes follow [Semantic Versioning](https://semver.org).

## [Unreleased]

### Added
- `test/adversarial.test.ts`: the review's 39-check attack simulation, with mocked network. Open attacks are `todo` until fixed.
- `publish --to-dir <dir>` writes the signed files into a local registry copy instead of opening a PR.

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

### Fixed
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

[Unreleased]: https://github.com/ao3575911/botproof/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ao3575911/botproof/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ao3575911/botproof/releases/tag/v0.1.0
