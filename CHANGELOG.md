# Changelog

All notable changes follow [Semantic Versioning](https://semver.org).

## [Unreleased]

### Fixed
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
