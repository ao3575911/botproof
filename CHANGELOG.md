# Changelog

All notable changes follow [Semantic Versioning](https://semver.org).

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
