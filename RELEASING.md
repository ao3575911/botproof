# Releasing

1. Merge a PR that bumps `package.json` and `VERSION` in `src/cli.ts`, moves the `CHANGELOG.md` `Unreleased` items under the new version and commits the rebuilt `dist/src`.
2. Run the `release` workflow on `main`: `gh workflow run release -R ao3575911/botproof` (or use the Actions tab).
3. The workflow tests, then **creates and GPG-signs the tag `vX.Y.Z` in CI** and pushes it. It then packs, writes `SHA256SUMS`, attests build provenance and creates the GitHub Release. When the `NPM_TOKEN` secret is set, it also runs `npm publish --provenance`.

Don't tag by hand. Nobody holds the signing key locally.

## Signing key

- The private key exists only in the Actions secret `RELEASE_GPG_KEY`.
- The public key is `.github/release-signing-key.asc`: ed25519, fingerprint `C35E1B1094F0EE4199EE4E2F7F5B79FA1BCBA754`, uid `<280728713+ao3575911@users.noreply.github.com>`.
- The same key signs registry tags (`tag` workflow in ao3575911/botproof-registry).
- For GitHub to show **Verified** on tags, an owner of the ao3575911 account adds this public key under *Settings → SSH and GPG keys → New GPG key*. Or from a shell: `gh auth refresh -s admin:gpg_key && gh gpg-key add .github/release-signing-key.asc`.
- v0.3.0 and v0.3.1 were signed with the retired key `E419E09237F7817B2116DDC4FE8705F155BFBE8C` (`.github/release-signing-key-v0.3.0-v0.3.1.asc`).
- Rotating the key means generating a new key, replacing the secret and this public key file, and adding it on GitHub.

Why GPG rather than gitsign? GitHub doesn't show sigstore/gitsign signatures as Verified. The build provenance below is already keyless sigstore.

## Verify a release

```bash
sha256sum -c SHA256SUMS                                          # tarball matches
gh attestation verify botproof-X.Y.Z.tgz -R ao3575911/botproof   # built by this repo's release workflow (sigstore)
gpg --import .github/release-signing-key*.asc && git tag -v vX.Y.Z   # tag signature
```
