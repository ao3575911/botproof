# Releasing

1. Merge a PR that bumps `package.json`, `VERSION` in `src/cli.ts` and moves `CHANGELOG.md` `Unreleased` items under the new version.
2. Tag from `main` with a signed, annotated tag and push it:
   ```bash
   git tag -s vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
   ```
3. The `release` workflow tests, packs, writes `SHA256SUMS`, attests build provenance, creates the GitHub Release and, when the `NPM_TOKEN` secret is set, runs `npm publish --provenance`.

## Verify a release

```bash
sha256sum -c SHA256SUMS                                   # tarball matches
gh attestation verify botproof-X.Y.Z.tgz -R ao3575911/botproof   # built by this repo's workflow
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers tag -v vX.Y.Z   # tag signature
```
