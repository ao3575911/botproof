# Registry API

Base: `https://ao3575911.github.io/botproof-registry`. Static JSON, CORS open.

| Path | Content |
|---|---|
| `/api/index.json` | `schemaVersion`, `registryCommit`, `bots[]`, `docs` (path → sha256 of every signed document) |
| `/api/bots/<platform>/<botId>.json` | Result (strength, score, breakdown, reviews) plus the signed `docs` |
| `/api/creators/github-<user>.json` | Creator profile and link results |
| `/badge/<platform>/<botId>.svg` | Badge |

`verify` re-checks everything itself. Over the API it also checks each document against the index hashes and the number of reviews. `verify --git` skips the API and uses a clone. The Pages build is attested (`gh attestation verify`), and rebuilt nightly to re-check live proofs.
