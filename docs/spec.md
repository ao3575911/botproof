# Spec (v1 documents)

Every document is JSON with `v: 1`, `type`, `ts` (ISO date), `key` (`ed25519:<base64url>`) and `sig`: Ed25519 over the canonical JSON of everything except `sig`. Canonical JSON is RFC 8785 limited to safe integers (no floats). `hash` = sha256 of the same bytes.

| type | Fields | Rules |
|---|---|---|
| `creator` | `handle: github:<user>`, `links[]` (github, x, dns) | GitHub link for the same user, proven live |
| `bot` | `platform` (grok, web), `botId`, `name`, `version`, `seq`, `creator`, `challenge {nonce, url, issued}`, `platformEvidence?` | Signed by the creator's key; `seq` increases |
| `attestation` | `platform`, `botId`, `versionHash`, `attester`, `tag`, `note` | Not by the bot's creator; counts only for that version |
| `revocation` | `target` (hash) | Signed by the target's signer |
| `transfer` | `platform`, `botId`, `to`, `toKey` | Signed by the current owner's key |
| `key-revocation` | `revokedKey`, `since` | Signed by the revoked key |
| `key-rotation` | `handle`, `oldKey`, `newKey`, `oldSig` | Signed by both keys |

Challenge text: `botproof-challenge:<platform>/<botId>:<keyId>:<nonce>` (nonce: 18 hex). Registry layout: `creators/`, `bots/<platform>/<botId>/{manifest.json,versions/,attestations/,transfers/}`, `revocations/`, `keys/<handle>/`, `platforms.json`.
