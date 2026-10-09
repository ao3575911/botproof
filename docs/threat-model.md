# Threat model

**botproof proves identity, not safety.** A listing says who made a bot and that they control it. It says nothing about whether the bot is good.

| Attack | Defence | Test |
|---|---|---|
| Copy another bot's code (replay) | Code is bound to platform, bot and key; nonces can't be reused | A2, N2 |
| Overwrite someone's bot | First-come ownership; changes need the same key or a signed transfer; PR author must be the signer | A3 |
| Claim a platform id from your own page | Grok: code must be on `x.ai/bot/<id>`; web: your gist or DNS-proven domain | A4 |
| Self-review / sock puppets | Self-reviews rejected; accounts under 90 days count 0; `verify --trust` | A5, A6 |
| Roll back to an old version | Monotonic `seq`, checked in CI and against `versions/` | A7 |
| Stolen key | `revoke --key`; CI rejects new signatures from it; `rotate` keeps your bots | A8, K1 |
| Tampered files / impersonated handle | Signatures and one shared rule set in CI and `verify` | A1, A9–A11 |
| Self-issued "platform-signed" | Only allowlisted platform directories; evidence bound to the code | N6, N8 |
| Tampered API mirror | Index with registry commit and per-document hashes; `verify --git` | R1 |
| XSS / slow or huge pages | Escaping; https only, 10 s timeout, 2 MB cap | A12c |

**Not covered:** a creator's GitHub account being taken over (GitHub is the anchor); a platform changing its share pages; the unofficial X embed endpoint (X links fall back to self-claimed). Every row above is a test in `test/adversarial.test.ts`.
