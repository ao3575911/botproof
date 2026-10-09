# Key management

Your key lives in `~/.botproof/key.pem`, encrypted with your passphrase (prompted, or `BOTPROOF_PASSPHRASE`).

| Task | Command |
|---|---|
| Show it | `botproof key` |
| Back it up | `botproof key export > backup.pem` (still encrypted) |
| Move to a new key | `botproof rotate`, then follow the printed steps (update your gist, re-link, re-sign, publish) |
| Lost or stolen | `botproof rotate` if you still have it, then `botproof revoke --key`; otherwise make a new key, re-link GitHub and re-publish from your GitHub account |

GitHub is the recovery anchor: a PR from your account with a fresh gist proof can re-establish you.
