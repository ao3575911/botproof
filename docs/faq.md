# FAQ

**Is a verified bot safe?** No. botproof links a bot to a creator. Judge the creator.

**Why GitHub?** It's the account most builders already have, and gists give a free public proof. Domains (DNS) and X add weight.

**Does it need a server?** No. The registry is a git repo; the API is static files on GitHub Pages.

**How is this different from A2A signed cards or Web Bot Auth?** They sign *what* a bot or request is. botproof says *who* holds those keys and whether others vouch for them. It uses Web Bot Auth as evidence.

**Can I run my own registry?** Yes: fork botproof-registry and pass `--registry`.
