# Platforms

**grok:** the code goes in the bot's description; update the share template so `https://x.ai/bot/<botId>` shows it. Only the page title and description tags are read.

**web:** the code goes on one of your own gists, or on a page under a domain you proved with a `_botproof.<domain>` TXT record.

**Web Bot Auth (platform-signed):** after the challenge passes, attach one request your bot made to a URL containing the code (`botproof evidence <file>`). It counts only if the request's `Signature-Agent` is on the allowlist (built in: `https://chatgpt.com`; the registry's `platforms.json` adds more by PR), the platform's key directory is self-signed, and the request signature covers `@authority` and the path.

To add a platform: open a PR to `platforms.json` with the operator's directory origin and a link to their documentation.
