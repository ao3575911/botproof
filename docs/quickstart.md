# Quickstart

Needs Node 22+ and the GitHub CLI (`gh`), signed in.

```bash
npm i -g github:ao3575911/botproof        # or: npx botproof (once on npm)
botproof init --bot https://x.ai/bot/<id> --name "My Bot"   # asks for a key passphrase
botproof link github <you>                 # prints a line: put it in a public gist
botproof link github <you> --proof <gist-url>
botproof challenge                         # prints a code: add it to the bot's description, update its share template
botproof sign && botproof publish          # opens a PR to the registry; CI checks it
botproof verify grok/<id>
```

**Web bots:** `botproof init --platform web --bot <name>`, then `botproof challenge --url <url>` where the URL is one of your own gists, or a page on a domain you proved with `botproof link dns <domain>`.
