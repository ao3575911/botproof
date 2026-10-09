# For consumers

```bash
botproof verify grok/<id>                       # exit 0 ok, 2 invalid/revoked
botproof verify grok/<id> --min-strength challenge-passed   # exit 3 below it
botproof verify grok/<id> --trust alice,bob     # only count reviews from your list
botproof verify grok/<id> --git                 # from a registry clone, not the API
```

GitHub Action:

```yaml
- uses: ao3575911/botproof@v0.3.2
  id: bot
  with:
    bot: grok/<id>
    min-strength: challenge-passed
- run: echo "${{ steps.bot.outputs.strength }} ${{ steps.bot.outputs.score }}"
```
