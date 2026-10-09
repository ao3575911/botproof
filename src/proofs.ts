import { resolveTxt } from "node:dns/promises";

export type Check = { ok: boolean; detail: string };
type Fetch = typeof fetch;

export const proofText = (kind: string, subject: string, key: string) => `botproof-proof:${kind}:${subject}:${key}`;
export const challengeText = (nonce: string) => `botproof-challenge:${nonce}`;

// Gists are fetched without a token: Actions tokens get 403 on the gists API.
function ghHeaders(raw = false, auth = !!process.env.GITHUB_TOKEN): Record<string, string> {
  const h: Record<string, string> = { "user-agent": "botproof", accept: raw ? "application/vnd.github.raw" : "application/vnd.github+json" };
  if (auth) h.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

/** GitHub link: a public gist owned by the user, or the user's profile README, contains the proof text. */
export async function checkGithub(user: string, proof: string, key: string, f: Fetch = fetch): Promise<Check> {
  const text = proofText("github", user.toLowerCase(), key);
  try {
    const gist = proof.match(/^https:\/\/gist\.github\.com\/(?:[\w-]+\/)?([0-9a-f]+)\/?$/i);
    if (gist) {
      const r = await f(`https://api.github.com/gists/${gist[1]}`, { headers: ghHeaders(false, false) });
      if (!r.ok) return { ok: false, detail: `gist fetch ${r.status}` };
      const g = (await r.json()) as { owner?: { login?: string }; files?: Record<string, { content?: string }> };
      if (g.owner?.login?.toLowerCase() !== user.toLowerCase()) return { ok: false, detail: "gist not owned by " + user };
      const found = Object.values(g.files || {}).some((x) => (x.content || "").includes(text));
      return found ? { ok: true, detail: "gist proof found" } : { ok: false, detail: "proof text not in gist" };
    }
    if (proof === "readme" || proof.toLowerCase() === `https://github.com/${user}/${user}`.toLowerCase()) {
      const r = await f(`https://api.github.com/repos/${user}/${user}/readme`, { headers: ghHeaders(true) });
      if (!r.ok) return { ok: false, detail: `readme fetch ${r.status}` };
      return (await r.text()).includes(text) ? { ok: true, detail: "profile README proof found" } : { ok: false, detail: "proof text not in profile README" };
    }
    return { ok: false, detail: "proof must be a gist URL or 'readme'" };
  } catch (e) { return { ok: false, detail: String(e) }; }
}

/** DNS link: TXT record at _botproof.<domain> contains the proof text. */
export async function checkDns(domain: string, key: string): Promise<Check> {
  try {
    const txt = (await resolveTxt(`_botproof.${domain}`)).map((r) => r.join(""));
    return txt.includes(proofText("dns", domain.toLowerCase(), key)) ? { ok: true, detail: "TXT proof found" } : { ok: false, detail: "TXT proof missing" };
  } catch (e) { return { ok: false, detail: String(e) }; }
}

export const GROK_SHARE = /^https:\/\/x\.ai\/bot\/([A-Za-z0-9_-]{6,64})\/?$/;

const unescapeHtml = (s: string) => s.replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
  .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d)).replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

/** Creator-editable text on a Grok Bot share page (x.ai/bot/<id>): name, description and visible text. */
export function grokPageText(html: string): string {
  const meta = [...html.matchAll(/<meta[^>]+(?:name="description"|property="og:(?:title|description)")[^>]+content="([^"]*)"/g)].map((m) => m[1]);
  const title = html.match(/<title>([^<]*)<\/title>/)?.[1] || "";
  const visible = html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/g, " ").replace(/<[^>]+>/g, " ");
  return unescapeHtml([title, ...meta, visible].join("\n"));
}

/** Bot challenge: the bot's public page shows the one-time code. */
export async function checkChallenge(url: string, nonce: string, f: Fetch = fetch): Promise<Check> {
  try {
    const gist = url.match(/^https:\/\/gist\.github\.com\/(?:[\w-]+\/)?([0-9a-f]+)\/?$/i);
    const grok = GROK_SHARE.test(url);
    const target = gist ? `https://api.github.com/gists/${gist[1]}` : url;
    const r = await f(target, { headers: gist ? ghHeaders(false, false) : { "user-agent": "botproof" } });
    if (!r.ok) return { ok: false, detail: `fetch ${r.status}` };
    let body = (await r.text()).slice(0, 2_000_000);
    if (grok) body = grokPageText(body);
    return body.includes(challengeText(nonce))
      ? { ok: true, detail: grok ? "code found on Grok share page" : "challenge code found" }
      : { ok: false, detail: "challenge code not found" };
  } catch (e) { return { ok: false, detail: String(e) }; }
}

export const X_POST = /^https:\/\/(?:x|twitter)\.com\/(\w{1,15})\/status\/(\d+)/;

/**
 * X link: the post contains the proof text and is by that handle. Uses the free embed
 * (syndication) endpoint; if X can't be reached the link stays self-claimed.
 */
export async function checkX(url: string, key: string, f: Fetch = fetch): Promise<Check & { reachable: boolean }> {
  const m = url.match(X_POST);
  if (!m) return { ok: false, reachable: true, detail: "not an X post URL" };
  try {
    const r = await f(`https://cdn.syndication.twimg.com/tweet-result?id=${m[2]}&token=a`, { headers: { "user-agent": "botproof" } });
    if (!r.ok) return { ok: false, reachable: false, detail: `X fetch ${r.status}` };
    const t = (await r.json()) as { text?: string; user?: { screen_name?: string } };
    const handle = t.user?.screen_name?.toLowerCase();
    if (handle !== m[1].toLowerCase()) return { ok: false, reachable: true, detail: "post is not by @" + m[1] };
    return (t.text || "").includes(proofText("x", handle, key))
      ? { ok: true, reachable: true, detail: "X post proof found" }
      : { ok: false, reachable: true, detail: "proof text not in post" };
  } catch (e) { return { ok: false, reachable: false, detail: String(e) }; }
}
