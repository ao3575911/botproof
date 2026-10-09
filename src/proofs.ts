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

/** Bot challenge: the bot's public page shows the one-time code. */
export async function checkChallenge(url: string, nonce: string, f: Fetch = fetch): Promise<Check> {
  try {
    const gist = url.match(/^https:\/\/gist\.github\.com\/(?:[\w-]+\/)?([0-9a-f]+)\/?$/i);
    const target = gist ? `https://api.github.com/gists/${gist[1]}` : url;
    const r = await f(target, { headers: gist ? ghHeaders(false, false) : { "user-agent": "botproof" } });
    if (!r.ok) return { ok: false, detail: `fetch ${r.status}` };
    const body = (await r.text()).slice(0, 2_000_000);
    return body.includes(challengeText(nonce)) ? { ok: true, detail: "challenge code found" } : { ok: false, detail: "challenge code not found" };
  } catch (e) { return { ok: false, detail: String(e) }; }
}

/** Platform signatures (Web Bot Auth, signed A2A cards). Stub in v0: see issue tracker. */
export async function checkPlatformSignature(_evidence: unknown): Promise<Check> {
  return { ok: false, detail: "platform signatures not supported in v0" };
}
