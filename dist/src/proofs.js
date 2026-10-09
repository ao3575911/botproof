import { resolveTxt } from "node:dns/promises";
export const FETCH_TIMEOUT_MS = 10_000, FETCH_MAX_BYTES = 2_000_000;
/** All network reads: https only, 10s timeout, bodies capped at 2 MB. */
export async function safeGet(f, url, init = {}) {
    if (!url.startsWith("https://"))
        throw new Error("only https URLs are fetched");
    const r = await f(url, { ...init, redirect: "error", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    const chunks = [];
    let n = 0;
    if (r.body)
        for await (const c of r.body) {
            n += c.length;
            if (n > FETCH_MAX_BYTES)
                throw new Error("response too large");
            chunks.push(c);
        }
    return new Response(r.status === 204 ? null : Buffer.concat(chunks), { status: r.status, headers: r.headers });
}
export const proofText = (kind, subject, key) => `botproof-proof:${kind}:${subject}:${key}`;
/** The code a creator shows on the bot's page. Bound to the bot and the creator's key, so it can't be reused. */
export const challengeText = (platform, botId, key, nonce) => `botproof-challenge:${platform}/${botId}:${key}:${nonce}`;
export const NONCE_RE = /^[0-9a-f]{18}$/;
export const GIST_URL = /^https:\/\/gist\.github\.com\/([A-Za-z0-9-]+)\/([0-9a-f]+)\/?$/i;
// Gists are fetched without a token: Actions tokens get 403 on the gists API.
function ghHeaders(raw = false, auth = !!process.env.GITHUB_TOKEN) {
    const h = { "user-agent": "botproof", accept: raw ? "application/vnd.github.raw" : "application/vnd.github+json" };
    if (auth)
        h.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    return h;
}
/** GitHub link: a public gist owned by the user, or the user's profile README, contains the proof text. */
export async function checkGithub(user, proof, key, f = fetch) {
    const text = proofText("github", user.toLowerCase(), key);
    try {
        const gist = proof.match(/^https:\/\/gist\.github\.com\/(?:[\w-]+\/)?([0-9a-f]+)\/?$/i);
        if (gist) {
            const r = await safeGet(f, `https://api.github.com/gists/${gist[1]}`, { headers: ghHeaders(false, false) });
            if (!r.ok)
                return { ok: false, detail: `gist fetch ${r.status}` };
            const g = (await r.json());
            if (g.owner?.login?.toLowerCase() !== user.toLowerCase())
                return { ok: false, detail: "gist not owned by " + user };
            const found = Object.values(g.files || {}).some((x) => (x.content || "").includes(text));
            return found ? { ok: true, detail: "gist proof found" } : { ok: false, detail: "proof text not in gist" };
        }
        if (proof === "readme" || proof.toLowerCase() === `https://github.com/${user}/${user}`.toLowerCase()) {
            const r = await safeGet(f, `https://api.github.com/repos/${user}/${user}/readme`, { headers: ghHeaders(true) });
            if (!r.ok)
                return { ok: false, detail: `readme fetch ${r.status}` };
            return (await r.text()).includes(text) ? { ok: true, detail: "profile README proof found" } : { ok: false, detail: "proof text not in profile README" };
        }
        return { ok: false, detail: "proof must be a gist URL or 'readme'" };
    }
    catch (e) {
        return { ok: false, detail: String(e) };
    }
}
/** DNS link: TXT record at _botproof.<domain> contains the proof text. */
export async function checkDns(domain, key) {
    try {
        const txt = (await resolveTxt(`_botproof.${domain}`)).map((r) => r.join(""));
        return txt.includes(proofText("dns", domain.toLowerCase(), key)) ? { ok: true, detail: "TXT proof found" } : { ok: false, detail: "TXT proof missing" };
    }
    catch (e) {
        return { ok: false, detail: String(e) };
    }
}
export const GROK_SHARE = /^https:\/\/x\.ai\/bot\/([A-Za-z0-9_-]{6,64})\/?$/;
const unescapeHtml = (s) => s.replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d)).replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
/** Creator-editable text on a Grok Bot share page (x.ai/bot/<id>): the title and description tags only. */
export function grokPageText(html) {
    const meta = [...html.matchAll(/<meta[^>]+(?:name="description"|property="og:(?:title|description)")[^>]+content="([^"]*)"/g)].map((m) => m[1]);
    const title = html.match(/<title>([^<]*)<\/title>/)?.[1] || "";
    return unescapeHtml([title, ...meta].join("\n"));
}
/** Bot challenge: the bot's public page shows the bound code. A gist must belong to `gistOwner`. */
export async function checkChallenge(url, text, f = fetch, gistOwner) {
    try {
        const gist = url.match(GIST_URL);
        const grok = GROK_SHARE.test(url);
        const target = gist ? `https://api.github.com/gists/${gist[2]}` : url;
        const r = await safeGet(f, target, { headers: gist ? ghHeaders(false, false) : { "user-agent": "botproof" } });
        if (!r.ok)
            return { ok: false, detail: `fetch ${r.status}` };
        let body = await r.text();
        if (gist) {
            const g = JSON.parse(body);
            if (!gistOwner || g.owner?.login?.toLowerCase() !== gistOwner.toLowerCase())
                return { ok: false, detail: "gist not owned by the creator" };
            body = Object.values(g.files || {}).map((x) => x.content || "").join("\n");
        }
        if (grok)
            body = grokPageText(body);
        return body.includes(text)
            ? { ok: true, detail: grok ? "code found on Grok share page" : "challenge code found" }
            : { ok: false, detail: "challenge code not found" };
    }
    catch (e) {
        return { ok: false, detail: String(e) };
    }
}
export async function githubStanding(user, f = fetch, now = Date.now()) {
    try {
        const r = await safeGet(f, `https://api.github.com/users/${encodeURIComponent(user)}`, { headers: ghHeaders() });
        if (!r.ok)
            return { level: "unknown", detail: `account lookup ${r.status}` };
        const u = (await r.json());
        const days = (now - Date.parse(String(u.created_at))) / 86400e3;
        if (!(days >= 90) || (!u.public_repos && !u.followers))
            return { level: "new", detail: `account ${Math.floor(days || 0)} days old` };
        return days >= 365 ? { level: "established", detail: `account ${Math.floor(days / 365)}y old` } : { level: "young", detail: `account ${Math.floor(days)} days old` };
    }
    catch (e) {
        return { level: "unknown", detail: String(e) };
    }
}
export const X_POST = /^https:\/\/(?:x|twitter)\.com\/(\w{1,15})\/status\/(\d+)/;
/**
 * X link: the post contains the proof text and is by that handle. Uses the free embed
 * (syndication) endpoint; if X can't be reached the link stays self-claimed.
 */
export async function checkX(url, key, f = fetch) {
    const m = url.match(X_POST);
    if (!m)
        return { ok: false, reachable: true, detail: "not an X post URL" };
    try {
        const r = await safeGet(f, `https://cdn.syndication.twimg.com/tweet-result?id=${m[2]}&token=a`, { headers: { "user-agent": "botproof" } });
        if (!r.ok)
            return { ok: false, reachable: false, detail: `X fetch ${r.status}` };
        const t = (await r.json());
        const handle = t.user?.screen_name?.toLowerCase();
        if (handle !== m[1].toLowerCase())
            return { ok: false, reachable: true, detail: "post is not by @" + m[1] };
        return (t.text || "").includes(proofText("x", handle, key))
            ? { ok: true, reachable: true, detail: "X post proof found" }
            : { ok: false, reachable: true, detail: "proof text not in post" };
    }
    catch (e) {
        return { ok: false, reachable: false, detail: String(e) };
    }
}
