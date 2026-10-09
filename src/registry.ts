import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { Doc, ID_RE, PLATFORMS, docHash, slug, verifyDoc, verifyRotation } from "./core.js";
import { githubStanding, GIST_URL, GROK_SHARE, NONCE_RE, challengeText, checkChallenge, checkX, checkDns, checkGithub } from "./proofs.js";
import { Platform, checkPlatformEvidence } from "./platform.js";
import { creatorErrors, docErrors } from "./rules.js";

type Fetch = typeof fetch;
export type Strength = "self-claimed" | "challenge-passed" | "platform-signed" | "revoked";
export type Bundle = { manifest: Doc; creator?: Doc; attestations: Doc[]; attesters: Record<string, Doc>; revocations: Doc[]; versions?: Doc[]; keyRevocations?: Doc[]; platforms?: Platform[] };

/** Valid key revocations: signed by the revoked key itself. Returns key → since (ms). */
export function revokedKeys(docs: Doc[] = []): Map<string, number> {
  const out = new Map<string, number>();
  for (const d of docs) if (d.type === "key-revocation" && verifyDoc(d) && d.key === d.revokedKey) {
    const since = Date.parse(String(d.since));
    if (!Number.isNaN(since)) out.set(String(d.key), Math.min(since, out.get(String(d.key)) ?? Infinity));
  }
  return out;
}
const revokedAt = (rk: Map<string, number>, d: Doc) => rk.has(String(d.key)) && !(Date.parse(String(d.ts)) < rk.get(String(d.key))!);
type Link = { type: string; user?: string; proof?: string; url?: string; domain?: string };

const W = { github: 50, dns: 35, x: 20, xClaimed: 5 } as Record<string, number>;
const OWN = { "self-claimed": 0, "challenge-passed": 25, "platform-signed": 35, revoked: 0 } as Record<Strength, number>;
const clamp = (n: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, n));

export async function creatorTrust(c: Doc | undefined, f: Fetch = fetch) {
  const links: { type: string; subject: string; status: string; detail: string }[] = [];
  if (!c || !verifyDoc(c)) return { trust: 0, links };
  let trust = 0;
  for (const l of (c.links as Link[]) || []) {
    if (l.type === "github" && l.user && l.proof) {
      const r = await checkGithub(l.user, l.proof, c.key!, f);
      const st = r.ok ? await githubStanding(l.user, f) : undefined;
      links.push({ type: "github", subject: l.user, status: r.ok ? "verified" : "failed", detail: st ? `${r.detail}; ${st.detail}` : r.detail });
      // New accounts are capped: established 50, under a year 35, new or unknown 15.
      if (st) trust += st.level === "established" ? W.github : st.level === "young" ? 35 : 15;
    } else if (l.type === "dns" && l.domain) {
      const r = await checkDns(l.domain, c.key!);
      links.push({ type: "dns", subject: l.domain, status: r.ok ? "verified" : "failed", detail: r.detail });
      if (r.ok) trust += W.dns;
    } else if (l.type === "x" && l.url) {
      const r = await checkX(l.url, c.key!, f);
      const status = r.ok ? "verified" : r.reachable ? "failed" : "self-claimed";
      links.push({ type: "x", subject: l.url, status, detail: r.detail });
      trust += r.ok ? W.x : status === "self-claimed" ? W.xClaimed : 0;
    }
  }
  return { trust: clamp(trust, 0, 100), links };
}

const githubUser = (h: unknown) => String(h).match(/^github:([A-Za-z0-9-]+)$/)?.[1];

/** Where a bot's challenge may live: grok → its own share page; web → the creator's gist or a DNS-proven domain. */
export function challengeUrlError(m: Doc, url: string, links: { type: string; subject: string; status: string }[]): string | undefined {
  if (m.platform === "grok") return url.match(GROK_SHARE)?.[1] === m.botId ? undefined : `grok challenge must be on https://x.ai/bot/${m.botId}`;
  if (m.platform === "web") {
    const g = url.match(GIST_URL);
    if (g) return g[1].toLowerCase() === githubUser(m.creator)?.toLowerCase() ? undefined : "web challenge gist must belong to the creator";
    let host = "";
    try { const u = new URL(url); if (u.protocol === "https:") host = u.hostname.toLowerCase(); } catch { /* invalid */ }
    const domains = links.filter((l) => l.type === "dns" && l.status === "verified").map((l) => l.subject);
    return host && domains.some((d) => host === d || host.endsWith("." + d)) ? undefined : "web challenge must be on the creator's gist or a DNS-proven domain";
  }
  return `unsupported platform ${m.platform}`;
}

export type EvalOpts = { trust?: string[] };
export async function evaluate(b: Bundle, f: Fetch = fetch, opts: EvalOpts = {}) {
  const m = b.manifest, errors: string[] = [...docErrors(m).map((e) => `manifest: ${e}`), ...creatorErrors(b.creator)];
  if (m.type !== "bot") errors.push("manifest: type must be bot");
  if (b.creator && (b.creator.handle !== m.creator || b.creator.key !== m.key)) errors.push("manifest not signed by creator's key");
  const rk = revokedKeys(b.keyRevocations);
  if (rk.has(String(m.key))) errors.push("manifest signed by a revoked key");
  if (b.creator && rk.has(String(b.creator.key))) errors.push("creator profile signed by a revoked key");
  const newer = (b.versions || []).find((v) => verifyDoc(v) && v.creator === m.creator && v.platform === m.platform && v.botId === m.botId && Number(v.seq) > Number(m.seq));
  if (newer) errors.push(`rolled back: a newer signed version exists (seq ${newer.seq})`);
  const docs = [m, ...b.attestations];
  const revoked = new Set<string>();
  for (const r of b.revocations) {
    const t = docs.find((d) => docHash(d) === r.target);
    if (t && verifyDoc(r) && r.key === t.key && !revokedAt(rk, r)) revoked.add(r.target as string);
  }
  const ct = await creatorTrust(errors.length ? undefined : b.creator, f);
  let strength: Strength = "self-claimed", ownershipDetail = "no challenge";
  const ch = m.challenge as { nonce: string; url: string; issued?: string } | undefined;
  const urlErr = ch ? challengeUrlError(m, ch.url, ct.links) : undefined;
  const code = ch?.nonce ? challengeText(String(m.platform), String(m.botId), String(m.key), ch.nonce) : "";
  if (errors.length) ownershipDetail = "invalid claim";
  else if (revoked.has(docHash(m))) { strength = "revoked"; ownershipDetail = "withdrawn by the creator"; }
  else if (ch?.nonce && ch.url) {
    if (urlErr) ownershipDetail = urlErr;
    else {
      const r = await checkChallenge(ch.url, code, f, githubUser(m.creator));
      ownershipDetail = r.detail;
      if (r.ok) strength = "challenge-passed";
    }
  }
  // Platform evidence only upgrades a claim whose own challenge passed; it never replaces it.
  if (strength === "challenge-passed" && m.platformEvidence) {
    const pe = await checkPlatformEvidence(m.platformEvidence, { code, issued: ch?.issued, platforms: b.platforms }, f);
    if (pe.ok) { strength = "platform-signed"; ownershipDetail = pe.detail; }
    else ownershipDetail += `; platform evidence: ${pe.detail}`;
  }
  const attestations = [];
  let reviews = 0;
  for (const a of b.attestations) {
    let status = "counted", weight = 0;
    const who = b.attesters[a.attester as string];
    const whoBad = creatorErrors(who).length > 0;
    if (docErrors(a).length || a.type !== "attestation") status = "invalid";
    else if (revoked.has(docHash(a))) status = "revoked";
    else if (revokedAt(rk, a)) status = "key revoked";
    else if (a.platform !== m.platform || a.botId !== m.botId) status = "wrong bot";
    else if (a.versionHash !== docHash(m)) status = "earlier version";
    else if (a.attester === m.creator || a.key === m.key) status = "self-review rejected";
    else if (!who || who.key !== a.key) status = "unknown attester";
    else if (whoBad) status = "attester invalid";
    else if (opts.trust && !opts.trust.map((x) => x.toLowerCase()).includes(String(a.attester).toLowerCase())) status = "not in your trust list";
    else if (!["established", "young"].includes((await githubStanding(String(a.attester).replace(/^github:/, ""), f)).level)) status = "new account (under 90 days), not counted";
    else {
      const t = (await creatorTrust(who, f)).trust;
      weight = Math.round((t / 100) * 10 * (a.tag === "flagged" ? -1 : 1));
      reviews += weight;
    }
    attestations.push({ attester: a.attester, tag: a.tag, note: a.note, ts: a.ts, hash: docHash(a), weight, status });
  }
  const breakdown = { identity: Math.round(ct.trust * 0.4), ownership: OWN[strength], reviews: clamp(reviews, -30, 30) };
  const score = strength === "revoked" || errors.length ? 0 : clamp(breakdown.identity + breakdown.ownership + breakdown.reviews, 0, 100);
  return {
    platform: m.platform, botId: m.botId, name: m.name, version: m.version, versionHash: docHash(m),
    creator: m.creator, creatorTrust: ct.trust, links: ct.links, strength, ownershipDetail, score, breakdown, attestations, errors,
    checkedAt: new Date().toISOString(),
  };
}

const readJson = (p: string) => {
  try { return JSON.parse(readFileSync(p, "utf8")) as Doc; } catch { throw new Error(`${p}: invalid JSON`); }
};
const jsonFiles = (d: string): string[] => !existsSync(d) ? [] : readdirSync(d, { withFileTypes: true })
  .flatMap((e) => e.isDirectory() ? jsonFiles(join(d, e.name)) : e.name.endsWith(".json") ? [join(d, e.name)] : []);

export function load(dir: string) {
  const creators: Record<string, Doc> = {};
  for (const p of jsonFiles(join(dir, "creators"))) { const c = readJson(p); creators[c.handle as string] = c; }
  const revocations = jsonFiles(join(dir, "revocations")).map(readJson);
  const keyDocs = jsonFiles(join(dir, "keys")).map(readJson);
  const keyRevocations = keyDocs.filter((d) => d.type === "key-revocation");
  let platforms: Platform[] | undefined;
  if (existsSync(join(dir, "platforms.json"))) platforms = (JSON.parse(readFileSync(join(dir, "platforms.json"), "utf8"))["web-bot-auth"] || []) as Platform[];
  const bots: { path: string; bundle: Bundle }[] = [];
  const root = join(dir, "bots");
  const dirs = (d: string) => readdirSync(d, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  for (const plat of existsSync(root) ? dirs(root) : []) for (const id of dirs(join(root, plat))) {
    const base = join(root, plat, id), mp = join(base, "manifest.json");
    if (!existsSync(mp)) continue;
    const manifest = readJson(mp);
    bots.push({ path: base, bundle: {
      manifest, creator: creators[manifest.creator as string], revocations, attesters: creators, keyRevocations, platforms,
      attestations: jsonFiles(join(base, "attestations")).map(readJson),
      versions: jsonFiles(join(base, "versions")).map(readJson),
    } });
  }
  return { creators, revocations, bots, keyDocs, keyRevocations };
}

/** Structural and live checks run on every registry PR. Returns a list of errors. */
export type CheckOpts = { baseDir?: string; author?: string };

/** Every signed file under the registry, by relative path. */
function signedFiles(dir: string): Map<string, Doc | undefined> {
  const out = new Map<string, Doc | undefined>();
  for (const p of ["creators", "bots", "revocations", "keys"].flatMap((d) => jsonFiles(join(dir, d)))) {
    let d: Doc | undefined;
    try { d = readJson(p); } catch { d = undefined; }
    out.set(relative(dir, p), d);
  }
  return out;
}

/**
 * Pull-request rules, comparing the PR head with its base:
 * signed files are append-only; a bot keeps its owner unless the owner signs a transfer;
 * and the PR author must be the GitHub account behind every signature it adds or changes.
 */
function checkChange(dir: string, baseDir: string, author: string | undefined, errs: string[]) {
  const head = signedFiles(dir), base = signedFiles(baseDir);
  const hc = load(dir).creators, bc = load(baseDir).creators;
  const keyOwner = new Map<string, string>();
  for (const c of [...Object.values(bc), ...Object.values(hc)]) if (c.key) keyOwner.set(c.key, String(c.handle));
  for (const [rel, d] of base) if (d && !head.has(rel)) errs.push(`${rel}: signed files can't be deleted`);
  const touched = [...head].filter(([rel, d]) => !d || !base.get(rel) || docHash(d) !== docHash(base.get(rel)!));
  const rk = revokedKeys([...head.values()].filter((d): d is Doc => !!d));
  for (const [rel, d] of touched) {
    if (!d) continue;
    if (d.type !== "key-revocation" && rk.has(String(d.key))) errs.push(`${rel}: signed by a revoked key`);
    if (d.type === "key-revocation" && d.key !== d.revokedKey) errs.push(`${rel}: a key can only be revoked by itself`);
    if (d.type === "key-rotation" && !verifyRotation(d)) errs.push(`${rel}: rotation needs signatures from both keys`);
    if (rel.endsWith("/manifest.json") && base.get(rel)) {
      const old = base.get(rel)!;
      if (!(Number(d.seq) > Number(old.seq))) errs.push(`${rel}: seq must increase (was ${old.seq}, now ${d.seq}); rollback rejected`);
      if (d.creator !== old.creator) {
        const tdir = join(dir, dirname(rel), "transfers");
        const ok = jsonFiles(tdir).map(readJson).some((t) => t.type === "transfer" && verifyDoc(t) && t.key === old.key &&
          t.platform === d.platform && t.botId === d.botId && t.to === d.creator && t.toKey === d.key);
        if (!ok) errs.push(`${rel}: owned by ${old.creator}; a new owner needs a transfer signed by their key`);
      } else if (d.key !== old.key && !(hc[String(d.creator)]?.key === d.key && bc[String(old.creator)]?.key === old.key))
        errs.push(`${rel}: owned by ${old.creator} with another key`);
    }
    if (author) {
      const signer = d.type === "creator" || d.type === "key-rotation" ? String(d.handle) : keyOwner.get(String(d.key));
      if (!signer) errs.push(`${rel}: signed by a key no registered creator holds`);
      else if (signer.toLowerCase() !== `github:${author.toLowerCase()}`) errs.push(`${rel}: signed by ${signer}, but the PR author is @${author}`);
    }
  }
}

export async function check(dir: string, f: Fetch = fetch, opts: CheckOpts = {}): Promise<string[]> {
  const errs: string[] = [];
  const all = ["creators", "bots", "revocations", "keys"].flatMap((x) => jsonFiles(join(dir, x)));
  const hashes = new Map<string, Doc>();
  for (const p of all) {
    const rel = relative(dir, p);
    let d: Doc;
    try { d = JSON.parse(readFileSync(p, "utf8")) as Doc; } catch { errs.push(`${rel}: invalid JSON`); continue; }
    for (const e of docErrors(d)) errs.push(`${rel}: ${e}`);
    hashes.set(docHash(d), d);
  }
  if (errs.some((e) => e.endsWith("invalid JSON"))) return errs;
  const { creators, revocations, bots } = load(dir);
  for (const c of Object.values(creators)) errs.push(...creatorErrors(c));
  for (const [h, c] of Object.entries(creators)) {
    const gh = h.match(/^github:([A-Za-z0-9-]+)$/);
    if (!gh) { errs.push(`creator ${h}: handle must be github:<user> in v0`); continue; }
    if (!existsSync(join(dir, "creators", slug(h) + ".json"))) errs.push(`creator ${h}: file must be creators/${slug(h)}.json`);
    const link = ((c.links as Link[]) || []).find((l) => l.type === "github" && l.user?.toLowerCase() === gh[1].toLowerCase());
    if (!link) { errs.push(`creator ${h}: missing github link`); continue; }
    const r = await checkGithub(link.user!, link.proof || "", c.key!, f);
    if (!r.ok) errs.push(`creator ${h}: github proof failed (${r.detail})`);
  }
  for (const { path, bundle } of bots) {
    const m = bundle.manifest, rel = relative(dir, path);
    if (!ID_RE.test(String(m.botId)) || rel !== join("bots", String(m.platform), String(m.botId))) errs.push(`${rel}: path must be bots/<platform>/<botId>`);
    if (!Number.isSafeInteger(m.seq) || Number(m.seq) < 1) errs.push(`${rel}: manifest needs a positive integer seq`);
    if (!existsSync(join(path, "versions", docHash(m) + ".json"))) errs.push(`${rel}: missing versions/${docHash(m)}.json`);
    for (const v of bundle.versions || []) if (Number(v.seq) > Number(m.seq) && v.creator === m.creator) errs.push(`${rel}: rolled back below seq ${v.seq}`);
    if (!bundle.creator) errs.push(`${rel}: creator ${m.creator} not registered`);
    else if (bundle.creator.key !== m.key) errs.push(`${rel}: manifest not signed by creator's key`);
    for (const a of bundle.attestations) {
      if (a.platform !== m.platform || a.botId !== m.botId) errs.push(`${rel}: attestation for another bot`);
      if (a.attester === m.creator || a.key === m.key) errs.push(`${rel}: self-review rejected (${a.attester})`);
      const who = creators[a.attester as string];
      if (!who || who.key !== a.key) errs.push(`${rel}: attester ${a.attester} not registered with this key`);
    }
  }
  const nonces = new Map<string, string>();
  for (const d of hashes.values()) {
    const ch = d.type === "bot" ? (d.challenge as { nonce?: string } | undefined) : undefined;
    if (!ch) continue;
    if (!NONCE_RE.test(String(ch.nonce))) { errs.push(`${d.platform}/${d.botId}: bad challenge nonce`); continue; }
    const owner = `${d.platform}/${d.botId}:${d.key}`, prev = nonces.get(ch.nonce!);
    if (prev && prev !== owner) errs.push(`${d.platform}/${d.botId}: challenge code reused from another bot or key`);
    else nonces.set(ch.nonce!, owner);
  }
  for (const r of revocations) {
    const t = hashes.get(r.target as string);
    if (!t) errs.push(`revocation ${r.target}: target not found`);
    else if (t.key !== r.key) errs.push(`revocation ${r.target}: only the original signer can revoke`);
  }
  if (opts.baseDir) checkChange(dir, opts.baseDir, opts.author, errs);
  return errs;
}

const COLORS: Record<string, string> = { "challenge-passed": "#2ea44f", "platform-signed": "#0969da", "self-claimed": "#57606a", revoked: "#cf222e" };
const esc = (s: string) => s.replace(/[<>&"'`]/g, (c) => `&#${c.charCodeAt(0)};`);

/** Badge text: the proof label, not the score (the score is in the API). */
export function badgeLabel(strength: string, creatorVerified: boolean): string {
  if (strength === "challenge-passed" || strength === "platform-signed") return `✓ ${strength}`;
  if (strength === "self-claimed" && creatorVerified) return "✓ verified creator";
  return strength;
}

export function badge(strength: string, label = badgeLabel(strength, false)): string {
  const l = "botproof", r = label;
  const lw = 6 * l.length + 12, rw = Math.round(6.2 * r.length) + 12, w = lw + rw;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(l)}: ${esc(r)}">` +
    `<rect width="${lw}" height="20" fill="#24292f"/><rect x="${lw}" width="${rw}" height="20" fill="${COLORS[strength] || "#8b949e"}"/>` +
    `<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">` +
    `<text x="6" y="14">${esc(l)}</text><text x="${lw + 6}" y="14">${esc(r)}</text></g></svg>`;
}

/** Build the static Pages site: JSON API + SVG badges. */
/** Per-build cache: each URL is fetched once per build, however many bots point at it. */
export function cachedFetch(f: Fetch): Fetch {
  const seen = new Map<string, Promise<{ status: number; headers: [string, string][]; body: ArrayBuffer }>>();
  return (async (url: string, init?: RequestInit) => {
    const k = String(url);
    if (!seen.has(k)) seen.set(k, f(url, init).then(async (r) => ({ status: r.status, headers: [...r.headers], body: await r.arrayBuffer() })));
    const c = await seen.get(k)!;
    return new Response(c.status === 204 ? null : c.body.slice(0), { status: c.status, headers: c.headers });
  }) as Fetch;
}

/** sha256 (docHash) of every signed file, by path: the index clients pin against. */
export function docIndex(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [rel, d] of signedFiles(dir)) if (d) out[rel] = docHash(d);
  return out;
}

export async function build(dir: string, out: string, f0: Fetch = fetch, registryCommit = process.env.GITHUB_SHA || "") {
  const f = cachedFetch(f0);
  const put = (p: string, s: string) => { mkdirSync(dirname(join(out, p)), { recursive: true }); writeFileSync(join(out, p), s); };
  const { creators, bots } = load(dir);
  const index = [];
  for (const { bundle } of bots) {
    if (!PLATFORMS.includes(String(bundle.manifest.platform)) || !ID_RE.test(String(bundle.manifest.botId))) continue;
    const res = await evaluate(bundle, f);
    const key = `${res.platform}/${res.botId}`;
    const attesters = Object.fromEntries(bundle.attestations.map((a) => [a.attester, creators[a.attester as string]]).filter(([, c]) => c));
    put(`api/bots/${key}.json`, JSON.stringify({ ...res, docs: { ...bundle, attesters } }, null, 2));
    put(`badge/${key}.svg`, badge(res.strength, badgeLabel(res.strength, res.links.some((x) => x.type === "github" && x.status === "verified"))));
    index.push({ platform: res.platform, botId: res.botId, name: res.name, creator: res.creator, strength: res.strength, score: res.score, api: `api/bots/${key}.json`, badge: `badge/${key}.svg` });
  }
  for (const [h, c] of Object.entries(creators)) {
    const t = await creatorTrust(c, f);
    put(`api/creators/${slug(h)}.json`, JSON.stringify({ handle: h, key: c.key, ...t, doc: c }, null, 2));
  }
  put("api/index.json", JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), registryCommit, bots: index, docs: docIndex(dir) }, null, 2));
  const rows = index.map((b) => `<tr><td>${esc(String(b.name || b.botId))}</td><td>${esc(String(b.creator))}</td><td><a href="${esc(b.api)}"><img src="${esc(b.badge)}" alt="${esc(b.strength)}"></a></td></tr>`).join("");
  put("index.html", `<!doctype html><meta charset="utf-8"><title>botproof registry</title><style>body{font:15px system-ui;max-width:720px;margin:40px auto;padding:0 16px}td{padding:6px 12px 6px 0}</style><h1>botproof registry</h1><p>Signed identity for AI agents. <a href="api/index.json">JSON API</a> · <a href="https://github.com/ao3575911/botproof">CLI</a></p><table><tr><th align=left>Bot</th><th align=left>Creator</th><th align=left>Proof</th></tr>${rows}</table>`);
  return index;
}
