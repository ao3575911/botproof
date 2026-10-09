import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { Doc, ID_RE, docHash, slug, verifyDoc } from "./core.js";
import { checkChallenge, checkDns, checkGithub, checkPlatformSignature } from "./proofs.js";

type Fetch = typeof fetch;
export type Strength = "self-claimed" | "challenge-passed" | "platform-signed" | "revoked";
export type Bundle = { manifest: Doc; creator?: Doc; attestations: Doc[]; attesters: Record<string, Doc>; revocations: Doc[] };
type Link = { type: string; user?: string; proof?: string; url?: string; domain?: string };

const W = { github: 50, dns: 35, x: 5 } as Record<string, number>;
const OWN = { "self-claimed": 0, "challenge-passed": 25, "platform-signed": 35, revoked: 0 } as Record<Strength, number>;
const clamp = (n: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, n));

export async function creatorTrust(c: Doc | undefined, f: Fetch = fetch) {
  const links: { type: string; subject: string; status: string; detail: string }[] = [];
  if (!c || !verifyDoc(c)) return { trust: 0, links };
  let trust = 0;
  for (const l of (c.links as Link[]) || []) {
    if (l.type === "github" && l.user && l.proof) {
      const r = await checkGithub(l.user, l.proof, c.key!, f);
      links.push({ type: "github", subject: l.user, status: r.ok ? "verified" : "failed", detail: r.detail });
      if (r.ok) trust += W.github;
    } else if (l.type === "dns" && l.domain) {
      const r = await checkDns(l.domain, c.key!);
      links.push({ type: "dns", subject: l.domain, status: r.ok ? "verified" : "failed", detail: r.detail });
      if (r.ok) trust += W.dns;
    } else if (l.type === "x" && l.url) {
      links.push({ type: "x", subject: l.url, status: "self-claimed", detail: "X posts are not fetched in v0" });
      trust += W.x;
    }
  }
  return { trust: clamp(trust, 0, 100), links };
}

export async function evaluate(b: Bundle, f: Fetch = fetch) {
  const m = b.manifest, errors: string[] = [];
  if (!verifyDoc(m)) errors.push("manifest signature invalid");
  if (!b.creator) errors.push("creator not found");
  else if (b.creator.handle !== m.creator || b.creator.key !== m.key) errors.push("manifest not signed by creator's key");
  const docs = [m, ...b.attestations];
  const revoked = new Set<string>();
  for (const r of b.revocations) {
    const t = docs.find((d) => docHash(d) === r.target);
    if (t && verifyDoc(r) && r.key === t.key) revoked.add(r.target as string);
  }
  const ct = await creatorTrust(errors.length ? undefined : b.creator, f);
  let strength: Strength = "self-claimed";
  const ch = m.challenge as { nonce: string; url: string } | undefined;
  if (errors.length) strength = "self-claimed";
  else if (revoked.has(docHash(m))) strength = "revoked";
  else if ((await checkPlatformSignature(m.platformEvidence)).ok) strength = "platform-signed";
  else if (ch?.nonce && ch.url && (await checkChallenge(ch.url, ch.nonce, f)).ok) strength = "challenge-passed";
  const attestations = [];
  let reviews = 0;
  for (const a of b.attestations) {
    let status = "counted", weight = 0;
    const who = b.attesters[a.attester as string];
    if (!verifyDoc(a)) status = "bad signature";
    else if (revoked.has(docHash(a))) status = "revoked";
    else if (a.platform !== m.platform || a.botId !== m.botId) status = "wrong bot";
    else if (a.attester === m.creator || a.key === m.key) status = "self-review rejected";
    else if (!who || who.key !== a.key) status = "unknown attester";
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
    creator: m.creator, creatorTrust: ct.trust, links: ct.links, strength, score, breakdown, attestations, errors,
    checkedAt: new Date().toISOString(),
  };
}

const readJson = (p: string) => JSON.parse(readFileSync(p, "utf8")) as Doc;
const jsonFiles = (d: string): string[] => !existsSync(d) ? [] : readdirSync(d, { withFileTypes: true })
  .flatMap((e) => e.isDirectory() ? jsonFiles(join(d, e.name)) : e.name.endsWith(".json") ? [join(d, e.name)] : []);

export function load(dir: string) {
  const creators: Record<string, Doc> = {};
  for (const p of jsonFiles(join(dir, "creators"))) { const c = readJson(p); creators[c.handle as string] = c; }
  const revocations = jsonFiles(join(dir, "revocations")).map(readJson);
  const bots: { path: string; bundle: Bundle }[] = [];
  const root = join(dir, "bots");
  const dirs = (d: string) => readdirSync(d, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
  for (const plat of existsSync(root) ? dirs(root) : []) for (const id of dirs(join(root, plat))) {
    const base = join(root, plat, id), mp = join(base, "manifest.json");
    if (!existsSync(mp)) continue;
    const manifest = readJson(mp);
    bots.push({ path: base, bundle: {
      manifest, creator: creators[manifest.creator as string], revocations, attesters: creators,
      attestations: jsonFiles(join(base, "attestations")).map(readJson),
    } });
  }
  return { creators, revocations, bots };
}

/** Structural and live checks run on every registry PR. Returns a list of errors. */
export async function check(dir: string, f: Fetch = fetch): Promise<string[]> {
  const errs: string[] = [];
  const all = [...jsonFiles(join(dir, "creators")), ...jsonFiles(join(dir, "bots")), ...jsonFiles(join(dir, "revocations"))];
  const hashes = new Map<string, Doc>();
  for (const p of all) {
    const rel = relative(dir, p);
    let d: Doc;
    try { d = readJson(p); } catch { errs.push(`${rel}: invalid JSON`); continue; }
    if (!verifyDoc(d)) errs.push(`${rel}: bad signature`);
    hashes.set(docHash(d), d);
  }
  const { creators, revocations, bots } = load(dir);
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
    if (!bundle.creator) errs.push(`${rel}: creator ${m.creator} not registered`);
    else if (bundle.creator.key !== m.key) errs.push(`${rel}: manifest not signed by creator's key`);
    for (const a of bundle.attestations) {
      if (a.platform !== m.platform || a.botId !== m.botId) errs.push(`${rel}: attestation for another bot`);
      if (a.attester === m.creator || a.key === m.key) errs.push(`${rel}: self-review rejected (${a.attester})`);
      const who = creators[a.attester as string];
      if (!who || who.key !== a.key) errs.push(`${rel}: attester ${a.attester} not registered with this key`);
    }
  }
  for (const r of revocations) {
    const t = hashes.get(r.target as string);
    if (!t) errs.push(`revocation ${r.target}: target not found`);
    else if (t.key !== r.key) errs.push(`revocation ${r.target}: only the original signer can revoke`);
  }
  return errs;
}

const COLORS: Record<string, string> = { "challenge-passed": "#2ea44f", "platform-signed": "#0969da", "self-claimed": "#8b949e", revoked: "#cf222e" };
const esc = (s: string) => s.replace(/[<>&"]/g, (c) => `&#${c.charCodeAt(0)};`);

export function badge(strength: string, score: number): string {
  const l = "botproof", r = `${strength} · ${score}`;
  const lw = 6 * l.length + 12, rw = Math.round(6.2 * r.length) + 12, w = lw + rw;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(l)}: ${esc(r)}">` +
    `<rect width="${lw}" height="20" fill="#24292f"/><rect x="${lw}" width="${rw}" height="20" fill="${COLORS[strength] || "#8b949e"}"/>` +
    `<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">` +
    `<text x="6" y="14">${esc(l)}</text><text x="${lw + 6}" y="14">${esc(r)}</text></g></svg>`;
}

/** Build the static Pages site: JSON API + SVG badges. */
export async function build(dir: string, out: string, f: Fetch = fetch) {
  const put = (p: string, s: string) => { mkdirSync(dirname(join(out, p)), { recursive: true }); writeFileSync(join(out, p), s); };
  const { creators, bots } = load(dir);
  const index = [];
  for (const { bundle } of bots) {
    const res = await evaluate(bundle, f);
    const key = `${res.platform}/${res.botId}`;
    const attesters = Object.fromEntries(bundle.attestations.map((a) => [a.attester, creators[a.attester as string]]).filter(([, c]) => c));
    put(`api/bots/${key}.json`, JSON.stringify({ ...res, docs: { ...bundle, attesters } }, null, 2));
    put(`badge/${key}.svg`, badge(res.strength, res.score));
    index.push({ platform: res.platform, botId: res.botId, name: res.name, creator: res.creator, strength: res.strength, score: res.score, api: `api/bots/${key}.json`, badge: `badge/${key}.svg` });
  }
  for (const [h, c] of Object.entries(creators)) {
    const t = await creatorTrust(c, f);
    put(`api/creators/${slug(h)}.json`, JSON.stringify({ handle: h, key: c.key, ...t, doc: c }, null, 2));
  }
  put("api/index.json", JSON.stringify({ generatedAt: new Date().toISOString(), bots: index }, null, 2));
  const rows = index.map((b) => `<tr><td>${esc(String(b.name || b.botId))}</td><td>${esc(String(b.creator))}</td><td><a href="${b.api}"><img src="${b.badge}" alt="${esc(b.strength)}"></a></td></tr>`).join("");
  put("index.html", `<!doctype html><meta charset="utf-8"><title>botproof registry</title><style>body{font:15px system-ui;max-width:720px;margin:40px auto;padding:0 16px}td{padding:6px 12px 6px 0}</style><h1>botproof registry</h1><p>Signed identity for AI agents. <a href="api/index.json">JSON API</a> · <a href="https://github.com/ao3575911/botproof">CLI</a></p><table><tr><th align=left>Bot</th><th align=left>Creator</th><th align=left>Proof</th></tr>${rows}</table>`);
  return index;
}
