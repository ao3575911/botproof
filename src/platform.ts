/**
 * Platform-signed evidence via Web Bot Auth (HTTP Message Signatures, RFC 9421 + the
 * web-bot-auth drafts). The platform (e.g. ChatGPT agent) signs the requests its agents make
 * and publishes its keys in a signed directory at /.well-known/http-message-signatures-directory.
 *
 * Evidence = one captured request from the bot to a URL containing the creator's challenge code.
 * It proves the creator runs an agent on that platform; it can't name a specific bot account.
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import type { Check } from "./proofs.js";

type Fetch = typeof fetch;
export type Jwk = { kty: string; crv: string; x: string; kid?: string };
export type WebBotAuthEvidence = {
  type: "web-bot-auth";
  request: { method: string; authority: string; path: string; headers: Record<string, string> };
};
export type Parsed = { label: string; params: string; components: { name: string; raw: string }[]; keyid?: string; created?: number; expires?: number; tag?: string; alg?: string; sig: Buffer };

export const thumbprint = (k: Jwk) => createHash("sha256").update(JSON.stringify({ crv: k.crv, kty: k.kty, x: k.x })).digest("base64url");
const lower = (h: Record<string, string>) => Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));

/** Parse one signature from Signature-Input / Signature. Picks the one with `tag`, else the first. */
export function parseSignature(input: string, signature: string, tag?: string): Parsed {
  const entries = input.split(/,\s*(?=[\w-]+=\()/);
  const e = entries.find((x) => tag && x.includes(`tag="${tag}"`)) || entries[0];
  const m = e.match(/^([\w-]+)=(\(([^)]*)\).*)$/);
  if (!m) throw new Error("bad Signature-Input");
  const [, label, params, list] = m;
  const p = (k: string) => params.match(new RegExp(`;${k}=("?)([^;"]*)\\1`))?.[2];
  const s = signature.match(new RegExp(`(?:^|,)\\s*${label}=:([^:]+):`));
  if (!s) throw new Error("signature label not found");
  return {
    label, params, components: [...list.matchAll(/"([^"]+)"((?:;[\w-]+)*)/g)].map((c) => ({ name: c[1], raw: c[0] })),
    keyid: p("keyid"), tag: p("tag"), alg: p("alg"),
    created: p("created") ? Number(p("created")) : undefined, expires: p("expires") ? Number(p("expires")) : undefined,
    sig: Buffer.from(s[1], "base64"),
  };
}

export function signatureBase(p: Parsed, value: (name: string) => string | undefined): string {
  const lines = p.components.map((c) => {
    const v = value(c.name);
    if (v === undefined) throw new Error(`missing component ${c.name}`);
    return `${c.raw}: ${v}`;
  });
  return [...lines, `"@signature-params": ${p.params}`].join("\n");
}

function verifyEd25519(p: Parsed, keys: Jwk[], base: string): string | undefined {
  if (p.alg && p.alg !== "ed25519") return "only ed25519 is supported";
  const k = keys.find((j) => j.kty === "OKP" && j.crv === "Ed25519" && thumbprint(j) === p.keyid);
  if (!k) return "key not in directory";
  const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: k.x }, format: "jwk" });
  return verify(null, Buffer.from(base), pub, p.sig) ? undefined : "bad signature";
}

/** Verify a key directory response is signed by one of its own keys. `now` (seconds) enables expiry checks. */
export function verifyDirectory(authority: string, headers: Record<string, string>, body: Buffer, now?: number): Check & { keys: Jwk[] } {
  try {
    const h = lower(headers);
    const keys = (JSON.parse(body.toString("utf8")).keys || []) as Jwk[];
    if (!h["signature-input"] || !h.signature) return { ok: false, detail: "directory is not signed", keys: [] };
    const p = parseSignature(h["signature-input"], h.signature, "http-message-signatures-directory");
    if (p.tag !== "http-message-signatures-directory") return { ok: false, detail: "no directory signature", keys: [] };
    if (now && p.expires && now > p.expires) return { ok: false, detail: "directory signature expired", keys: [] };
    const digest = "sha-256=:" + createHash("sha256").update(body).digest("base64") + ":";
    if (p.components.some((c) => c.name === "content-digest") && h["content-digest"] !== digest) return { ok: false, detail: "content-digest mismatch", keys: [] };
    const err = verifyEd25519(p, keys, signatureBase(p, (n) => (n === "@authority" ? authority : h[n])));
    return err ? { ok: false, detail: "directory: " + err, keys: [] } : { ok: true, detail: "directory signature valid", keys };
  } catch (e) { return { ok: false, detail: String(e), keys: [] }; }
}

export async function fetchDirectory(origin: string, f: Fetch = fetch): Promise<Check & { keys: Jwk[] }> {
  const url = new URL("/.well-known/http-message-signatures-directory", origin);
  if (url.protocol !== "https:") return { ok: false, detail: "signature agent must be https", keys: [] };
  const r = await f(url.toString(), { headers: { "user-agent": "botproof" } });
  if (!r.ok) return { ok: false, detail: `directory fetch ${r.status}`, keys: [] };
  const headers: Record<string, string> = {};
  r.headers.forEach((v, k) => (headers[k] = v));
  return verifyDirectory(url.host, headers, Buffer.from(await r.arrayBuffer()), Date.now() / 1000);
}

/**
 * The request must be signed by a key from the platform's verified directory, cover
 * @authority and the path, and the path must contain the challenge code issued before signing.
 */
export async function checkWebBotAuth(ev: WebBotAuthEvidence, nonce: string, issued: string | undefined, f: Fetch = fetch): Promise<Check> {
  try {
    const { method, authority, path } = ev.request;
    const h = lower(ev.request.headers || {});
    const agent = h["signature-agent"]?.match(/https:\/\/[^"\s,]+/)?.[0];
    if (!agent) return { ok: false, detail: "no Signature-Agent" };
    const p = parseSignature(h["signature-input"] || "", h.signature || "", "web-bot-auth");
    const names = p.components.map((c) => c.name);
    if (!names.includes("@authority") || !(names.includes("@path") || names.includes("@target-uri")))
      return { ok: false, detail: "signature must cover @authority and the path" };
    if (!path.includes(nonce)) return { ok: false, detail: "request path does not contain the bot code" };
    if (issued && p.created && p.created < Date.parse(issued) / 1000) return { ok: false, detail: "signed before the code was issued" };
    const dir = await fetchDirectory(new URL(agent).origin, f);
    if (!dir.ok) return dir;
    const values: Record<string, string> = {
      "@authority": authority, "@method": method.toUpperCase(), "@path": path.split("?")[0],
      "@target-uri": `https://${authority}${path}`, "@scheme": "https",
    };
    const err = verifyEd25519(p, dir.keys, signatureBase(p, (n) => values[n] ?? h[n]));
    return err ? { ok: false, detail: err } : { ok: true, detail: `request signed by ${new URL(agent).host}` };
  } catch (e) { return { ok: false, detail: String(e) }; }
}

export async function checkPlatformEvidence(ev: unknown, nonce: string | undefined, issued: string | undefined, f: Fetch = fetch): Promise<Check> {
  const e = ev as { type?: string } | undefined;
  if (!e) return { ok: false, detail: "no platform evidence" };
  if (!nonce) return { ok: false, detail: "platform evidence needs a challenge code" };
  if (e.type === "web-bot-auth") return checkWebBotAuth(e as WebBotAuthEvidence, nonce, issued, f);
  return { ok: false, detail: `unsupported evidence type ${e.type}` };
}
