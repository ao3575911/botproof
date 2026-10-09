import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createPublicKey, KeyObject } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Doc, canonical, docHash, keyId, signDoc, verifyDoc } from "../src/core.js";
import { readFileSync } from "node:fs";
import { sign } from "node:crypto";
import { checkWebBotAuth, parseSignature, signatureBase, thumbprint, verifyDirectory } from "../src/platform.js";
import { challengeText, checkChallenge, checkGithub, checkX, grokPageText, proofText } from "../src/proofs.js";
import { badge, build, check, evaluate, load } from "../src/registry.js";

const kp = () => generateKeyPairSync("ed25519").privateKey;
const alice = kp(), bob = kp();
const id = (k: KeyObject) => keyId(createPublicKey(k));

// Fake GitHub: gist <user> holds that user's proof; page "bot" shows the challenge code.
const gists: Record<string, { login: string; content: string }> = {
  aaa: { login: "alice", content: proofText("github", "alice", id(alice)) },
  bbb: { login: "bob", content: proofText("github", "bob", id(bob)) },
};
const N = "0123456789abcdef01", T = "2026-10-09T00:00:00.000Z";
gists.ccc = { login: "alice", content: "bot page " + challengeText("web", "demo", id(alice), N) };
const fakeFetch = (async (url: string) => {
  const g = String(url).match(/gists\/(\w+)$/);
  if (g && gists[g[1]]) return new Response(JSON.stringify({ owner: { login: gists[g[1]].login }, files: { f: { content: gists[g[1]].content } } }));
  return new Response("nope", { status: 404 });
}) as typeof fetch;

const creator = (k: KeyObject, user: string, gist: string) =>
  signDoc({ v: 1, type: "creator", handle: `github:${user}`, links: [{ type: "github", user, proof: `https://gist.github.com/${user}/${gist}` }], ts: T }, k);

function registry(files: Record<string, Doc>) {
  const dir = mkdtempSync(join(tmpdir(), "bp-"));
  mkdirSync(join(dir, "bots")); writeFileSync(join(dir, "bots", ".gitkeep"), "");
  const all: Record<string, Doc> = { ...files };
  for (const [p, d] of Object.entries(files)) if (p.endsWith("/manifest.json")) all[p.replace("manifest.json", `versions/${docHash(d)}.json`)] = d;
  for (const [p, d] of Object.entries(all)) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), JSON.stringify(d)); }
  return dir;
}
const manifest = signDoc({ v: 1, type: "bot", platform: "web", botId: "demo", name: "Demo", version: "1.0.0", seq: 1, creator: "github:alice", challenge: { nonce: N, url: "https://gist.github.com/alice/ccc" }, ts: T }, alice);
const base = { "creators/github-alice.json": creator(alice, "alice", "aaa"), "creators/github-bob.json": creator(bob, "bob", "bbb"), "bots/web/demo/manifest.json": manifest };

test("canonical JSON sorts keys", () => assert.equal(canonical({ b: 1, a: [true, "x"] }), '{"a":[true,"x"],"b":1}'));

test("RFC 8785 vectors: UTF-16 key order and string escaping; non-integers rejected", () => {
  // RFC 8785 §3.2.3 sorting example (keys in UTF-16 code-unit order)
  const sorted = canonical({ "\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One",
    "\ud83d\ude00": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis" });
  assert.deepEqual([...sorted.matchAll(/"((?:[^"\\]|\\.)*)":"/g)].map((m) => JSON.parse(`"${m[1]}"`)), ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\ud83d\ude00", "\ufb33"]);
  // RFC 8785 §3.2.2.2 string serialisation
  assert.equal(canonical({ string: "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/" }), '{"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
  assert.equal(canonical({ literals: [null, true, false], n: -42 }), '{"literals":[null,true,false],"n":-42}');
  for (const bad of [1.5, 1e400, 2 ** 60]) assert.throws(() => canonical({ bad }));
  assert.equal(verifyDoc({ ...manifest, seq: 1.5 }), false);
});

test("signatures verify and catch tampering", () => {
  assert.ok(verifyDoc(manifest));
  assert.equal(verifyDoc({ ...manifest, name: "Evil" }), false);
});

test("github gist proof must be owned by the user", async () => {
  assert.ok((await checkGithub("alice", "https://gist.github.com/alice/aaa", id(alice), fakeFetch)).ok);
  assert.equal((await checkGithub("alice", "https://gist.github.com/bob/bbb", id(alice), fakeFetch)).ok, false);
});

test("challenge-passed bot with a counted review from someone else", async () => {
  const review = signDoc({ v: 1, type: "attestation", platform: "web", botId: "demo", attester: "github:bob", tag: "reviewed", note: "", versionHash: docHash(manifest), ts: T }, bob);
  const dir = registry({ ...base, "bots/web/demo/attestations/bob.json": review });
  assert.deepEqual(await check(dir, fakeFetch), []);
  const r = await evaluate(load(dir).bots[0].bundle, fakeFetch);
  assert.equal(r.strength, "challenge-passed");
  assert.equal(r.attestations[0].status, "counted");
  assert.equal(r.score, 20 + 25 + 5);
  const idx = await build(dir, join(dir, "_site"), fakeFetch);
  assert.equal(idx[0].score, 50);
});

test("self-reviews are rejected", async () => {
  const self = signDoc({ v: 1, type: "attestation", platform: "web", botId: "demo", attester: "github:alice", tag: "reviewed", note: "", versionHash: docHash(manifest), ts: T }, alice);
  const dir = registry({ ...base, "bots/web/demo/attestations/alice.json": self });
  assert.ok((await check(dir, fakeFetch)).some((e) => e.includes("self-review rejected")));
  assert.equal((await evaluate(load(dir).bots[0].bundle, fakeFetch)).attestations[0].status, "self-review rejected");
});

test("only the signer can revoke", async () => {
  const rev = (k: KeyObject) => signDoc({ v: 1, type: "revocation", target: docHash(manifest), reason: "", ts: T }, k);
  assert.ok((await check(registry({ ...base, "revocations/x.json": rev(bob) }), fakeFetch)).some((e) => e.includes("only the original signer")));
  const dir = registry({ ...base, "revocations/x.json": rev(alice) });
  assert.deepEqual(await check(dir, fakeFetch), []);
  const r = await evaluate(load(dir).bots[0].bundle, fakeFetch);
  assert.equal(r.strength, "revoked");
  assert.equal(r.score, 0);
});

test("badge is SVG", () => assert.match(badge("challenge-passed", 50), /<svg.*challenge-passed · 50/));

// Real x.ai/bot share page (fixture), with the challenge code added to the bot description.
const grokHtml = readFileSync(new URL("../../test/fixtures/grok-share.html", import.meta.url), "utf8");
test("grok share page: reads the description and finds the code", async () => {
  const code = challengeText("grok", "0fF7Cqp8LTzh9JGQ-je3M", id(alice), N);
  assert.match(grokPageText(grokHtml), /On-demand iCloud Mail helper/);
  const withCode = grokHtml.replaceAll("Does nothing until you ask.", "Does nothing until you ask. " + code);
  const f = (async () => new Response(withCode)) as unknown as typeof fetch;
  assert.ok((await checkChallenge("https://x.ai/bot/0fF7Cqp8LTzh9JGQ-je3M", code, f)).ok);
  assert.equal((await checkChallenge("https://x.ai/bot/0fF7Cqp8LTzh9JGQ-je3M", code.replace(N, "f".repeat(18)), f)).ok, false);
});

test("grok claims only count a code on that bot's own share page", async () => {
  const m = (url: string) => signDoc({ v: 1, type: "bot", platform: "grok", botId: "0fF7Cqp8LTzh9JGQ-je3M", name: "x", version: "1", seq: 1, creator: "github:alice", challenge: { nonce: N, url }, ts: T }, alice);
  const ok = (async (u: string) => String(u).includes("gists") ? fakeFetch(u) : new Response(`<meta name="description" content="${challengeText("grok", "0fF7Cqp8LTzh9JGQ-je3M", id(alice), N)}"/>`)) as typeof fetch;
  const b = (url: string) => ({ manifest: m(url), creator: base["creators/github-alice.json"], attestations: [], attesters: {}, revocations: [] });
  assert.equal((await evaluate(b("https://x.ai/bot/0fF7Cqp8LTzh9JGQ-je3M"), ok)).strength, "challenge-passed");
  assert.equal((await evaluate(b("https://gist.github.com/alice/ccc"), ok)).strength, "self-claimed");
});

test("X post proof: verified, wrong author, unreachable", async () => {
  const post = (user: string, text: string, status = 200) => (async () => new Response(JSON.stringify({ text, user: { screen_name: user } }), { status })) as unknown as typeof fetch;
  const url = "https://x.com/Alice/status/123", txt = proofText("x", "alice", id(alice));
  assert.ok((await checkX(url, id(alice), post("alice", "hi " + txt))).ok);
  assert.equal((await checkX(url, id(alice), post("mallory", txt))).ok, false);
  const down = await checkX(url, id(alice), post("alice", "", 503));
  assert.equal(down.ok || down.reachable, false);
});

// Real signed key directory from chatgpt.com (fixture, captured 2026-10-09).
const gpt = JSON.parse(readFileSync(new URL("../../test/fixtures/chatgpt-directory.json", import.meta.url), "utf8"));
test("web bot auth: real ChatGPT key directory signature verifies", () => {
  assert.ok(verifyDirectory(gpt.authority, gpt.headers, Buffer.from(gpt.body)).ok);
  assert.equal(verifyDirectory(gpt.authority, gpt.headers, Buffer.from(gpt.body.replace("ai", "ia"))).ok, false);
  assert.equal(verifyDirectory("evil.com", gpt.headers, Buffer.from(gpt.body)).ok, false);
});

test("web bot auth: signed request with the code makes a claim platform-signed", async () => {
  const k = kp(), jwk = { ...k.export({ format: "jwk" }), d: undefined } as { kty: string; crv: string; x: string };
  const kid = thumbprint(jwk), now = Math.floor(Date.now() / 1000);
  const sigOver = (input: string, value: (n: string) => string | undefined) =>
    sign(null, Buffer.from(signatureBase(parseSignature(input, "s=:AA==:".replace("s", input.split("=")[0])), value)), k).toString("base64");
  const body = JSON.stringify({ keys: [jwk] });
  const dIn = `d=("@authority";req);created=${now};keyid="${kid}";alg="ed25519";tag="http-message-signatures-directory"`;
  const dirHeaders = { "signature-input": dIn, signature: `d=:${sigOver(dIn, () => "agent.example")}:` };
  const rIn = `r=("@authority" "@path" "signature-agent");created=${now};keyid="${kid}";alg="ed25519";tag="web-bot-auth"`;
  const code = challengeText("web", "demo", id(alice), N), path = `/botproof/${encodeURIComponent(code)}`;
  const vals: Record<string, string> = { "@authority": "alice.example", "@path": path, "signature-agent": '"https://agent.example"' };
  const ev = { type: "web-bot-auth" as const, request: { method: "GET", authority: "alice.example", path,
    headers: { "signature-agent": vals["signature-agent"], "signature-input": rIn, signature: `r=:${sigOver(rIn, (n) => vals[n])}:` } } };
  const f = (async (u: string) => String(u).startsWith("https://agent.example/") ? new Response(body, { headers: dirHeaders }) : fakeFetch(u)) as typeof fetch;
  const platforms = [{ origin: "https://agent.example" }], ctx = { code, platforms };
  assert.ok((await checkWebBotAuth(ev, ctx, f)).ok);
  assert.match((await checkWebBotAuth(ev, { code }, f)).detail, /not an allowlisted platform/);
  assert.equal((await checkWebBotAuth(ev, { ...ctx, code: code.replace(N, "f".repeat(18)) }, f)).ok, false);
  assert.equal((await checkWebBotAuth({ ...ev, request: { ...ev.request, authority: "bob.example" } }, ctx, f)).ok, false);
  const m2 = signDoc({ ...manifest, sig: undefined, platformEvidence: ev }, alice);
  const r = await evaluate({ manifest: m2, creator: base["creators/github-alice.json"], attestations: [], attesters: {}, revocations: [], platforms }, f);
  assert.equal(r.strength, "platform-signed");
  assert.equal(r.score, 20 + 35);
});

test("ownership: a legit update and a signed transfer pass; takeover and wrong author fail", async () => {
  const baseDir = registry(base), keepV = { [`bots/web/demo/versions/${docHash(manifest)}.json`]: manifest };
  const upd = signDoc({ ...manifest, sig: undefined, key: undefined, version: "1.1.0", seq: 2 }, alice);
  const d1 = registry({ ...base, ...keepV, "bots/web/demo/manifest.json": upd });
  assert.deepEqual(await check(d1, fakeFetch, { baseDir, author: "alice" }), []);
  assert.ok((await check(d1, fakeFetch, { baseDir, author: "bob" })).some((e) => e.includes("PR author")));
  const take = signDoc({ ...manifest, sig: undefined, key: undefined, creator: "github:bob", challenge: undefined, seq: 2 }, bob);
  const d2 = registry({ ...base, ...keepV, "bots/web/demo/manifest.json": take });
  assert.ok((await check(d2, fakeFetch, { baseDir, author: "bob" })).some((e) => e.includes("owned by github:alice")));
  const t = signDoc({ v: 1, type: "transfer", platform: "web", botId: "demo", to: "github:bob", toKey: id(bob), ts: T }, alice);
  const d3 = registry({ ...base, "bots/web/demo/transfers/t.json": t });
  assert.deepEqual(await check(d3, fakeFetch, { baseDir, author: "alice" }), []);
  const d4 = registry({ ...base, ...keepV, "bots/web/demo/transfers/t.json": t, "bots/web/demo/manifest.json": take });
  assert.deepEqual(await check(d4, fakeFetch, { baseDir: d3, author: "bob" }), []);
  const d5 = registry({ "creators/github-bob.json": base["creators/github-bob.json"] });
  assert.ok((await check(d5, fakeFetch, { baseDir, author: "bob" })).some((e) => e.includes("can't be deleted")));
});
