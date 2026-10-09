import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createPublicKey, KeyObject } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Doc, canonical, docHash, keyId, signDoc, verifyDoc } from "../src/core.js";
import { challengeText, checkGithub, proofText } from "../src/proofs.js";
import { badge, build, check, evaluate, load } from "../src/registry.js";

const kp = () => generateKeyPairSync("ed25519").privateKey;
const alice = kp(), bob = kp();
const id = (k: KeyObject) => keyId(createPublicKey(k));

// Fake GitHub: gist <user> holds that user's proof; page "bot" shows the challenge code.
const gists: Record<string, { login: string; content: string }> = {
  aaa: { login: "alice", content: proofText("github", "alice", id(alice)) },
  bbb: { login: "bob", content: proofText("github", "bob", id(bob)) },
};
const fakeFetch = (async (url: string) => {
  const g = String(url).match(/gists\/(\w+)$/);
  if (g && gists[g[1]]) return new Response(JSON.stringify({ owner: { login: gists[g[1]].login }, files: { f: { content: gists[g[1]].content } } }));
  if (String(url) === "https://bot.example/page") return new Response("hello " + challengeText("n0nce"));
  return new Response("nope", { status: 404 });
}) as typeof fetch;

const creator = (k: KeyObject, user: string, gist: string) =>
  signDoc({ v: 1, type: "creator", handle: `github:${user}`, links: [{ type: "github", user, proof: `https://gist.github.com/${user}/${gist}` }], ts: "t" }, k);

function registry(files: Record<string, Doc>) {
  const dir = mkdtempSync(join(tmpdir(), "bp-"));
  for (const [p, d] of Object.entries(files)) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), JSON.stringify(d)); }
  return dir;
}
const manifest = signDoc({ v: 1, type: "bot", platform: "web", botId: "demo", name: "Demo", version: "1.0.0", creator: "github:alice", challenge: { nonce: "n0nce", url: "https://bot.example/page" }, ts: "t" }, alice);
const base = { "creators/github-alice.json": creator(alice, "alice", "aaa"), "creators/github-bob.json": creator(bob, "bob", "bbb"), "bots/web/demo/manifest.json": manifest };

test("canonical JSON sorts keys", () => assert.equal(canonical({ b: 1, a: [true, "x"] }), '{"a":[true,"x"],"b":1}'));

test("signatures verify and catch tampering", () => {
  assert.ok(verifyDoc(manifest));
  assert.equal(verifyDoc({ ...manifest, name: "Evil" }), false);
});

test("github gist proof must be owned by the user", async () => {
  assert.ok((await checkGithub("alice", "https://gist.github.com/alice/aaa", id(alice), fakeFetch)).ok);
  assert.equal((await checkGithub("alice", "https://gist.github.com/bob/bbb", id(alice), fakeFetch)).ok, false);
});

test("challenge-passed bot with a counted review from someone else", async () => {
  const review = signDoc({ v: 1, type: "attestation", platform: "web", botId: "demo", attester: "github:bob", tag: "reviewed", note: "", ts: "t" }, bob);
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
  const self = signDoc({ v: 1, type: "attestation", platform: "web", botId: "demo", attester: "github:alice", tag: "reviewed", note: "", ts: "t" }, alice);
  const dir = registry({ ...base, "bots/web/demo/attestations/alice.json": self });
  assert.ok((await check(dir, fakeFetch)).some((e) => e.includes("self-review rejected")));
  assert.equal((await evaluate(load(dir).bots[0].bundle, fakeFetch)).attestations[0].status, "self-review rejected");
});

test("only the signer can revoke", async () => {
  const rev = (k: KeyObject) => signDoc({ v: 1, type: "revocation", target: docHash(manifest), reason: "", ts: "t" }, k);
  assert.ok((await check(registry({ ...base, "revocations/x.json": rev(bob) }), fakeFetch)).some((e) => e.includes("only the original signer")));
  const dir = registry({ ...base, "revocations/x.json": rev(alice) });
  assert.deepEqual(await check(dir, fakeFetch), []);
  const r = await evaluate(load(dir).bots[0].bundle, fakeFetch);
  assert.equal(r.strength, "revoked");
  assert.equal(r.score, 0);
});

test("badge is SVG", () => assert.match(badge("challenge-passed", 50), /<svg.*challenge-passed · 50/));
