/**
 * Port of the v0.2.0 review's 39-check simulation (botproof-review/sim2). Network is mocked.
 * Happy-path checks (H) must pass. Attack checks (A, N) pass when the attack is BLOCKED.
 * Checks for attacks that are still open are marked `todo` and flip to required as fixes land.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Doc, docHash, loadOrCreateKey, signDoc } from "../src/core.js";
import { build, check, CheckOpts, evaluate, load } from "../src/registry.js";
import { parseSignature, signatureBase, thumbprint } from "../src/platform.js";
// @ts-ignore plain JS fixture
import { fakeFetch } from "../../test/fixtures/fakeweb.mjs";

const CLI = new URL("../src/cli.js", import.meta.url).pathname;
const MOCK = new URL("../../test/fixtures/mock.mjs", import.meta.url).pathname;
const ROOT = mkdtempSync(join(tmpdir(), "bp-adv-"));
const FAKEWEB = join(ROOT, "fakeweb.json");
const REG = join(ROOT, "reg");
const OLD = "2015-01-01T00:00:00Z", NEW = new Date(Date.now() - 5 * 86400e3).toISOString();
type Web = { gists: Record<string, { owner: string; content: string }>; users: Record<string, { login: string; created_at: string; public_repos: number; followers: number }>; pages: Record<string, unknown> };
const web: Web = { gists: {}, users: {}, pages: {} };
const save = () => writeFileSync(FAKEWEB, JSON.stringify(web));
const f = (async (u: string, i?: RequestInit) => fakeFetch(JSON.parse(readFileSync(FAKEWEB, "utf8")))(u, i)) as typeof fetch;
process.env.BOTPROOF_PASSPHRASE = "test-pass";
mkdirSync(REG, { recursive: true }); save();
const git = (...a: string[]) => execFileSync("git", a, { cwd: REG, stdio: "pipe", env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" } });
git("init", "-q"); writeFileSync(join(REG, "platforms.json"), JSON.stringify({ "web-bot-auth": [{ origin: "https://chatgpt.com", name: "ChatGPT agent" }] }));
git("add", "-A"); git("commit", "-qm", "init");

class Actor {
  home: string; cwd: string; env: Record<string, string>;
  constructor(public name: string, age = OLD) {
    this.home = join(ROOT, "home", name); this.cwd = join(ROOT, "work", name);
    mkdirSync(this.cwd, { recursive: true });
    this.env = { ...process.env as Record<string, string>, BOTPROOF_HOME: this.home, FAKEWEB, BOTPROOF_PASSPHRASE: "test-pass" };
    web.users[name] = { login: name, created_at: age, public_repos: age === OLD ? 20 : 0, followers: age === OLD ? 10 : 0 }; save();
  }
  run(...args: string[]) {
    try { return { code: 0, out: execFileSync(process.execPath, ["--import", MOCK, CLI, ...args], { cwd: this.cwd, env: this.env, encoding: "utf8", stdio: "pipe" }) }; }
    catch (e) { const x = e as { status: number; stdout: string; stderr: string }; return { code: x.status, out: x.stdout + x.stderr }; }
  }
  get key() { return loadOrCreateKey(this.home); }
  /** Prints the proof, posts it as a gist, then links it. Returns both exit codes. */
  linkGithub() {
    const a = this.run("link", "github", this.name);
    const proof = a.out.trim().split("\n").pop()!;
    web.gists[gid("g" + this.name)] = { owner: this.name, content: proof }; save();
    const b = this.run("link", "github", this.name, "--proof", `https://gist.github.com/${this.name}/${gid("g" + this.name)}`);
    return [a.code, b.code];
  }
  /** Runs challenge and shows the printed code on `page` (a gist id or a URL). */
  challenge(url?: string, show = (text: string) => { web.pages[url!] = `bot page ${text}`; }) {
    const r = this.run("challenge", ...(url ? ["--url", url] : []));
    show(r.out.trim().split("\n").pop()!); save();
    return r.code;
  }
  craft(d: Doc) { return signDoc(d, this.key.priv); }
  get manifest() { return JSON.parse(readFileSync(join(this.cwd, "botproof.json"), "utf8")) as Doc; }
}
const gid = (s: string) => Buffer.from(s).toString("hex");
const showOnGist = (a: Actor, id: string) => (text: string) => { web.gists[gid(id)] = { owner: a.name, content: text }; };
const write = (dir: string, p: string, d: unknown) => { mkdirSync(join(dir, p, ".."), { recursive: true }); writeFileSync(join(dir, p), typeof d === "string" ? d : JSON.stringify(d, null, 2)); };
const commit = () => { git("add", "-A"); git("commit", "-qm", "merge", "--allow-empty"); };
const adv = () => { const d = mkdtempSync(join(ROOT, "adv-")); cpSync(REG, d, { recursive: true, filter: (x) => !x.includes("/.git") }); return d; };
const bundle = (dir: string, ref: string) => {
  const b = load(dir).bots.find((x) => `${x.bundle.manifest.platform}/${x.bundle.manifest.botId}` === ref);
  assert.ok(b, `${ref} not in registry`); return b!.bundle;
};
const verdict = async (dir: string, ref: string, opts: CheckOpts = {}) => ({ errs: await check(dir, f, { baseDir: REG, ...opts }), res: await evaluate(bundle(dir, ref), f) });
/** An attack is blocked when CI rejects it and verify does not grant the bot an ownership label. */
const blocked = async (dir: string, ref: string, opts: CheckOpts = {}) => {
  const { errs, res } = await verdict(dir, ref, opts);
  assert.ok(errs.length > 0, "CI accepted the attack");
  assert.ok(res.errors.length > 0 || res.strength === "self-claimed" || res.strength === "revoked", `verify gave ${res.strength}`);
  return { errs, res };
};

const alice = new Actor("alice"), bob = new Actor("bob"), mallory = new Actor("mallory"), grace = new Actor("grace");
const ALICE_PAGE = `https://gist.github.com/alice/${gid("alicebot")}`;
let v1: Doc, steps: Record<string, number> = {};

// ---------- Happy path ----------
test("H0 package installs from git or npm (prepare script + bin)", () => {
  const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
  assert.ok(pkg.scripts.prepare && pkg.bin.botproof && pkg.files.includes("dist/src"));
});
test("H1 test suite runs from source", () => assert.ok(existsSync(CLI)));
test("H4 init", () => { steps.init = alice.run("init", "--platform", "web", "--bot", "alice-bot", "--name", "Alice Bot").code; assert.equal(steps.init, 0); });
test("H5–H6 link github (prints proof, then links it)", () => assert.deepEqual(alice.linkGithub(), [0, 0]));
test("H7 challenge + sign", () => {
  assert.equal(alice.challenge(ALICE_PAGE, showOnGist(alice, "alicebot")), 0);
  assert.equal(alice.run("sign").code, 0);
});
test("H8 publish into the registry", () => {
  assert.equal(alice.run("publish", "--to-dir", REG).code, 0);
  assert.ok(existsSync(join(REG, "bots/web/alice-bot/manifest.json")));
});
test("H2/H9 registry check passes", async () => { assert.deepEqual(await check(REG, f, { baseDir: undefined, author: "alice" }), []); commit(); });
test("H3/H10 verify: challenge-passed", async () => {
  const r = alice.run("verify", "web/alice-bot", "--registry", REG);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /challenge-passed/);
  v1 = alice.manifest;
});
test("H11 another creator reviews and publishes", async () => {
  bob.linkGithub();
  assert.equal(bob.run("attest", "web/alice-bot", "--tag", "reviewed", "--registry", REG).code, 0);
  assert.equal(bob.run("publish", "--to-dir", REG).code, 0);
  assert.deepEqual(await check(REG, f, { author: "bob" }), []); commit();
});
test("H12 verify counts the review", async () => {
  const r = await evaluate(bundle(REG, "web/alice-bot"), f);
  assert.equal(r.attestations[0].status, "counted");
  assert.ok(r.breakdown.reviews > 0);
});
test("H13 creator revokes a version", async () => {
  const d = adv();
  const a = new Actor("alice"); a.env.BOTPROOF_HOME = alice.home;
  assert.equal(alice.run("revoke", docHash(alice.manifest), "--reason", "withdraw").code, 0);
  alice.run("publish", "--to-dir", d);
  assert.deepEqual(await check(d, f, { author: "alice" }), []);
  assert.equal((await evaluate(bundle(d, "web/alice-bot"), f)).strength, "revoked");
  rmSync(join(alice.home, "out"), { recursive: true, force: true });
});

// ---------- Adversarial (pass = blocked) ----------
test("setup mallory", () => { mallory.run("init", "--platform", "web", "--bot", "mallory-bot"); assert.deepEqual(mallory.linkGithub(), [0, 0]); });
const mc = () => JSON.parse(readFileSync(join(mallory.home, "creator.json"), "utf8"));

test("A1 edited signed manifest is rejected", async () => {
  const d = adv(), p = join(d, "bots/web/alice-bot/manifest.json");
  write(d, "bots/web/alice-bot/manifest.json", { ...JSON.parse(readFileSync(p, "utf8")), name: "Alice Bot (official)" });
  const { errs, res } = await verdict(d, "web/alice-bot");
  assert.ok(errs.some((e) => e.includes("bad signature")));
  assert.ok(res.errors.length > 0);
});
test("A1b random signature bytes are rejected", async () => {
  const d = adv(), p = join(d, "bots/web/alice-bot/manifest.json");
  write(d, "bots/web/alice-bot/manifest.json", { ...JSON.parse(readFileSync(p, "utf8")), sig: "A".repeat(86) });
  assert.ok((await check(d, f)).length > 0);
});
test("A2 replayed challenge on another bot", async () => {
  const d = adv(); write(d, "creators/github-mallory.json", mc());
  write(d, "bots/web/mallory-bot/manifest.json", mallory.craft({ v: 1, type: "bot", platform: "web", botId: "mallory-bot", name: "Mallory Bot", version: "0.1.0", seq: 1, challenge: v1.challenge, creator: "github:mallory", ts: new Date().toISOString() }));
  await blocked(d, "web/mallory-bot", { author: "mallory" });
});
test("A3 takeover: overwrite another creator's bot", async () => {
  const d = adv(); write(d, "creators/github-mallory.json", mc());
  write(d, "bots/web/alice-bot/manifest.json", mallory.craft({ v: 1, type: "bot", platform: "web", botId: "alice-bot", name: "Alice Bot", version: "9.9.9", seq: 99, challenge: v1.challenge, creator: "github:mallory", ts: new Date().toISOString() }));
  const { errs } = await blocked(d, "web/alice-bot", { author: "mallory" });
  assert.ok(errs.some((e) => /owned by|author/.test(e)), errs.join("; "));
  assert.equal((await evaluate(bundle(d, "web/alice-bot"), f)).breakdown.reviews, 0, "inherited review must not count");
});
test("A4 claim a grok id from a page the attacker controls", async () => {
  const d = adv(); write(d, "creators/github-mallory.json", mc());
  web.pages["https://mallory.example/x"] = "botproof-challenge:feedfacefeedface00"; save();
  write(d, "bots/grok/1234567890/manifest.json", mallory.craft({ v: 1, type: "bot", platform: "grok", botId: "1234567890", name: "Official Grok Helper", version: "1.0.0", seq: 1, challenge: { nonce: "feedfacefeedface00", url: "https://mallory.example/x" }, creator: "github:mallory", ts: new Date().toISOString() }));
  const res = await evaluate(bundle(d, "grok/1234567890"), f);
  assert.notEqual(res.strength, "challenge-passed");
});
test("A5 self-review is rejected", async () => {
  const d = adv();
  write(d, "bots/web/alice-bot/attestations/self.json", alice.craft({ v: 1, type: "attestation", platform: "web", botId: "alice-bot", attester: "github:alice", tag: "audited", note: "", versionHash: docHash(v1), ts: new Date().toISOString() }));
  const { errs, res } = await verdict(d, "web/alice-bot", { author: "alice" });
  assert.ok(errs.some((e) => e.includes("self-review")));
  assert.ok(res.attestations.some((a) => a.status === "self-review rejected"));
});
test("A6 sybil: fresh sock accounts' reviews count 0", async () => {
  const d = adv(); write(d, "creators/github-mallory.json", mc());
  write(d, "bots/web/mallory-bot/manifest.json", mallory.craft({ v: 1, type: "bot", platform: "web", botId: "mallory-bot", name: "Mallory Bot", version: "0.1.0", seq: 1, creator: "github:mallory", ts: new Date().toISOString() }));
  for (const n of ["sock1", "sock2"]) {
    const s = new Actor(n, NEW); s.linkGithub();
    write(d, `creators/github-${n}.json`, JSON.parse(readFileSync(join(s.home, "creator.json"), "utf8")));
    write(d, `bots/web/mallory-bot/attestations/${n}.json`, s.craft({ v: 1, type: "attestation", platform: "web", botId: "mallory-bot", attester: `github:${n}`, tag: "audited", note: "", versionHash: docHash(load(d).bots.find((b) => b.bundle.manifest.botId === "mallory-bot")!.bundle.manifest), ts: new Date().toISOString() }));
  }
  const res = await evaluate(bundle(d, "web/mallory-bot"), f);
  assert.equal(res.breakdown.reviews, 0, JSON.stringify(res.attestations));
});
test("T1 verify --trust limits reviews to the list", async () => {
  const b = bundle(REG, "web/alice-bot");
  assert.equal((await evaluate(b, f, { trust: ["github:carol"] })).attestations[0].status, "not in your trust list");
  assert.equal((await evaluate(b, f, { trust: ["github:bob"] })).attestations[0].status, "counted");
  const r = alice.run("verify", "web/alice-bot", "--registry", REG, "--trust", "carol");
  assert.match(r.out, /not in your trust list/);
});
test("A7 rollback to an older signed version", async () => {
  const d = adv();
  const v = (version: string, seq: number) => alice.craft({ ...v1, sig: undefined, key: undefined, version, seq, ts: new Date().toISOString() });
  const v2 = v("2.0.0", 2), v3 = v("3.0.0", 3);
  for (const m of [v2, v3]) write(d, `bots/web/alice-bot/versions/${docHash(m)}.json`, m);
  write(d, "bots/web/alice-bot/manifest.json", v3);
  const base = mkdtempSync(join(ROOT, "base-")); cpSync(d, base, { recursive: true });
  write(d, "bots/web/alice-bot/manifest.json", v2);
  const errs = await check(d, f, { baseDir: base, author: "alice" });
  assert.ok(errs.some((e) => /seq|rollback|older/.test(e)), errs.join("; "));
  assert.ok((await evaluate(bundle(d, "web/alice-bot"), f)).errors.length > 0);
});
test("A8 stolen key: manifests signed after key revocation are invalid", async () => {
  const d = adv();
  assert.equal(alice.run("revoke", "--key", "--reason", "key stolen").code, 0);
  alice.run("publish", "--to-dir", d);
  write(d, "bots/web/alice-bot/manifest.json", alice.craft({ ...v1, sig: undefined, key: undefined, version: "6.6.6", seq: 666, ts: new Date().toISOString() }));
  await blocked(d, "web/alice-bot", { author: "alice" });
});
test("A9 tampered creator file is rejected by CI and verify", async () => {
  const d = adv(), p = join(d, "creators/github-alice.json"), c = JSON.parse(readFileSync(p, "utf8"));
  c.links.push({ type: "dns", domain: "alice.com" }); write(d, "creators/github-alice.json", c);
  const { errs, res } = await verdict(d, "web/alice-bot", { author: "alice" });
  assert.ok(errs.length > 0); assert.ok(res.errors.length > 0);
});
test("A10 impersonate a GitHub handle", async () => {
  const d = adv();
  write(d, "creators/github-alice.json", mallory.craft({ v: 1, type: "creator", handle: "github:alice", links: [{ type: "github", user: "alice", proof: `https://gist.github.com/alice/${gid("gmallory")}` }], ts: new Date().toISOString() }));
  assert.ok((await check(d, f)).length > 0);
  assert.equal(mallory.run("link", "github", "alice", "--proof", `https://gist.github.com/mallory/${gid("gmallory")}`).code, 1);
});
test("A10b verify rejects a handle that doesn't match its proven account", async () => {
  const d = adv();
  write(d, "creators/github-torvalds.json", mallory.craft({ v: 1, type: "creator", handle: "github:torvalds", links: [{ type: "github", user: "mallory", proof: `https://gist.github.com/mallory/${gid("gmallory")}` }], ts: new Date().toISOString() }));
  write(d, "bots/web/linux-bot/manifest.json", mallory.craft({ v: 1, type: "bot", platform: "web", botId: "linux-bot", name: "Linus Bot", version: "1.0.0", seq: 1, creator: "github:torvalds", ts: new Date().toISOString() }));
  assert.ok((await evaluate(bundle(d, "web/linux-bot"), f)).errors.length > 0);
});
test("A11 review labelled bob but signed by mallory", async () => {
  const d = adv();
  write(d, "bots/web/alice-bot/attestations/fake.json", mallory.craft({ v: 1, type: "attestation", platform: "web", botId: "alice-bot", attester: "github:bob", tag: "flagged", note: "malware", versionHash: docHash(v1), ts: new Date().toISOString() }));
  const { errs, res } = await verdict(d, "web/alice-bot", { author: "mallory" });
  assert.ok(errs.length > 0);
  assert.ok(res.attestations.some((a) => a.status === "unknown attester"));
});
test("A12 bad CLI input fails cleanly", () => {
  for (const a of [["init", "--platform", "web", "--bot", "../../etc/passwd"], ["init", "--platform", "<x>", "--bot", "b"], ["verify", "a/b/c"], ["verify", "../x"], ["revoke", "nothex"], ["attest", "web/alice-bot", "--tag", "great"], ["link", "github"], ["frobnicate"]])
    assert.equal(mallory.run(...a).code, 1, a.join(" "));
});
test("A12b invalid JSON fails closed and names the file", async () => {
  const d = adv(); write(d, "creators/github-broken.json", "{not json");
  const errs = await check(d, f);
  assert.ok(errs.some((e) => e.includes("creators/github-broken.json")), errs.join("; "));
});
test("A12c HTML in a platform name is rejected and escaped", async () => {
  const d = adv(), P = 'x" onmouseover="alert(1)';
  write(d, "creators/github-mallory.json", mc());
  write(d, `bots/${P}/b/manifest.json`, mallory.craft({ v: 1, type: "bot", platform: P, botId: "b", name: "n", version: "1", seq: 1, creator: "github:mallory", ts: new Date().toISOString() }));
  assert.ok((await check(d, f)).length > 0);
  await build(d, join(d, "_site"), f);
  assert.ok(!readFileSync(join(d, "_site/index.html"), "utf8").includes('onmouseover="alert'));
});

// ---------- New in v0.2.0 ----------
test("N1a README quickstart: init with only a share link", () => {
  const g = new Actor("n1a"); assert.equal(g.run("init", "--bot", "https://x.ai/bot/GrokBot123", "--name", "Grace Helper").code, 0);
});
test("N1b grok flow: code in the share page description → challenge-passed", async () => {
  assert.equal(grace.run("init", "--bot", "https://x.ai/bot/GrokBot123", "--name", "Grace Helper").code, 0);
  grace.linkGithub();
  grace.challenge(undefined, (t) => { web.pages["https://x.ai/bot/GrokBot123"] = `<html><head><title>Grace Helper</title><meta name="description" content="Helps. ${t}"></head><body></body></html>`; });
  assert.equal(grace.run("sign").code, 0);
  assert.equal(grace.run("publish", "--to-dir", REG).code, 0);
  assert.deepEqual(await check(REG, f, { author: "grace" }), []); commit();
  assert.equal((await evaluate(bundle(REG, "grok/GrokBot123"), f)).strength, "challenge-passed");
});
test("N2 grok takeover with a copied code", async () => {
  const d = adv(); write(d, "creators/github-mallory.json", mc());
  write(d, "bots/grok/GrokBot123/manifest.json", mallory.craft({ v: 1, type: "bot", platform: "grok", botId: "GrokBot123", name: "Grace Helper", version: "9.0.0", seq: 99, challenge: grace.manifest.challenge, creator: "github:mallory", ts: new Date().toISOString() }));
  await blocked(d, "grok/GrokBot123", { author: "mallory" });
});
test("N3 X link verified (+identity)", () => {
  const key = bob.key.id;
  web.pages["https://cdn.syndication.twimg.com/tweet-result?id=111&token=a"] = JSON.stringify({ text: `botproof-proof:x:bobx:${key}`, user: { screen_name: "BobX" } }); save();
  assert.equal(bob.run("link", "x", "https://x.com/bobx/status/111").code, 0);
  assert.equal(JSON.parse(readFileSync(join(bob.home, "creator.json"), "utf8")).links.find((l: { type: string }) => l.type === "x").url, "https://x.com/bobx/status/111");
});
test("N4 X post by another handle is rejected", () => {
  web.pages["https://cdn.syndication.twimg.com/tweet-result?id=222&token=a"] = JSON.stringify({ text: `botproof-proof:x:bobx:${bob.key.id}`, user: { screen_name: "someoneelse" } }); save();
  assert.equal(bob.run("link", "x", "https://x.com/bobx/status/222").code, 1);
});
test("N5 X unreachable stays self-claimed", () => assert.equal(bob.run("link", "x", "https://x.com/bobx/status/333").code, 0));

/** Self-issued Web Bot Auth evidence from an attacker-run directory. */
function selfIssued(path: string, authority: string, agent: string) {
  const k = generateKeyPairSync("ed25519").privateKey, j = k.export({ format: "jwk" });
  const jwk = { kty: j.kty!, crv: j.crv!, x: j.x! }, kid = thumbprint(jwk), now = Math.floor(Date.now() / 1000) + 2, host = new URL(agent).host;
  const sg = (input: string, val: (n: string) => string | undefined) => sign(null, Buffer.from(signatureBase(parseSignature(input, input.split("=")[0] + "=:AA==:"), val)), k).toString("base64");
  const dIn = `d=("@authority";req);created=${now};keyid="${kid}";alg="ed25519";tag="http-message-signatures-directory"`;
  const rIn = `r=("@authority" "@path" "signature-agent");created=${now};keyid="${kid}";alg="ed25519";tag="web-bot-auth"`;
  const sa = `"${agent}"`, vals: Record<string, string> = { "@authority": authority, "@path": path, "signature-agent": sa };
  web.pages[`${agent}/.well-known/http-message-signatures-directory`] = { body: JSON.stringify({ keys: [jwk] }), headers: { "signature-input": dIn, signature: `d=:${sg(dIn, () => host)}:` } }; save();
  return { type: "web-bot-auth", request: { method: "GET", authority, path, headers: { "signature-agent": sa, "signature-input": rIn, signature: `r=:${sg(rIn, (n) => vals[n])}:` } } };
}
let n6: Doc;
test("N6 self-issued platform signature is not platform-signed", async () => {
  const m = new Actor("mallory"); m.cwd = join(ROOT, "work", "mallory-n6"); mkdirSync(m.cwd, { recursive: true });
  m.run("init", "--platform", "web", "--bot", "openai-operator", "--name", "OpenAI Operator (official)");
  m.challenge(`https://gist.github.com/mallory/${gid("mop")}`, showOnGist(mallory, "mop"));
  const ch = m.manifest.challenge as { nonce: string };
  writeFileSync(join(m.cwd, "ev.json"), JSON.stringify(selfIssued(`/botproof/${encodeURIComponent(String(web.gists[gid("mop")].content))}/${ch.nonce}`, "mallory.example", "https://agent.mallory.example")));
  m.run("evidence", "ev.json"); m.run("sign");
  n6 = m.manifest;
  const d = adv(); write(d, "creators/github-mallory.json", mc()); write(d, "bots/web/openai-operator/manifest.json", n6);
  write(d, "bots/web/openai-operator/manifest.json", { ...n6, platformEvidence: n6.platformEvidence ?? JSON.parse(readFileSync(join(m.cwd, "ev.json"), "utf8")) });
  const res = await evaluate(bundle(d, "web/openai-operator"), f);
  assert.notEqual(res.strength, "platform-signed");
});
test("N7 tampered evidence is rejected", () => {
  const m = new Actor("mallory"); m.cwd = join(ROOT, "work", "mallory-n7"); mkdirSync(m.cwd, { recursive: true });
  m.run("init", "--platform", "web", "--bot", "n7"); m.challenge(`https://gist.github.com/mallory/${gid("m7")}`, showOnGist(mallory, "m7"));
  const ev = selfIssued(`/botproof/${(m.manifest.challenge as { nonce: string }).nonce}`, "mallory.example", "https://agent.mallory.example");
  ev.request.path += "/x"; writeFileSync(join(m.cwd, "ev.json"), JSON.stringify(ev));
  assert.equal(m.run("evidence", "ev.json").code, 1);
});
test("N8 evidence + copied challenge cannot take over a grok bot", async () => {
  const d = adv(); write(d, "creators/github-mallory.json", mc());
  const ev = selfIssued(`/botproof/${(grace.manifest.challenge as { nonce: string }).nonce}`, "mallory.example", "https://agent.mallory.example");
  write(d, "bots/grok/GrokBot123/manifest.json", mallory.craft({ v: 1, type: "bot", platform: "grok", botId: "GrokBot123", name: "Grace Helper", version: "9.9.9", seq: 99, challenge: grace.manifest.challenge, platformEvidence: ev, creator: "github:mallory", ts: new Date().toISOString() }));
  await blocked(d, "grok/GrokBot123", { author: "mallory" });
});

test("K1 a rotated key keeps the bot", async () => {
  const a = new Actor("alice"); a.home = join(ROOT, "home", "alice-rot"); a.cwd = join(ROOT, "work", "alice-rot");
  cpSync(alice.home, a.home, { recursive: true }); cpSync(alice.cwd, a.cwd, { recursive: true }); a.env.BOTPROOF_HOME = a.home;
  rmSync(join(a.home, "out"), { recursive: true, force: true });
  const r = a.run("rotate"); assert.equal(r.code, 0, r.out);
  web.gists[gid("galice")].content = r.out.match(/botproof-proof:\S+/)![0]; save();
  assert.equal(a.run("link", "github", "alice", "--proof", `https://gist.github.com/alice/${gid("galice")}`).code, 0);
  a.challenge(ALICE_PAGE, showOnGist(a, "alicebot"));
  assert.equal(a.run("sign").code, 0);
  const d = adv(); assert.equal(a.run("publish", "--to-dir", d).code, 0);
  assert.deepEqual(await check(d, f, { baseDir: REG, author: "alice" }), []);
  const res = await evaluate(bundle(d, "web/alice-bot"), f);
  assert.equal(res.strength, "challenge-passed", res.ownershipDetail);
  assert.ok(readFileSync(join(a.home, "key.pem"), "utf8").includes("ENCRYPTED PRIVATE KEY"));
});

test("R1 verify flags an API document that doesn't match the index hash", async () => {
  const site = mkdtempSync(join(ROOT, "site-"));
  await build(REG, site, f, "abc123");
  const api = "https://api.test", get = (p: string) => readFileSync(join(site, p), "utf8");
  web.pages[`${api}/api/index.json`] = get("api/index.json");
  web.pages[`${api}/api/bots/web/alice-bot.json`] = get("api/bots/web/alice-bot.json"); save();
  const ok = alice.run("verify", "web/alice-bot", "--registry", api);
  assert.equal(ok.code, 0, ok.out); assert.match(ok.out, /registry commit abc123 \(index hashes match\)/);
  const j = JSON.parse(get("api/bots/web/alice-bot.json")); j.docs.attestations = [];
  web.pages[`${api}/api/bots/web/alice-bot.json`] = JSON.stringify(j); save();
  const stripped = alice.run("verify", "web/alice-bot", "--registry", api);
  assert.equal(stripped.code, 1); assert.match(stripped.out, /lists 1 review/);
  j.docs.attestations = JSON.parse(get("api/bots/web/alice-bot.json")).docs.attestations; j.docs.manifest.name = "Evil";
  web.pages[`${api}/api/bots/web/alice-bot.json`] = JSON.stringify(j); save();
  const bad = alice.run("verify", "web/alice-bot", "--registry", api);
  assert.equal(bad.code, 1); assert.match(bad.out, /don't match the registry index/);
});

test("cleanup", () => rmSync(ROOT, { recursive: true, force: true }));
