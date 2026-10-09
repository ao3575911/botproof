#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { randomBytes } from "node:crypto";
import { Doc, ID_RE, PLATFORMS, docHash, home, loadOrCreateKey, now, sha256, signDoc, slug } from "./core.js";
import { X_POST, challengeText, checkDns, checkGithub, checkX, proofText } from "./proofs.js";
import { build, check, evaluate } from "./registry.js";
import { checkPlatformEvidence } from "./platform.js";

const VERSION = "0.2.0";
const REGISTRY = process.env.BOTPROOF_REGISTRY || "ao3575911/botproof-registry";
const API = process.env.BOTPROOF_API || "https://ao3575911.github.io/botproof-registry";
const MANIFEST = "botproof.json";

const HELP = `botproof ${VERSION}: signed identity for AI agents

  init --platform <p> --bot <id|x.ai/bot link> [--name n] [--model m] [--bot-version v] [--prompt-file f]
                              start a bot manifest (botproof.json) and your key
  link github <user> [--proof <gist-url>|readme]
                              prove your GitHub account (prints the proof text first)
  link x <post-url>           prove your X account with a post
  link dns <domain>           prove a domain with a TXT record
  challenge [--url <bot-page>] get a one-time code to show on the bot's public page
                              (grok: put it in the bot description and update the share template)
  evidence <file.json>        attach a platform-signed request (Web Bot Auth)
  sign                        sign botproof.json with your key
  publish [--to-dir d]        open a PR to the registry with your signed files
                              (--to-dir: write them into a local registry copy instead)
  verify <platform>/<botId>   check a bot: signatures, live proofs, score
  attest <platform>/<botId> --tag <reviewed|audited|used-ok|flagged> [--note t]
                              sign a review of someone else's bot
  revoke <hash> [--reason t]  withdraw something you signed

  Files: key and creator profile in ${home()}, manifest in ./${MANIFEST}`;

const die = (msg: string): never => { console.error("error: " + msg); process.exit(1); };
const rd = (p: string) => JSON.parse(readFileSync(p, "utf8")) as Doc;
const wr = (p: string, d: unknown) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(d, null, 2) + "\n"); };
const creatorFile = () => join(home(), "creator.json");
const outbox = () => join(home(), "out");
const gh = (args: string[], cwd?: string) => execFileSync("gh", args, { cwd, encoding: "utf8" }).trim();
const git = (args: string[], cwd: string) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }).trim();

function botRef(ref?: string) {
  const [platform, botId] = (ref || "").split("/");
  if (!platform || !botId || !ID_RE.test(platform) || !ID_RE.test(botId)) die("expected <platform>/<botId>");
  return { platform, botId };
}

async function main() {
  const { values: o, positionals: [cmd, ...args] } = parseArgs({ allowPositionals: true, options: {
    platform: { type: "string" }, bot: { type: "string" }, name: { type: "string" }, model: { type: "string" },
    "bot-version": { type: "string" }, "prompt-file": { type: "string" }, proof: { type: "string" },
    url: { type: "string" }, tag: { type: "string" }, note: { type: "string" }, reason: { type: "string" },
    registry: { type: "string" }, "to-dir": { type: "string" }, json: { type: "boolean" }, help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" },
  } });
  if (o.version) return console.log(VERSION);
  if (!cmd || o.help) return console.log(HELP);
  const key = () => loadOrCreateKey();
  const creator = (): Doc => existsSync(creatorFile()) ? rd(creatorFile()) : die("no creator profile: run `botproof link github <user>` first");

  switch (cmd) {
    case "init": {
      const share = o.bot?.match(/^https:\/\/x\.ai\/bot\/([A-Za-z0-9_-]+)\/?$/);
      if (share) { o.platform ??= "grok"; o.bot = share[1]; }
      if (!o.platform || !o.bot) die("init needs --bot <x.ai/bot link>, or --platform and --bot");
      if (share && o.platform !== "grok") die("an x.ai/bot link is a grok bot");
      if (!PLATFORMS.includes(o.platform!)) die(`platform must be one of ${PLATFORMS.join(", ")}`);
      if (!ID_RE.test(o.bot!)) die("bot id may use letters, digits, . _ -");
      const k = key();
      const m: Doc = { v: 1, type: "bot", platform: o.platform, botId: o.bot, name: o.name || o.bot, model: o.model,
        version: o["bot-version"] || "0.1.0", promptHash: o["prompt-file"] ? "sha256:" + sha256(readFileSync(o["prompt-file"]!)) : undefined };
      wr(MANIFEST, m);
      console.log(`wrote ${MANIFEST}${k.created ? `\nnew key ${k.id}` : ""}\nnext: botproof link github <user>`);
      break;
    }
    case "link": {
      const [type, subject] = args;
      if (!type || !subject) die("usage: link github <user> | link x <url> | link dns <domain>");
      const k = key();
      const c: Doc = existsSync(creatorFile()) ? rd(creatorFile()) : { v: 1, type: "creator", links: [] };
      let links = (c.links as Record<string, string>[]).filter((l) => l.type !== type);
      if (type === "github") {
        const user = subject.toLowerCase();
        if (!o.proof) {
          console.log(`Put this line in a public gist (or your profile README), then rerun with --proof <gist-url> or --proof readme:\n\n${proofText("github", user, k.id)}`);
          return;
        }
        const r = await checkGithub(user, o.proof!, k.id);
        if (!r.ok) die(r.detail);
        links.push({ type, user, proof: o.proof! });
        c.handle = `github:${user}`;
      } else if (type === "dns") {
        const domain = subject.toLowerCase();
        const r = await checkDns(domain, k.id);
        if (!r.ok) { console.log(`Add a TXT record at _botproof.${domain}:\n\n${proofText("dns", domain, k.id)}`); die(r.detail); }
        links.push({ type, domain });
      } else if (type === "x") {
        const xm = subject.match(X_POST);
        if (!xm) die("expected an X post URL, e.g. https://x.com/<you>/status/<id>");
        const r = await checkX(subject, k.id);
        if (!r.ok) {
          console.log(`Your post must contain:\n${proofText("x", xm![1].toLowerCase(), k.id)}`);
          if (r.reachable) die(r.detail);
          console.log(`Could not reach X (${r.detail}); recorded as self-claimed.`);
        }
        links.push({ type, url: subject });
      } else die("unknown link type " + type);
      if (!c.handle) die("link github first: GitHub is the creator handle in v0");
      wr(creatorFile(), signDoc({ ...c, links, ts: now() }, k.priv));
      console.log(`linked ${type}: ${subject}`);
      break;
    }
    case "challenge": {
      const m = rd(MANIFEST);
      if (!o.url && m.platform === "grok") o.url = `https://x.ai/bot/${m.botId}`;
      if (!o.url) die("challenge needs --url <public page of the bot>");
      const nonce = randomBytes(9).toString("hex");
      wr(MANIFEST, { ...m, challenge: { nonce, url: o.url, issued: now() }, sig: undefined, key: undefined });
      console.log(`Show this on ${o.url} (bot description, bio or a reply), then run botproof sign:\n\n${challengeText(String(m.platform), String(m.botId), loadOrCreateKey().id, nonce)}`);
      break;
    }
    case "evidence": {
      if (!args[0]) die("usage: evidence <file.json> (a captured Web Bot Auth request, see README)");
      const m = rd(MANIFEST), ev = rd(args[0]);
      const ch = m.challenge as { nonce?: string; issued?: string } | undefined;
      const r = await checkPlatformEvidence(ev, ch?.nonce, ch?.issued);
      if (!r.ok) die(r.detail);
      wr(MANIFEST, { ...m, platformEvidence: ev, sig: undefined, key: undefined });
      console.log(`platform evidence ok: ${r.detail}; run botproof sign`);
      break;
    }
    case "sign": {
      const k = key(), c = creator();
      if (c.key !== k.id) die("creator profile was signed with another key; run link github again");
      const m: Doc = signDoc({ ...rd(MANIFEST), creator: c.handle, ts: now() }, k.priv);
      wr(MANIFEST, m);
      console.log(`signed ${m.platform}/${m.botId} version ${m.version}\nhash ${docHash(m)}`);
      break;
    }
    case "attest": {
      const { platform, botId } = botRef(args[0]);
      const tags = ["reviewed", "audited", "used-ok", "flagged"];
      if (!o.tag || !tags.includes(o.tag)) die("--tag must be one of " + tags.join(", "));
      const k = key(), c = creator();
      const a = signDoc({ v: 1, type: "attestation", platform, botId, attester: c.handle, tag: o.tag, note: o.note || "", ts: now() }, k.priv);
      const p = join(outbox(), "bots", platform, botId, "attestations", `${slug(String(c.handle))}-${Date.now()}.json`);
      wr(p, a);
      console.log(`signed ${o.tag} for ${platform}/${botId}; run botproof publish`);
      break;
    }
    case "revoke": {
      const target = args[0];
      if (!/^[0-9a-f]{64}$/.test(target || "")) die("revoke needs the sha256 hash of the signed document (shown by verify)");
      const r = signDoc({ v: 1, type: "revocation", target, reason: o.reason || "", ts: now() }, key().priv);
      wr(join(outbox(), "revocations", `${target}.json`), r);
      console.log(`revocation signed for ${target}; run botproof publish`);
      break;
    }
    case "publish": {
      const c = creator();
      const stage = (dir: string) => {
        wr(join(dir, "creators", slug(String(c.handle)) + ".json"), c);
        if (existsSync(MANIFEST)) {
          const m = rd(MANIFEST);
          if (!m.sig) die("botproof.json is not signed; run botproof sign");
          const base = join(dir, "bots", String(m.platform), String(m.botId));
          wr(join(base, "manifest.json"), m);
          wr(join(base, "versions", docHash(m) + ".json"), m);
        }
        if (existsSync(outbox())) cpSync(outbox(), dir, { recursive: true });
      };
      if (o["to-dir"]) {
        stage(o["to-dir"]);
        rmSync(outbox(), { recursive: true, force: true });
        console.log(`staged into ${o["to-dir"]}`);
        break;
      }
      const repo = o.registry || REGISTRY;
      const me = gh(["api", "user", "-q", ".login"]);
      const dir = mkdtempSync(join(tmpdir(), "botproof-"));
      try {
        gh(["repo", "clone", repo, dir, "--", "--depth", "1", "-q"]);
        let remote = "origin";
        if (repo.split("/")[0].toLowerCase() !== me.toLowerCase()) {
          gh(["repo", "fork", repo, "--clone=false"]);
          git(["remote", "add", "fork", `https://github.com/${me}/${repo.split("/")[1]}.git`], dir);
          remote = "fork";
        }
        stage(dir);
        if (!git(["status", "--porcelain"], dir)) return console.log("nothing new to publish");
        const branch = `botproof/${slug(String(c.handle))}-${Date.now()}`;
        git(["checkout", "-q", "-b", branch], dir);
        git(["add", "-A"], dir);
        git(["commit", "-q", "-m", `botproof: update from ${c.handle}`], dir);
        git(["push", "-q", remote, branch], dir);
        const url = gh(["pr", "create", "--repo", repo, "--head", `${me}:${branch}`, "--title", `botproof: ${c.handle}`, "--body", "Signed by the botproof CLI. CI verifies signatures and proofs."]);
        rmSync(outbox(), { recursive: true, force: true });
        console.log(url);
      } finally { rmSync(dir, { recursive: true, force: true }); }
      break;
    }
    case "verify": {
      const { platform, botId } = botRef(args[0]);
      let docs: { manifest: Doc; creator?: Doc; attestations: Doc[]; attesters: Record<string, Doc>; revocations: Doc[] };
      if (o.registry && existsSync(o.registry)) {
        const { load } = await import("./registry.js");
        const b = load(o.registry).bots.find((x) => x.bundle.manifest.platform === platform && x.bundle.manifest.botId === botId);
        docs = b ? b.bundle : die("not in registry");
      } else {
        const r = await fetch(`${o.registry || API}/api/bots/${platform}/${botId}.json`);
        if (!r.ok) die(`not found in registry (${r.status})`);
        docs = ((await r.json()) as { docs: typeof docs }).docs;
      }
      const res = await evaluate(docs);
      if (o.json) return console.log(JSON.stringify(res, null, 2));
      const ok = (b: boolean) => (b ? "✓" : "✗");
      console.log(`${res.name} (${platform}/${botId}) v${res.version}`);
      console.log(`${ok(!res.errors.length)} signatures${res.errors.length ? ": " + res.errors.join("; ") : ""}`);
      for (const l of res.links) console.log(`${ok(l.status === "verified")} ${l.type} ${l.subject}: ${l.status}`);
      console.log(`  ownership: ${res.strength} (${res.ownershipDetail})`);
      for (const a of res.attestations) console.log(`  ${a.tag} by ${a.attester}: ${a.status}${a.weight ? ` (${a.weight > 0 ? "+" : ""}${a.weight})` : ""}`);
      console.log(`score ${res.score} = identity ${res.breakdown.identity} + ownership ${res.breakdown.ownership} + reviews ${res.breakdown.reviews}`);
      console.log(`hash ${res.versionHash}`);
      if (res.errors.length || res.strength === "revoked") process.exit(2);
      break;
    }
    case "registry": {
      const [sub, dir = ".", out = "_site"] = args;
      if (sub === "check") {
        const errs = await check(dir);
        errs.forEach((e) => console.error("✗ " + e));
        if (errs.length) process.exit(1);
        console.log("✓ registry valid");
      } else if (sub === "build") {
        const idx = await build(dir, out);
        console.log(`built ${idx.length} bots into ${out}`);
      } else die("usage: registry check|build <dir> [out]");
      break;
    }
    default: die(`unknown command ${cmd}\n\n${HELP}`);
  }
}
main().catch((e) => die(e instanceof Error ? e.message : String(e)));
