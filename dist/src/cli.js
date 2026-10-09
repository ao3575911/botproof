#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { randomBytes } from "node:crypto";
import { ID_RE, PLATFORMS, docHash, home, loadOrCreateKey, now, rotationDoc, sha256, signDoc, slug } from "./core.js";
import { X_POST, safeGet, challengeText, checkDns, checkGithub, checkX, proofText } from "./proofs.js";
import { build, check, evaluate, load } from "./registry.js";
import { checkPlatformEvidence } from "./platform.js";
const VERSION = "0.3.2";
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
  verify <platform>/<botId> [--git | --registry dir]
                              check a bot: signatures, live proofs, score
                              (--git: from a fresh clone of the registry, not the API)
                              (--trust a,b | file: only count reviews from these handles)
                              (--min-strength s: exit 3 below it)
  Exit codes: 0 ok, 1 error, 2 invalid or revoked, 3 below --min-strength
  attest <platform>/<botId> --tag <reviewed|audited|used-ok|flagged> [--note t]
                              sign a review of someone else's bot
  transfer <platform>/<botId> --to github:<user> --to-key <key>
                              hand a bot to another creator
  revoke <hash> [--reason t]  withdraw something you signed
  revoke --key [--since date] revoke your key (lost or stolen); its later signatures are void
  rotate                      move to a new key; your bots stay yours
  key [export]                show your key id, or print the encrypted key for backup

  Files: encrypted key and creator profile in ${home()}, manifest in ./${MANIFEST}
  Passphrase: prompted, or BOTPROOF_PASSPHRASE`;
const die = (msg) => { console.error("error: " + msg); process.exit(1); };
const rd = (p) => JSON.parse(readFileSync(p, "utf8"));
const wr = (p, d) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(d, null, 2) + "\n"); };
const creatorFile = () => join(home(), "creator.json");
const outbox = () => join(home(), "out");
const gh = (args, cwd) => execFileSync("gh", args, { cwd, encoding: "utf8" }).trim();
const git = (args, cwd) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }).trim();
function botRef(ref) {
    const [platform, botId] = (ref || "").split("/");
    if (!platform || !botId || !ID_RE.test(platform) || !ID_RE.test(botId))
        die("expected <platform>/<botId>");
    return { platform, botId };
}
async function askHidden(prompt) {
    const { createInterface } = await import("node:readline");
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(prompt))
        process.stdout.write(prompt); };
    const answer = await new Promise((r) => rl.question(prompt, r));
    rl.close();
    process.stdout.write("\n");
    return answer;
}
async function fetchBundle(platform, botId, registry, viaGit = false) {
    if (viaGit) {
        const dir = mkdtempSync(join(tmpdir(), "botproof-git-"));
        execFileSync("git", ["clone", "-q", "--depth", "1", `https://github.com/${REGISTRY}.git`, dir]);
        registry = dir;
    }
    if (registry && existsSync(registry)) {
        const b = load(registry).bots.find((x) => x.bundle.manifest.platform === platform && x.bundle.manifest.botId === botId);
        if (!b)
            return die("not in registry");
        let commit = "";
        try {
            commit = execFileSync("git", ["-C", registry, "rev-parse", "HEAD"], { encoding: "utf8", stdio: "pipe" }).trim();
        }
        catch { /* not a git dir */ }
        return { ...b.bundle, note: commit ? `registry commit ${commit}` : `registry dir ${registry}` };
    }
    const base = registry || API;
    const r = await safeGet(fetch, `${base}/api/bots/${platform}/${botId}.json`);
    if (!r.ok)
        die(`not found in registry (${r.status})`);
    const docs = (await r.json()).docs;
    delete docs.platforms; // the allowlist is never taken from a mirror; use --registry <dir> for the registry's own list
    const idx = (await (await safeGet(fetch, `${base}/api/index.json`)).json());
    const pinned = new Set(Object.values(idx.docs || {}));
    const all = [docs.manifest, docs.creator, ...docs.attestations, ...docs.revocations, ...(docs.versions || []), ...(docs.keyRevocations || []), ...Object.values(docs.attesters || {})].filter((d) => !!d);
    const bad = all.filter((d) => !pinned.has(docHash(d)));
    if (bad.length)
        die(`${bad.length} document(s) don't match the registry index hashes; try --git`);
    const listed = Object.keys(idx.docs || {}).filter((p) => p.startsWith(`bots/${platform}/${botId}/attestations/`)).length;
    if (listed !== docs.attestations.length)
        die(`the index lists ${listed} review(s) but the API returned ${docs.attestations.length}; try --git`);
    return { ...docs, note: `registry commit ${idx.registryCommit || "unknown"} (index hashes match)` };
}
async function main() {
    const { values: o, positionals: [cmd, ...args] } = parseArgs({ allowPositionals: true, options: {
            platform: { type: "string" }, bot: { type: "string" }, name: { type: "string" }, model: { type: "string" },
            "bot-version": { type: "string" }, "prompt-file": { type: "string" }, proof: { type: "string" },
            url: { type: "string" }, tag: { type: "string" }, note: { type: "string" }, reason: { type: "string" },
            registry: { type: "string" }, base: { type: "string" }, author: { type: "string" }, to: { type: "string" }, "to-key": { type: "string" }, "version-hash": { type: "string" }, key: { type: "boolean" }, git: { type: "boolean" }, trust: { type: "string" }, "min-strength": { type: "string" }, since: { type: "string" }, "to-dir": { type: "string" }, json: { type: "boolean" }, help: { type: "boolean", short: "h" }, version: { type: "boolean", short: "v" },
        } });
    if (o.version)
        return console.log(VERSION);
    if (!cmd || o.help)
        return console.log(HELP);
    const key = async () => {
        const f = join(home(), "key.pem");
        if (!process.env.BOTPROOF_PASSPHRASE && process.stdin.isTTY && (!existsSync(f) || readFileSync(f, "utf8").includes("ENCRYPTED")))
            process.env.BOTPROOF_PASSPHRASE = await askHidden("Key passphrase: ");
        try {
            return loadOrCreateKey();
        }
        catch (e) {
            return die(e.message);
        }
    };
    const creator = () => existsSync(creatorFile()) ? rd(creatorFile()) : die("no creator profile: run `botproof link github <user>` first");
    switch (cmd) {
        case "init": {
            const share = o.bot?.match(/^https:\/\/x\.ai\/bot\/([A-Za-z0-9_-]+)\/?$/);
            if (share) {
                o.platform ??= "grok";
                o.bot = share[1];
            }
            if (!o.platform || !o.bot)
                die("init needs --bot <x.ai/bot link>, or --platform and --bot");
            if (share && o.platform !== "grok")
                die("an x.ai/bot link is a grok bot");
            if (!PLATFORMS.includes(o.platform))
                die(`platform must be one of ${PLATFORMS.join(", ")}`);
            if (!ID_RE.test(o.bot))
                die("bot id may use letters, digits, . _ -");
            const k = await key();
            const m = { v: 1, type: "bot", platform: o.platform, botId: o.bot, name: o.name || o.bot, model: o.model,
                version: o["bot-version"] || "0.1.0", promptHash: o["prompt-file"] ? "sha256:" + sha256(readFileSync(o["prompt-file"])) : undefined };
            wr(MANIFEST, m);
            console.log(`wrote ${MANIFEST}${k.created ? `\nnew key ${k.id}` : ""}\nnext: botproof link github <user>`);
            break;
        }
        case "link": {
            const [type, subject] = args;
            if (!type || !subject)
                die("usage: link github <user> | link x <url> | link dns <domain>");
            const k = await key();
            const c = existsSync(creatorFile()) ? rd(creatorFile()) : { v: 1, type: "creator", links: [] };
            let links = c.links.filter((l) => l.type !== type);
            if (type === "github") {
                const user = subject.toLowerCase();
                if (!o.proof) {
                    console.log(`Put this line in a public gist (or your profile README), then rerun with --proof <gist-url> or --proof readme:\n\n${proofText("github", user, k.id)}`);
                    return;
                }
                const r = await checkGithub(user, o.proof, k.id);
                if (!r.ok)
                    die(r.detail);
                links.push({ type, user, proof: o.proof });
                c.handle = `github:${user}`;
            }
            else if (type === "dns") {
                const domain = subject.toLowerCase();
                const r = await checkDns(domain, k.id);
                if (!r.ok) {
                    console.log(`Add a TXT record at _botproof.${domain}:\n\n${proofText("dns", domain, k.id)}`);
                    die(r.detail);
                }
                links.push({ type, domain });
            }
            else if (type === "x") {
                const xm = subject.match(X_POST);
                if (!xm)
                    die("expected an X post URL, e.g. https://x.com/<you>/status/<id>");
                const r = await checkX(subject, k.id);
                if (!r.ok) {
                    console.log(`Your post must contain:\n${proofText("x", xm[1].toLowerCase(), k.id)}`);
                    if (r.reachable)
                        die(r.detail);
                    console.log(`Could not reach X (${r.detail}); recorded as self-claimed.`);
                }
                links.push({ type, url: subject });
            }
            else
                die("unknown link type " + type);
            if (!c.handle)
                die("link github first: GitHub is the creator handle in v0");
            wr(creatorFile(), signDoc({ ...c, links, ts: now() }, k.priv));
            console.log(`linked ${type}: ${subject}`);
            break;
        }
        case "challenge": {
            const m = rd(MANIFEST);
            if (!o.url && m.platform === "grok")
                o.url = `https://x.ai/bot/${m.botId}`;
            if (!o.url)
                die("challenge needs --url <public page of the bot>");
            const nonce = randomBytes(9).toString("hex");
            wr(MANIFEST, { ...m, challenge: { nonce, url: o.url, issued: now() }, sig: undefined, key: undefined });
            console.log(`Show this on ${o.url} (bot description, bio or a reply), then run botproof sign:\n\n${challengeText(String(m.platform), String(m.botId), (await key()).id, nonce)}`);
            break;
        }
        case "evidence": {
            if (!args[0])
                die("usage: evidence <file.json> (a captured Web Bot Auth request, see README)");
            const m = rd(MANIFEST), ev = rd(args[0]);
            const ch = m.challenge;
            const k = await key();
            const code = ch?.nonce ? challengeText(String(m.platform), String(m.botId), k.id, ch.nonce) : "";
            const r = await checkPlatformEvidence(ev, { code, issued: ch?.issued });
            if (!r.ok)
                die(r.detail);
            wr(MANIFEST, { ...m, platformEvidence: ev, sig: undefined, key: undefined });
            console.log(`platform evidence ok: ${r.detail}; run botproof sign`);
            break;
        }
        case "sign": {
            const k = await key(), c = creator();
            if (c.key !== k.id)
                die("creator profile was signed with another key; run link github again");
            const prev = rd(MANIFEST);
            const m = signDoc({ ...prev, seq: (Number(prev.seq) || 0) + 1, creator: c.handle, ts: now() }, k.priv);
            wr(MANIFEST, m);
            console.log(`signed ${m.platform}/${m.botId} version ${m.version}\nhash ${docHash(m)}`);
            break;
        }
        case "attest": {
            const { platform, botId } = botRef(args[0]);
            const tags = ["reviewed", "audited", "used-ok", "flagged"];
            if (!o.tag || !tags.includes(o.tag))
                die("--tag must be one of " + tags.join(", "));
            const k = await key(), c = creator();
            let versionHash = o["version-hash"];
            if (!versionHash) {
                const res = await fetchBundle(platform, botId, o.registry).then((b) => docHash(b.manifest));
                versionHash = res;
            }
            if (!/^[0-9a-f]{64}$/.test(versionHash))
                die("bad --version-hash");
            const a = signDoc({ v: 1, type: "attestation", platform, botId, versionHash, attester: c.handle, tag: o.tag, note: o.note || "", ts: now() }, k.priv);
            const p = join(outbox(), "bots", platform, botId, "attestations", `${slug(String(c.handle))}-${Date.now()}.json`);
            wr(p, a);
            console.log(`signed ${o.tag} for ${platform}/${botId}; run botproof publish`);
            break;
        }
        case "transfer": {
            const { platform, botId } = botRef(args[0]);
            if (!o.to?.match(/^github:[A-Za-z0-9-]+$/) || !o["to-key"]?.startsWith("ed25519:"))
                die("usage: transfer <platform>/<botId> --to github:<user> --to-key <their key id>");
            const t = signDoc({ v: 1, type: "transfer", platform, botId, to: o.to, toKey: o["to-key"], ts: now() }, (await key()).priv);
            wr(join(outbox(), "bots", platform, botId, "transfers", `${docHash(t)}.json`), t);
            console.log(`transfer to ${o.to} signed; run botproof publish, then they publish their manifest`);
            break;
        }
        case "revoke": {
            const k = await key();
            if (o.key) {
                const c = creator();
                const since = o.since ? new Date(o.since).toISOString() : now();
                const r = signDoc({ v: 1, type: "key-revocation", revokedKey: k.id, since, reason: o.reason || "", ts: now() }, k.priv);
                wr(join(outbox(), "keys", slug(String(c.handle)), `revoked-${docHash(r)}.json`), r);
                console.log(`key ${k.id} revoked from ${since}; run botproof publish. Anything it signs from then on is invalid.\nTo keep your bots, run botproof rotate first.`);
                break;
            }
            const target = args[0];
            if (!/^[0-9a-f]{64}$/.test(target || ""))
                die("revoke needs the sha256 hash of the signed document (shown by verify), or --key");
            const r = signDoc({ v: 1, type: "revocation", target, reason: o.reason || "", ts: now() }, k.priv);
            wr(join(outbox(), "revocations", `${target}.json`), r);
            console.log(`revocation signed for ${target}; run botproof publish`);
            break;
        }
        case "rotate": {
            const c = creator(), old = await key();
            renameSync(old.file, join(home(), `key-${Date.now()}.old.pem`));
            const nw = await key();
            const rot = rotationDoc(String(c.handle), old.priv, nw.priv);
            wr(join(outbox(), "keys", slug(String(c.handle)), `rotation-${docHash(rot)}.json`), rot);
            wr(creatorFile(), signDoc({ ...c, ts: now() }, nw.priv));
            const user = String(c.handle).replace(/^github:/, "");
            console.log(`new key ${nw.id} (old key kept as a .old.pem file)\n\n1. Replace the line in your proof gist with:\n   ${proofText("github", user, nw.id)}\n2. botproof link github ${user} --proof <gist-url>\n3. For each bot: botproof challenge, update its page, botproof sign\n4. botproof publish (optionally botproof revoke --key with the old key first)`);
            break;
        }
        case "key": {
            const k = await key();
            if (args[0] === "export")
                process.stdout.write(readFileSync(k.file, "utf8"));
            else
                console.log(`key ${k.id}\nfile ${k.file}\nencrypted ${k.encrypted ? "yes" : "NO: rotate to an encrypted key"}`);
            break;
        }
        case "publish": {
            const c = creator();
            const stage = (dir) => {
                wr(join(dir, "creators", slug(String(c.handle)) + ".json"), c);
                if (existsSync(MANIFEST)) {
                    const m = rd(MANIFEST);
                    if (!m.sig)
                        die("botproof.json is not signed; run botproof sign");
                    const base = join(dir, "bots", String(m.platform), String(m.botId));
                    wr(join(base, "manifest.json"), m);
                    wr(join(base, "versions", docHash(m) + ".json"), m);
                }
                if (existsSync(outbox()))
                    cpSync(outbox(), dir, { recursive: true });
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
                if (!git(["status", "--porcelain"], dir))
                    return console.log("nothing new to publish");
                const branch = `botproof/${slug(String(c.handle))}-${Date.now()}`;
                git(["checkout", "-q", "-b", branch], dir);
                git(["add", "-A"], dir);
                git(["commit", "-q", "-m", `botproof: update from ${c.handle}`], dir);
                git(["push", "-q", remote, branch], dir);
                const url = gh(["pr", "create", "--repo", repo, "--head", `${me}:${branch}`, "--title", `botproof: ${c.handle}`, "--body", "Signed by the botproof CLI. CI verifies signatures and proofs."]);
                rmSync(outbox(), { recursive: true, force: true });
                console.log(url);
            }
            finally {
                rmSync(dir, { recursive: true, force: true });
            }
            break;
        }
        case "verify": {
            const { platform, botId } = botRef(args[0]);
            const docs = await fetchBundle(platform, botId, o.registry, o.git);
            let trust;
            if (o.trust)
                trust = (existsSync(o.trust) ? readFileSync(o.trust, "utf8") : o.trust).split(/[\s,]+/).filter(Boolean).map((h) => (h.includes(":") ? h : `github:${h}`));
            const res = await evaluate(docs, fetch, { trust });
            const RANK = ["revoked", "self-claimed", "challenge-passed", "platform-signed"];
            const min = o["min-strength"];
            if (min && !RANK.includes(min))
                die(`--min-strength must be one of ${RANK.slice(1).join(", ")}`);
            const below = !!min && (res.errors.length > 0 || RANK.indexOf(res.strength) < RANK.indexOf(min));
            if (o.json) {
                console.log(JSON.stringify(res, null, 2));
                if (below)
                    process.exit(3);
                return;
            }
            const ok = (b) => (b ? "✓" : "✗");
            console.log(`${res.name} (${platform}/${botId}) v${res.version}`);
            console.log(`${ok(!res.errors.length)} signatures${res.errors.length ? ": " + res.errors.join("; ") : ""}`);
            for (const l of res.links)
                console.log(`${ok(l.status === "verified")} ${l.type} ${l.subject}: ${l.status}`);
            console.log(`  ownership: ${res.strength} (${res.ownershipDetail})`);
            const earlier = res.attestations.filter((a) => a.status === "earlier version").length;
            if (earlier)
                console.log(`  reviews of earlier versions: ${earlier} (not counted)`);
            for (const a of res.attestations.filter((x) => x.status !== "earlier version"))
                console.log(`  ${a.tag} by ${a.attester}: ${a.status}${a.weight ? ` (${a.weight > 0 ? "+" : ""}${a.weight})` : ""}`);
            console.log(`score ${res.score} = identity ${res.breakdown.identity} + ownership ${res.breakdown.ownership} + reviews ${res.breakdown.reviews}`);
            console.log(`hash ${res.versionHash}`);
            if (docs.note)
                console.log(docs.note);
            if (res.errors.length || res.strength === "revoked")
                process.exit(2);
            if (below) {
                console.error(`below --min-strength ${min}`);
                process.exit(3);
            }
            break;
        }
        case "registry": {
            const [sub, dir = ".", out = "_site"] = args;
            if (sub === "check") {
                let baseDir;
                if (o.base) {
                    if (!/^[\w./-]{1,100}$/.test(o.base))
                        die("bad --base ref");
                    baseDir = mkdtempSync(join(tmpdir(), "botproof-base-"));
                    execFileSync("sh", ["-c", 'git -C "$0" archive "$1" | tar -x -C "$2"', dir, o.base, baseDir]);
                }
                if (o.author && !/^[A-Za-z0-9-]{1,39}$/.test(o.author))
                    die("bad --author");
                const errs = await check(dir, fetch, { baseDir, author: o.author });
                errs.forEach((e) => console.error("✗ " + e));
                if (errs.length)
                    process.exit(1);
                console.log("✓ registry valid");
            }
            else if (sub === "build") {
                const idx = await build(dir, out);
                console.log(`built ${idx.length} bots into ${out}`);
            }
            else
                die("usage: registry check|build <dir> [out]");
            break;
        }
        default: die(`unknown command ${cmd}\n\n${HELP}`);
    }
}
main().catch((e) => die(e instanceof Error ? e.message : String(e)));
