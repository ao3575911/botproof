import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = new URL("../src/cli.js", import.meta.url).pathname;
export function cli(args: string[], cwd: string, env: Record<string, string> = {}) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8", stdio: "pipe", env: { ...process.env, ...env } }) };
  } catch (e) { const x = e as { status: number; stdout: string; stderr: string }; return { code: x.status, out: x.stdout + x.stderr }; }
}
export const sandbox = () => { const d = mkdtempSync(join(tmpdir(), "bpcli-")); return { cwd: d, env: { BOTPROOF_HOME: join(d, ".home"), BOTPROOF_PASSPHRASE: "test-pass" } }; };

test("README quickstart: init with only an x.ai/bot link", () => {
  const s = sandbox();
  const r = cli(["init", "--bot", "https://x.ai/bot/0fF7Cqp8LTzh9JGQ-je3M", "--name", "My Bot"], s.cwd, s.env);
  assert.equal(r.code, 0, r.out);
  const m = JSON.parse(readFileSync(join(s.cwd, "botproof.json"), "utf8"));
  assert.equal(m.platform, "grok");
  assert.equal(m.botId, "0fF7Cqp8LTzh9JGQ-je3M");
});

test("bad CLI input fails cleanly", () => {
  const s = sandbox();
  for (const args of [["init", "--platform", "web", "--bot", "../../etc/passwd"], ["init", "--platform", "<x>", "--bot", "b"], ["verify", "a/b/c"], ["revoke", "nothex"], ["frobnicate"]])
    assert.equal(cli(args, s.cwd, s.env).code, 1, args.join(" "));
});
