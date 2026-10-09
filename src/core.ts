import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, KeyObject } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type Doc = Record<string, unknown> & { key?: string; sig?: string };

/** Canonical JSON: sorted keys, no whitespace (JCS for strings, ints, bools). */
export function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") {
    if (typeof v === "number" && !Number.isFinite(v)) throw new Error("non-finite number");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const o = v as Record<string, unknown>;
  return "{" + Object.keys(o).filter((k) => o[k] !== undefined).sort()
    .map((k) => JSON.stringify(k) + ":" + canonical(o[k])).join(",") + "}";
}

export const sha256 = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function keyId(pub: KeyObject): string {
  const der = pub.export({ format: "der", type: "spki" }) as Buffer;
  return "ed25519:" + der.subarray(der.length - 32).toString("base64url");
}

export function publicKey(id: string): KeyObject {
  if (!id.startsWith("ed25519:")) throw new Error("unsupported key: " + id);
  const raw = Buffer.from(id.slice(8), "base64url");
  if (raw.length !== 32) throw new Error("bad key length");
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

/** Sign a document. The signer's key id is embedded as `key`. */
export function signDoc<T extends Doc>(doc: T, priv: KeyObject): T {
  const { sig: _sig, ...rest } = doc;
  const body = { ...rest, key: keyId(createPublicKey(priv)) };
  const sig = sign(null, Buffer.from(canonical(body)), priv).toString("base64url");
  return { ...body, sig } as T;
}

export function verifyDoc(doc: Doc): boolean {
  const { sig, ...body } = doc;
  if (typeof sig !== "string" || typeof body.key !== "string") return false;
  try {
    return verify(null, Buffer.from(canonical(body)), publicKey(body.key), Buffer.from(sig, "base64url"));
  } catch { return false; }
}

/** Version hash of a signed document: sha256 of its canonical body. */
export const docHash = (doc: Doc) => { const { sig: _s, ...body } = doc; return sha256(canonical(body)); };

export function home(): string {
  return process.env.BOTPROOF_HOME || join(process.env.HOME || ".", ".botproof");
}

export function loadOrCreateKey(dir = home()): { priv: KeyObject; id: string; created: boolean } {
  const file = join(dir, "key.pem");
  let created = false;
  if (!existsSync(file)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const { privateKey } = generateKeyPairSync("ed25519");
    writeFileSync(file, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600, flag: "wx" });
    created = true;
  }
  const priv = createPrivateKey(readFileSync(file));
  return { priv, id: keyId(createPublicKey(priv)), created };
}

export const slug = (handle: string) => handle.replace(/:/g, "-");
export const ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
export const now = () => new Date().toISOString();
