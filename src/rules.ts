/** One rule set for documents, used by both `registry check` (CI) and `verify` (clients). */
import { Doc, ID_RE, PLATFORMS, verifyDoc } from "./core.js";

const TYPES = ["creator", "bot", "attestation", "revocation", "transfer", "key-revocation", "key-rotation"];
const isTs = (t: unknown) => typeof t === "string" && /^\d{4}-\d{2}-\d{2}T/.test(t) && !Number.isNaN(Date.parse(t));
const str = (v: unknown, max = 500) => typeof v === "string" && v.length <= max;

/** Shape errors for any signed document (no network). */
export function docErrors(d: Doc): string[] {
  const e: string[] = [];
  if (d.v !== 1) e.push("v must be 1");
  if (!TYPES.includes(String(d.type))) e.push(`unknown type ${String(d.type).slice(0, 40)}`);
  if (!isTs(d.ts)) e.push("ts must be an ISO date");
  if (!verifyDoc(d)) e.push("bad signature");
  if (d.type === "bot" || d.type === "attestation" || d.type === "transfer") {
    if (!PLATFORMS.includes(String(d.platform))) e.push(`platform must be one of ${PLATFORMS.join(", ")}`);
    if (!ID_RE.test(String(d.botId))) e.push("bad botId");
  }
  if (d.type === "bot") {
    if (!Number.isSafeInteger(d.seq) || Number(d.seq) < 1) e.push("manifest needs a positive integer seq");
    for (const k of ["name", "version", "creator"]) if (!str(d[k], 200)) e.push(`${k} must be a short string`);
  }
  if (d.type === "attestation" && (!str(d.note) || !/^[0-9a-f]{64}$/.test(String(d.versionHash)))) e.push("attestation needs a note string and a versionHash");
  return e;
}

/** A creator profile: valid shape, github:<user> handle, and a GitHub link for that same user. */
export function creatorErrors(c: Doc | undefined): string[] {
  if (!c) return ["creator not registered"];
  const e = docErrors(c);
  const gh = String(c.handle).match(/^github:([A-Za-z0-9-]{1,39})$/);
  if (!gh) e.push("handle must be github:<user>");
  else if (!((c.links as { type: string; user?: string }[]) || []).some((l) => l.type === "github" && l.user?.toLowerCase() === gh[1].toLowerCase()))
    e.push(`handle ${c.handle} has no GitHub link for that account`);
  return e.map((x) => `creator ${String(c.handle).slice(0, 60)}: ${x}`);
}
