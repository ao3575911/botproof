// Sandbox network for CLI subprocesses: serves fake gists, users and pages from $FAKEWEB. Nothing leaves the box.
import { readFileSync } from "node:fs";
import { fakeFetch } from "./fakeweb.mjs";
globalThis.fetch = (url, init) => fakeFetch(JSON.parse(readFileSync(process.env.FAKEWEB, "utf8")))(url, init);
