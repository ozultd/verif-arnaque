// Runs the browser engine against the same samples as the Python tests.
// Usage: python scripts/export_web.py && node tests/web/test_engine.mjs
import { readFileSync } from "node:fs";
import vm from "node:vm";

const here = new URL(".", import.meta.url);
globalThis.window = globalThis;
vm.runInThisContext(readFileSync(new URL("../../docs/patterns.js", here), "utf8"));
vm.runInThisContext(readFileSync(new URL("../../docs/engine.js", here), "utf8"));

const { analyze, formatReply } = globalThis.VerifArnaque;
const { scams, legit } = JSON.parse(readFileSync(new URL("samples.json", here), "utf8"));
const rank = { no_signs: 0, suspect: 1, danger: 2 };
let failed = 0;

for (const [label, text, minimum] of scams) {
  const r = analyze(text);
  if (rank[r.level] < rank[minimum]) { failed++; console.log("FAIL scam", label, r.level, r.score); }
}
for (const [label, text] of legit) {
  const r = analyze(text);
  if (r.level === "danger") { failed++; console.log("FAIL legit", label, r.score); }
}
const green = formatReply(analyze("Bonjour, a demain pour le cafe."), "sms");
if (!green.startsWith("🟢") || !green.includes("ne garantit pas")) { failed++; console.log("FAIL green reply"); }

console.log(`${scams.length + legit.length + 1 - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
