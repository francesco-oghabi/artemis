#!/usr/bin/env node
// Validate: scan every t("key")/t('key') reference under src and reconcile it against en-US.json.
// Reports: (1) keys referenced in code but missing from the JSON (prints the raw key to add); (2) files with leftover hardcoded CJK.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const SRC = new URL("../web/src/", import.meta.url).pathname;
const enUS = JSON.parse(readFileSync(join(SRC, "i18n/locales/en-US.json"), "utf8"));

function walk(dir, acc = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const s = statSync(p);
    if (s.isDirectory()) walk(p, acc);
    else if (/\.(tsx?|ts)$/.test(e)) acc.push(p);
  }
  return acc;
}

function hasKey(obj, dotted) {
  return dotted.split(".").reduce((o, k) => (o && typeof o === "object" ? o[k] : undefined), obj) !== undefined;
}

const files = walk(SRC);
const KEY_RE = /\bt\(\s*["'`]([a-zA-Z0-9_.]+)["'`]/g;
const missing = new Map(); // key -> [files]
let refCount = 0;

for (const f of files) {
  const src = readFileSync(f, "utf8");
  let m;
  while ((m = KEY_RE.exec(src))) {
    const key = m[1];
    if (!key.includes(".")) continue; // skip non-namespaced keys (e.g. variables)
    refCount++;
    if (!hasKey(enUS, key)) {
      const rel = f.replace(SRC, "");
      if (!missing.has(key)) missing.set(key, new Set());
      missing.get(key).add(rel);
    }
  }
}

console.log(`Scanned ${files.length} files, ${refCount} t() references.`);
if (missing.size === 0) {
  console.log("✓ All t() keys exist in en-US.json.");
} else {
  console.log(`✗ ${missing.size} keys missing from en-US.json:`);
  for (const [k, fs] of missing) console.log(`  ${k}  ← ${[...fs].join(", ")}`);
}

// Leftover CJK (excluding comment lines and the locales directory)
const inCJK = (ch) => {
  const n = ch.codePointAt(0);
  return n >= 0x4e00 && n <= 0x9fff;
};
const residual = [];
for (const f of files) {
  if (f.includes("/i18n/locales/") || f.includes("/lib/mock/")) continue;
  const lines = readFileSync(f, "utf8").split("\n");
  let n = 0;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue; // comment
    if ([...line].some(inCJK)) n++;
  }
  if (n > 0) residual.push([f.replace(SRC, ""), n]);
}
residual.sort((a, b) => b[1] - a[1]);
console.log(`\nFiles with leftover CJK (non-comment, non-mock/locale): ${residual.length}`);
for (const [f, n] of residual) console.log(`  ${String(n).padStart(4)}  ${f}`);

process.exit(missing.size === 0 ? 0 : 1);
