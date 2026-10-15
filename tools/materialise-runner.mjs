// ---------------------------------------------------------------------------
// tools/materialise-runner.mjs — copies the runner and its dependency closure out of app.asar so a plain node.exe can host it.
//
// Author: Ethan-H1K, who offered these scripts in this repository's issue #1 and gave credit in the same thread.
// Origin: https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6170010818
// The body underneath this block is unedited. tools/README.md says what each arm is for
// and which number it reproduces; the count of packages the materialiser copies is printed
// by that script itself rather than written down anywhere.
// ---------------------------------------------------------------------------
// materialise-runner.mjs - copy the windows-acl runner and its dependency closure out of app.asar
// into a real directory, so a plain console node.exe (which cannot read app.asar) can run it.
//
//   "<DSH install>\DeepSeek Harness.exe" --expose-internals materialise-runner.mjs --out <dir>
//   "<node.exe>" <dir>\runner.js --workspace <ws> --temp <tmp> --mode workspace-write -- cmd.exe /c "echo ok"
//
// The closure is resolved two ways: package.json dependencies/peerDependencies/optional win32-x64
// entries, then a static scan of every emitted .js for bare import/require specifiers (repeat until
// nothing is missing). Absolute paths only: the copy resolves its own node_modules.
import fs from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";

const argv = process.argv.slice(2);
const outArg = argv[argv.indexOf("--out") + 1];
if (!outArg) {
  console.error("usage: materialise-runner.mjs --out <dir>");
  process.exit(2);
}
const OUT = path.resolve(outArg);
const OUT_NM = path.join(OUT, "node_modules");
const exeDir = path.dirname(process.execPath);
const ASAR_NM = process.env.SBX_ASAR_NM ||
  path.join(exeDir, "resources", "app.asar", "dsh", "node_modules");
const SEED_PKG = "@deepseek-ai/dsh-sandbox-windows-acl";

const pkgPath = (name) => path.join(ASAR_NM, ...name.split("/"));

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dst, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else { try { fs.copyFileSync(s, d); } catch {} }
  }
}

const BUILTINS = new Set([...builtinModules, ...builtinModules.map((m) => "node:" + m)]);

function pkgRoot(spec) {
  if (spec.startsWith(".") || spec.startsWith("data:") || spec.startsWith("file:")) return null;
  if (BUILTINS.has(spec)) return null;
  if (/^[-.]/.test(spec) || spec.length < 2) return null;
  const parts = spec.split("/");
  const root = spec.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
  return /^(@[A-Za-z0-9._-]+\/)?[A-Za-z0-9][A-Za-z0-9._-]*$/.test(root) ? root : null;
}

function scanSpecs(root) {
  const specs = new Set();
  (function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(js|mjs|cjs)$/.test(e.name)) {
        let text;
        try { text = fs.readFileSync(p, "utf8"); } catch { continue; }
        for (const m of text.matchAll(/(?:from|import|require)\s*\(?\s*['"]([^'"]+)['"]/g)) specs.add(m[1]);
      }
    }
  })(root);
  return [...specs];
}

const seen = new Set();
const queue = [SEED_PKG];
const copied = [];
const missing = [];
while (queue.length) {
  const name = queue.shift();
  if (seen.has(name)) continue;
  seen.add(name);
  const src = pkgPath(name);
  if (!fs.existsSync(src)) { missing.push(name); continue; }
  copyDir(src, path.join(OUT_NM, ...name.split("/")));
  copied.push(name);
  try {
    const pj = JSON.parse(fs.readFileSync(path.join(src, "package.json"), "utf8"));
    for (const d of Object.keys(pj.dependencies || {})) queue.push(d);
    for (const d of Object.keys(pj.peerDependencies || {})) queue.push(d);
    for (const d of Object.keys(pj.optionalDependencies || {})) if (/win32-x64/.test(d)) queue.push(d);
  } catch {}
}

for (let round = 0; round < 8; round++) {
  const roots = new Set(scanSpecs(OUT).map(pkgRoot).filter(Boolean));
  const need = [...roots].filter((r) => !fs.existsSync(path.join(OUT_NM, ...r.split("/"))));
  if (!need.length) break;
  let added = 0;
  for (const r of need) {
    const src = pkgPath(r);
    if (!fs.existsSync(src)) { missing.push(r); continue; }
    copyDir(src, path.join(OUT_NM, ...r.split("/")));
    copied.push(r);
    added++;
  }
  if (!added) break;
}

const libSrc = path.join(pkgPath(SEED_PKG), "lib");
if (!fs.existsSync(path.join(libSrc, "runner.js"))) { console.error("runner.js not found under " + libSrc); process.exit(3); }
copyDir(libSrc, OUT);
fs.writeFileSync(path.join(OUT, "package.json"), JSON.stringify({ name: "dsh-windows-acl-runner", private: true, type: "module" }, null, 2));

console.log("materialised into " + OUT);
console.log("packages copied (" + [...new Set(copied)].length + "): " + [...new Set(copied)].join(", "));
console.log("not present in app.asar (optional peers, other platforms, or scan noise): " + ([...new Set(missing)].join(", ") || "none"));
console.log("next: \"<node.exe>\" \"" + path.join(OUT, "runner.js") + "\" --workspace <ws> --temp <tmp> --mode workspace-write -- cmd.exe /c \"echo ok\"");
