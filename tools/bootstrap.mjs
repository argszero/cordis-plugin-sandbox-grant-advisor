// ---------------------------------------------------------------------------
// tools/bootstrap.mjs — loads the shipped runner with the two-axis probe hook registered.
//
// Author: Ethan-H1K, who offered these scripts in this repository's issue #1 and gave credit in the same thread.
// Origin: https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6172657585
// The body underneath this block is unedited. tools/README.md says what each arm is for
// and which number it reproduces; the count of packages the materialiser copies is printed
// by that script itself rather than written down anywhere.
// ---------------------------------------------------------------------------
// bootstrap.mjs - load the shipped windows-acl runner with the probe hook registered.
//   SBXRUNNER  file URL of .../dsh-sandbox-windows-acl/lib/runner.js
//   SBXVAR     arm name (see hook.mjs)
import { register } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const exeDir = path.dirname(process.execPath);
const koffiUrl = process.env.SBX_KOFFI ||
  pathToFileURL(path.join(exeDir, "resources", "app.asar", "dsh", "node_modules", "koffi", "index.js")).href;

if (process.env.SBX_ALLOCCONSOLE === '1') {
  const koffi = (await import(koffiUrl)).default;
  const k32 = koffi.load('kernel32.dll');
  process.stderr.write('allocconsole=' + k32.func('bool AllocConsole()')() + '\n');
}

const runner = process.env.SBXRUNNER;
if (!runner) { process.stderr.write("SBXRUNNER required\n"); process.exit(2); }
register(new URL("./hook.mjs", import.meta.url), { data: { variant: process.env.SBXVAR || "baseline" } });
await import(runner);
