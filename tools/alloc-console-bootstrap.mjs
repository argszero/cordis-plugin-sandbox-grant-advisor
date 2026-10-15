// ---------------------------------------------------------------------------
// tools/alloc-console-bootstrap.mjs — loads the shipped runner in this process, optionally allocating a console first and/or registering the hook.
//
// Author: Ethan-H1K, who offered these scripts in this repository's issue #1 and gave credit in the same thread.
// Origin: https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6170010818
// The body underneath this block is unedited. tools/README.md says what each arm is for
// and which number it reproduces; the count of packages the materialiser copies is printed
// by that script itself rather than written down anywhere.
// ---------------------------------------------------------------------------
// alloc-console-bootstrap.mjs - loads the real windows-acl runner in THIS process, optionally
//   (a) allocating a console first            (SBX_ALLOCCONSOLE=1), and
//   (b) registering the default-DACL hook     (SBXVAR=both|replace).
//
// Usage:
//   set SBXRUNNER=file:///<DSH install>/resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-sandbox-windows-acl/lib/runner.js
//   set SBX_ALLOCCONSOLE=1
//   set SBXVAR=both
//   "<DSH install>\DeepSeek Harness.exe" --expose-internals alloc-console-bootstrap.mjs --workspace <ws> --temp <tmp> --mode workspace-write -- cmd.exe /c "echo ok"
//
// Note: the packaged desktop mediator is a GUI-subsystem executable and has no console; a plain
// console-subsystem node.exe has one already, which is the other mediator arm.
import { register } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const exeDir = path.dirname(process.execPath);
const koffiUrl = process.env.SBX_KOFFI ||
  pathToFileURL(path.join(exeDir, "resources", "app.asar", "dsh", "node_modules", "koffi", "index.js")).href;

if (process.env.SBX_ALLOCCONSOLE === "1") {
  const koffi = (await import(koffiUrl)).default;
  const k32 = koffi.load("kernel32.dll");
  const AllocConsole = k32.func("bool AllocConsole()");
  process.stderr.write("allocconsole=" + AllocConsole() + "\n");
}

const runner = process.env.SBXRUNNER;
if (!runner) {
  process.stderr.write("SBXRUNNER is required: file URL of .../dsh-sandbox-windows-acl/lib/runner.js\n");
  process.exit(2);
}
if (process.env.SBXVAR) {
  register(new URL("./dacl-patch-hook.mjs", import.meta.url), { data: { variant: process.env.SBXVAR } });
}
await import(runner);
