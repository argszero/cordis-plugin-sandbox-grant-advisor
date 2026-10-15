// ---------------------------------------------------------------------------
// tools/dump-dacl.mjs — prints the calling process token's Default DACL (TokenDefaultDacl) as SID + mask.
//
// Author: Ethan-H1K, who offered these scripts in this repository's issue #1 and gave credit in the same thread.
// Origin: https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6170010818
// The body underneath this block is unedited. tools/README.md says what each arm is for
// and which number it reproduces; the count of packages the materialiser copies is printed
// by that script itself rather than written down anywhere.
// ---------------------------------------------------------------------------
// dump-dacl.mjs - print the calling process token's Default DACL (TokenDefaultDacl, class 6).
//
//   "<DSH install>\DeepSeek Harness.exe" --expose-internals dump-dacl.mjs <label> [koffi file URL]
//
// To dump the token of a CONFINED child, run it as the sandboxed command. The runner may not pass
// ELECTRON_RUN_AS_NODE to the child, so wrap it (dump.cmd):
//
//   @echo off
//   set ELECTRON_RUN_AS_NODE=1
//   "<DSH install>\DeepSeek Harness.exe" --expose-internals "<path>\dump-dacl.mjs" %1
//
//   runner.js --workspace <ws> --temp <tmp> --mode read-only -- cmd.exe /c "<path>\dump.cmd" ro
//
// koffi is loaded from the install (derived from process.execPath); override with argv[1] or KOFFI_URL.
import path from "node:path";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const label = argv.find((a) => !a.startsWith("file:")) || "";
const fromArgv = argv.find((a) => a.startsWith("file:"));
const exeDir = path.dirname(process.execPath);
const koffiUrl = process.env.KOFFI_URL || fromArgv ||
  pathToFileURL(path.join(exeDir, "resources", "app.asar", "dsh", "node_modules", "koffi", "index.js")).href;

const { default: koffi } = await import(koffiUrl);
const k32 = koffi.load("kernel32.dll");
const adv = koffi.load("advapi32.dll");
const GetCurrentProcess = k32.func("void *GetCurrentProcess()");
const OpenProcessToken = adv.func("bool OpenProcessToken(void *h, uint32 access, _Out_ void **token)");
const GetTokenInformation = adv.func("bool GetTokenInformation(void *token, int cls, void *buf, uint32 len, _Out_ uint32 *needed)");

const ACL = koffi.struct("ACL", { AclRevision: "uint8", Sbz1: "uint8", AclSize: "uint16", AceCount: "uint16", Sbz2: "uint16" });
const ACEH = koffi.struct("ACE_HEADER", { AceType: "uint8", AceFlags: "uint8", AceSize: "uint16" });
const SID = koffi.struct("SID", { Revision: "uint8", SubAuthorityCount: "uint8", IdentifierAuthority: koffi.array("uint8", 6), SubAuthority: koffi.array("uint32", 15) });

function sidToString(s) {
  let auth = 0n;
  for (const b of s.IdentifierAuthority) auth = (auth << 8n) | BigInt(b);
  const subs = [];
  for (let i = 0; i < s.SubAuthorityCount; i++) subs.push(String(s.SubAuthority[i]));
  return "S-" + s.Revision + "-" + auth.toString() + (subs.length ? "-" + subs.join("-") : "");
}

const out = { label, aces: [] };
try {
  const holder = Buffer.alloc(8);
  if (!OpenProcessToken(GetCurrentProcess(), 0x0008 /* TOKEN_QUERY */, holder)) throw new Error("OpenProcessToken failed");
  const token = koffi.decode(holder, "void *");
  const need = Buffer.alloc(4);
  GetTokenInformation(token, 6 /* TokenDefaultDacl */, null, 0, need);
  const size = need.readUInt32LE(0);
  const buf = Buffer.alloc(size);
  if (!GetTokenInformation(token, 6, buf, size, need)) throw new Error("GetTokenInformation failed");
  const aclAddr = koffi.decode(buf, "void *");
  const acl = koffi.decode(aclAddr, ACL);
  let off = 8n;
  for (let i = 0; i < acl.AceCount; i++) {
    const h = koffi.decode(aclAddr + off, ACEH);
    const mask = koffi.decode(aclAddr + off + 4n, "uint32");
    const sid = koffi.decode(aclAddr + off + 8n, SID);
    out.aces.push({ type: h.AceType, mask: "0x" + mask.toString(16).toUpperCase().padStart(8, "0"), sid: sidToString(sid) });
    off += BigInt(h.AceSize);
  }
} catch (error) {
  out.error = String(error);
}
console.log("DACLDUMP " + JSON.stringify(out, null, 1));
