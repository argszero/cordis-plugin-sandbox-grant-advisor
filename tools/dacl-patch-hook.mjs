// ---------------------------------------------------------------------------
// tools/dacl-patch-hook.mjs — the module-loading hook that rewrites the ONE default-DACL grant in the shipped runner.
//
// Author: Ethan-H1K, who offered these scripts in this repository's issue #1 and gave credit in the same thread.
// Origin: https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6170010818
// The body underneath this block is unedited. tools/README.md says what each arm is for
// and which number it reproduces; the count of packages the materialiser copies is printed
// by that script itself rather than written down anywhere.
// ---------------------------------------------------------------------------
// dacl-patch-hook.mjs - a Node module-loading hook that rewrites the ONE default-DACL grant in
// @deepseek-ai/dsh-sandbox-windows-acl (AclSandbox.init) and changes nothing else.
//
//   variant "both"    : keep the shipped call and ADD a second grant naming Everyone
//                       (capability ACE stays + Everyone; the decisive arm - the ACE can stay)
//   variant "replace" : name Everyone INSTEAD of the capability SID
//
// Register it from a bootstrap (see alloc-console-bootstrap.mjs), which is the reliable entry point:
//   register(new URL("./dacl-patch-hook.mjs", import.meta.url), { data: { variant: "both" } });
export let variant = "both";

export function initialize(data) {
  if (data && data.variant) variant = data.variant;
}

const ANCHOR = "setTokenDefaultDaclGrant(api, restrictedToken, this.tempWriteSidPtr ?? this.writeSidPtr ?? worldSid);";
const MIRROR = "setTokenDefaultDaclGrant(api, restrictedToken, worldSid);";

export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  if (!url.includes("dsh-sandbox-windows-acl") || !url.endsWith(".js")) return result;
  const source = result.source ? Buffer.from(result.source).toString("utf8") : "";
  if (!source.includes(ANCHOR)) return result;
  const patched = variant === "replace"
    ? source.replace(ANCHOR, MIRROR)
    : source.replace(ANCHOR, ANCHOR + "\n\t\t\t" + MIRROR);
  return { ...result, source: patched, format: "module" };
}
