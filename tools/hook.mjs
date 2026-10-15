// ---------------------------------------------------------------------------
// tools/hook.mjs — probes the two axes (restricting list vs default DACL) with one variable per arm.
//
// Author: Ethan-H1K, who offered these scripts in this repository's issue #1 and gave credit in the same thread.
// Origin: https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6172657585
// The body underneath this block is unedited. tools/README.md says what each arm is for
// and which number it reproduces; the count of packages the materialiser copies is printed
// by that script itself rather than written down anywhere.
// ---------------------------------------------------------------------------
// hook.mjs - probe the two axes (restricting list vs default DACL) with one variable per arm.
// Read-only is the useful setting for the DACL axis: its restricting list carries no capability SID,
// so a DACL fix can be read without the capability SID being available to pass-2.
export let variant = "baseline";
export function initialize(data) { if (data && data.variant) variant = data.variant; }

const DACL_ANCHOR = "setTokenDefaultDaclGrant(api, restrictedToken, this.tempWriteSidPtr ?? this.writeSidPtr ?? worldSid);";
const RESTRICT_ANCHOR = "createRestrictedToken(api, currentToken, logonSid, [this.writeSidPtr, this.tempWriteSidPtr].filter((sid) => sid !== void 0), { world: worldSid }, this.mode)";
const EVERYONE = 'setTokenDefaultDaclGrant(api, restrictedToken, worldSid);';

// A synthetic identity: not an enabled group of the token, not in the restricting list.
const PROBE_PTR = 'parseSid("S-1-4-4242-4242")';
// The capability SID the workspace-write path would name for this workspace (S-1-4-x-y), named here
// in a mode that does not carry it - the faithful mirror of the shipped DACL.
const WS_PTR = 'parseSid(workspaceWriteSid((() => { const i = process.argv.indexOf("--workspace"); return i >= 0 ? process.argv[i + 1] : ""; })()))';

const DACL_SYNTH = "setTokenDefaultDaclGrant(api, restrictedToken, " + PROBE_PTR + ");";
const DACL_WS = "setTokenDefaultDaclGrant(api, restrictedToken, " + WS_PTR + ");";
const RESTRICT_SYNTH = RESTRICT_ANCHOR.replace("[this.writeSidPtr, this.tempWriteSidPtr]", "[this.writeSidPtr, this.tempWriteSidPtr, " + PROBE_PTR + "]");

function patch(src) {
  switch (variant) {
    case "baseline": return src;
    case "dacl-everyone": return src.replace(DACL_ANCHOR, DACL_ANCHOR + "\n\t\t\t" + EVERYONE);
    case "dacl-synth": return src.replace(DACL_ANCHOR, DACL_SYNTH);
    case "dacl-wssid": return src.replace(DACL_ANCHOR, DACL_WS);
    case "dacl-wssid-everyone": return src.replace(DACL_ANCHOR, DACL_WS + "\n\t\t\t" + EVERYONE);
    case "rl-synth": return src.replace(RESTRICT_ANCHOR, RESTRICT_SYNTH);
    case "rl-synth-dacl-synth": return src.replace(RESTRICT_ANCHOR, RESTRICT_SYNTH).replace(DACL_ANCHOR, DACL_SYNTH);
    case "rl-synth-dacl-synth-everyone": return src.replace(RESTRICT_ANCHOR, RESTRICT_SYNTH).replace(DACL_ANCHOR, DACL_SYNTH + "\n\t\t\t" + EVERYONE);
    default: return src;
  }
}

export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  if (!url.includes("dsh-sandbox-windows-acl") || !url.endsWith(".js")) return result;
  const source = result.source ? Buffer.from(result.source).toString("utf8") : "";
  if (!source.includes(DACL_ANCHOR) || !source.includes(RESTRICT_ANCHOR)) return result;
  const patched = patch(source);
  return patched === source ? result : { ...result, source: patched, format: "module" };
}
