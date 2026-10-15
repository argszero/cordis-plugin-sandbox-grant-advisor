// ---------------------------------------------------------------------------
// tools/hook.mjs — probes the two axes (restricting list vs default DACL) with one variable per arm.
//
// Author: Ethan-H1K, who offered these scripts in this repository's issue #1 and gave credit in the same thread.
// Origin: https://github.com/argszero/cordis-plugin-sandbox-grant-advisor/issues/1#issuecomment-6196102774
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
const CALL_SITE_SIDS = "[this.writeSidPtr, this.tempWriteSidPtr].filter((sid) => sid !== void 0)";
const GUARD = "writeSids.length === 0 ? (() => {";
const PARSE = (s) => "parseSid(\"" + s + "\")";
const WW_LIST = "[\n\t\tlogonSid,\n\t\tknown.world,\n\t\t...writeSids\n\t]";
const WW_NO_LOGON = "[\n\t\tknown.world,\n\t\t...writeSids\n\t]";
const wwWith = (sid) => "[\n\t\tlogonSid,\n\t\tknown.world,\n\t\t" + PARSE(sid) + ",\n\t\t...writeSids\n\t]";
const WW_NO_WORLD = "[\n\t\tlogonSid,\n\t\t...writeSids\n\t]";
const RESTRICT_SYNTH = RESTRICT_ANCHOR.replace("[this.writeSidPtr, this.tempWriteSidPtr]", "[this.writeSidPtr, this.tempWriteSidPtr, " + PROBE_PTR + "]");

function must(out, before) {
  if (out === before) throw new Error("probe hook: anchor not found for variant " + variant);
  return out;
}

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
    case "nosids": return src.replace(CALL_SITE_SIDS, "[]").replace(GUARD, "false ? (() => {");
    case "noli": return src.replace("restrictTokenIntegrity(api, restrictedToken, lowLabelSid);", "void lowLabelSid;");
    case "dacl-interactive": return must(src.replace(DACL_ANCHOR, "setTokenDefaultDaclGrant(api, restrictedToken, " + PARSE("S-1-5-4") + ");"), src);
    case "dacl-authusers": return must(src.replace(DACL_ANCHOR, "setTokenDefaultDaclGrant(api, restrictedToken, " + PARSE("S-1-5-11") + ");"), src);
    case "dacl-admins": return must(src.replace(DACL_ANCHOR, "setTokenDefaultDaclGrant(api, restrictedToken, " + PARSE("S-1-5-32-544") + ");"), src);
    case "everyone-no-logon": return must(must(src.replace(DACL_ANCHOR, DACL_ANCHOR + "\n\t\t\t" + EVERYONE), src).replace(WW_LIST, WW_NO_LOGON), src);
    case "everyone-no-world": return must(must(src.replace(DACL_ANCHOR, DACL_ANCHOR + "\n\t\t\t" + EVERYONE), src).replace(WW_LIST, WW_NO_WORLD), src);
    case "rl-named-interactive": return must(must(src.replace(DACL_ANCHOR, "setTokenDefaultDaclGrant(api, restrictedToken, " + PARSE("S-1-5-4") + ");"), src).replace(CALL_SITE_SIDS, "[this.writeSidPtr, this.tempWriteSidPtr, " + PARSE("S-1-5-4") + "]"), src);
    case "rl-named-authusers": return must(must(src.replace(DACL_ANCHOR, "setTokenDefaultDaclGrant(api, restrictedToken, " + PARSE("S-1-5-11") + ");"), src).replace(CALL_SITE_SIDS, "[this.writeSidPtr, this.tempWriteSidPtr, " + PARSE("S-1-5-11") + "]"), src);
    case "rl-named-synth": return must(must(src.replace(DACL_ANCHOR, DACL_SYNTH), src).replace(CALL_SITE_SIDS, "[this.writeSidPtr, this.tempWriteSidPtr, " + PARSE("S-1-4-4242-4242") + "]"), src);
    case "rl-named-interactive-no-world": return must(must(must(src.replace(DACL_ANCHOR, "setTokenDefaultDaclGrant(api, restrictedToken, " + PARSE("S-1-5-4") + ");"), src).replace(CALL_SITE_SIDS, "[this.writeSidPtr, this.tempWriteSidPtr, " + PARSE("S-1-5-4") + "]"), src).replace(WW_LIST, WW_NO_WORLD), src);
    case "rl-named-admins": return must(must(src.replace(DACL_ANCHOR, "setTokenDefaultDaclGrant(api, restrictedToken, " + PARSE("S-1-5-32-544") + ");"), src).replace(CALL_SITE_SIDS, "[this.writeSidPtr, this.tempWriteSidPtr, " + PARSE("S-1-5-32-544") + "]"), src);
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
