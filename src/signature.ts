/**
 * Recognize the four environment failures this plugin explains, and refuse
 * everything else.
 *
 * ## The ACL provisioning failure (`acl-provisioning`)
 *
 * The harness's Windows sandbox provisions a workspace by writing the
 * directory's DACL and its mandatory-integrity label in **one**
 * `SetNamedSecurityInfoW` call (`packages/sandbox/sandbox-windows-acl/src/acl.ts`).
 * When that call is refused, the error a session actually sees is the bare
 * Win32 string — `SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\ws)` —
 * with no statement of which right was missing or what the caller can do about
 * it. Every sandboxed command then fails the same way, forever, because the
 * grant is materialized lazily and nothing is cached on the failure path.
 *
 * Recognizing the string is therefore the whole job of this half, and the
 * recognition is deliberately narrow:
 *
 * - **Only the two `...NamedSecurityInfoW` operations are classified.** Their
 *   failures are the provisioning path. `SetEntriesInAclW` merges entries in
 *   process memory (no object, no rights), and the `LocalFree` /
 *   `SetConsoleCtrlHandler` / `LockFileEx` failures in the same package are
 *   allocation or lock errors — advising an ACL fix for any of those would send
 *   a user to change the wrong thing. A classifier that names a wrong cause is
 *   worse than one that stays silent.
 * - **The Win32 code is kept, not flattened.** `ERROR_ACCESS_DENIED` (5) is the
 *   case the documented prerequisite explains; another code is a different
 *   story and the advisory says so instead of borrowing the same sentence.
 * - **The producer's detail is preserved verbatim** (`grantWrite(D:\ws)`), so
 *   the advisory can quote the exact line the model and the user are looking
 *   at, and the path can be re-used in the fix command.
 *
 * One signature covers three environments, the text is identical in all of them,
 * and the classifier cannot and must not try to tell them apart — but the
 * *remedy* is not the same in all of them, which is why the advisory forks on a
 * check the user runs rather than on a guess this module cannot make:
 *
 * - a workspace the caller created with `mkdir` that inherits "Authenticated
 *   Users: Modify" from the drive root (`#7622`, `#7646`, `#7720`);
 * - a directory on a data volume where **no ACE names the caller at all**, so
 *   the inherited entry is the whole of their access (`#7750` on D:/E:,
 *   `#7735`'s second defect);
 * - a directory **the caller does not own** — an installer- or
 *   administrator-created one, `#7771` (owner `BUILTIN\Administrators`, held
 *   deny-only for that token), which `#7804` reached from the other direction.
 *
 * In the first two the caller is the owner, so their implicit `WRITE_DAC`
 * satisfies the DACL half and `WRITE_OWNER` is the single missing right — one
 * unelevated `icacls /grant` supplies exactly it, and `#7750` measured that
 * remedy working. In the third `WRITE_DAC` is missing as well, so that same
 * `icacls` is refused for the very command that would fix it and `(WO)` alone
 * would not be enough even if it went through. The advisory therefore hands over
 * the ownership check (`(Get-Acl "<dir>").Owner`) as the branch selector and
 * gives each branch the command that works there — the same class, two rights
 * situations, and no guess about which one this is.
 *
 * What the text *does* carry that the failure does not is the version boundary:
 * the merged DACL + label write exists only from `0.1.7-alpha.1` on
 * (`packages/sandbox/sandbox-windows-acl/src/acl.ts`, flag
 * `DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION`), so on an older line
 * the same string belongs to a different cause space.
 *
 * ## The persistent-shell startup failure (`pty-startup`)
 *
 * `dsh-terminal-bash` throws `PTY shell exited during startup` when the shell
 * it spawned through the sandbox exits before reaching its first prompt
 * (`src/session.ts` and `src/index.ts`, both on the same `waitReason ===
 * 'session_exit'` branch). The text names no cause and, under the `minimal`
 * preset — whose only shell tool is a persistent PTY — there is no other shell
 * tool left to fall back on, so the model reads it as "the command failed" and
 * retries forever. #7638 is the report: 33 consecutive failures under
 * `workspace-write`, none under `danger-full-access`, with the reporter's own
 * three-arm control showing the sandbox mode is the discriminator.
 *
 * This family is recognized on an **exact line**, not on a substring, and that
 * is deliberate. The producer's message has no detail field at all — the whole
 * message is the sentence — so anything that merely *contains* the phrase is
 * quoting it (a transcript, a log a failing command printed, a pasted issue
 * body) rather than producing it. The sibling throw on the same branch, `PTY
 * shell did not reach readiness before startup timeout`, is **not** classified
 * here: it means the shell started and then did not reach a prompt, which is a
 * different cause space (a slow or blocked shell) with a different remedy, and
 * a classifier that names a wrong cause is worse than one that stays silent.
 *
 * ## The process that never started (`native-init`)
 *
 * The third family is not a message at all: it is a **structured exit code on a
 * result the pipeline calls a success**. Two reports of one code —
 * `STATUS_DLL_INIT_FAILED`, `0xC0000142`, seen as `-1073741502` in a tool result
 * because Windows exit codes are 32-bit NTSTATUS values and Node reports them
 * signed — describe a confined child that died while its native images were
 * initializing, i.e. before its entry point. `#7876` is the packaged desktop app:
 * `sandbox-local` starts the sandbox runner as `[process.execPath, entry]`, and
 * in that build `process.execPath` is the Electron executable, which starts as an
 * *app* unless `ELECTRON_RUN_AS_NODE=1` is in the child's environment — so the
 * runner itself never runs and every confined command reports this code with no
 * output at all. `#7877` is an MSYS2/Git-Bash program under the restricted
 * token: bash cannot create its own signal pipe (`couldn't create signal pipe,
 * Win32 error 5`) and aborts in the same place, while `cmd.exe` and `pwsh` run
 * fine under the identical mode.
 *
 * **This family is the only one that is invisible from the error path**, and that
 * is the whole reason it is classified from the canonical value instead of from
 * text. Upstream's runner-failure rules admit exactly one code —
 * `RUNNER_FAILURE_RULES['windows-acl'] = [{ allowedExitCodes: [127], fatalSignatures:
 * ['windows-acl-run: '] }]` (`packages/sandbox/sandbox-local/src/index.ts`) — and
 * `classifyRunnerFailure` skips any other code before it even looks at stderr
 * (`packages/sandbox/sandbox/src/diagnostics.ts`), so `0xC0000142` is never a
 * runner failure and `SandboxUnavailableError` is never thrown. The renderer then
 * reports it the way it reports any finished command — *"Non-zero exits are
 * reported, not errored … only infrastructure failures (spawn errors, aborts)
 * surface as isError results"* (`packages/shell/tool-pwsh/src/render.ts`) — as
 * `[exit code: …]`. A plugin reading only `isError` results (every version of
 * this one before `0.6.0`) is structurally blind to it, which is exactly why the
 * model retries a command that can never start.
 *
 * The read is `ToolExecutionSuccess.value` — the tool's own canonical output,
 * documented as *"Execution-local canonical value; deliberately omitted from
 * durable events"* (`packages/core/tools/src/index.ts`) — so the code arrives
 * structurally and no line of rendered text can be mistaken for it. Reading it
 * this way is what makes the recognition safe: a command that prints a line
 * saying `0xC0000142` is not this failure, and a call whose arguments merely
 * mention a Windows path is not either.
 *
 * Three narrowings, each of which is a thing that could otherwise make the
 * diagnosis wrong:
 *
 * - **The `foreground` discriminator is required.** The shipped shell tools
 *   project a finished foreground run as `{ kind: 'foreground', exitCode, … }`
 *   and a still-running background handle as a different shape (`tool-pwsh` /
 *   `tool-bash`, mirrored by design), so requiring it keeps a value some other
 *   tool happens to build with an `exitCode` field out of this family. A value
 *   without it is left alone — the fail-closed direction, since the cost of
 *   silence is one missing diagnosis and the cost of a wrong match is a confident
 *   wrong cause.
 * - **Only `STATUS_DLL_INIT_FAILED` is classified.** `0xC0000142` has producers
 *   this module does not know about (a program that simply cannot load its own
 *   DLLs, and the console-hiding that the sandbox backend's own source records as
 *   producing it), so the advisory enumerates the measured ones and says so
 *   rather than asserting one. The neighbouring statuses are deliberately **not**
 *   folded in: `0xC0000409` is the Cygwin/MSYS2 runtime's deliberate fast-fail
 *   (a different mechanism with a different story), and `0xC0000135` is a missing
 *   DLL (a packaging problem, not a sandbox one).
 * - **No platform gate.** The code is a Windows NTSTATUS: a POSIX process cannot
 *   exit with a value above 255, so the number itself is the platform evidence. A
 *   `process.platform === 'win32'` check would add nothing a session could
 *   observe and would make this family untestable on the host this plugin is
 *   built on — which is how a family ships without ever having been run.
 *
 * ## Denied inside the workspace (`workspace-denial`)
 *
 * The fourth family is the other half of the same backend the first one
 * explains. There the grant could not be applied at all and every command died
 * before it ran; here the grant *was* applied and the workspace looks
 * provisioned — and part of the tree still refuses writes. `#423` is the
 * report: under `workspace-write` on Windows, a command writing into a
 * subdirectory that was created or moved in from outside the session is denied,
 * forever, while the same command against a directory the harness itself
 * created succeeds.
 *
 * Like the native-init family, and for the same structural reason, this one is
 * **invisible from the error path**: a denied command exits nonzero, and the
 * shipped shell tools report a nonzero exit as a finished run rather than as
 * `isError`, so the fact arrives in `ToolExecutionSuccess.value`. Unlike that
 * family it does not need a bespoke code to be read — the shipped executors
 * *stamp the denial* onto the value, as a structured triple no line of rendered
 * text can fabricate:
 *
 *   `sandbox: { mode, denied: true, enforcement? }`
 *
 * (`packages/shell/bash-sandbox/src/index.ts` and `pwsh-sandbox`, both on
 * `classifyDenial`; projected into the tool result value by `tool-bash` /
 * `tool-pwsh`). `denied` is produced by matching the backend's own refusal
 * dialect in the *captured stderr* — `'access is denied'`, `'access to the
 * path'`, `'permission denied'`, `'operation not permitted'` for the
 * `windows-acl` backend — so the value is the harness's reading of its own
 * sandbox, not this plugin's reading of a message.
 *
 * **`denied` alone is not this family, and the narrowings are the whole
 * design.** A denial is the *sanctioned* outcome in three other situations, and
 * advising about a missing inherited grant in any of them would be the
 * confidently wrong cause this module exists to avoid:
 *
 * - **Outside the workspace.** `fs-sandbox` throws its marker only when a path
 *   falls outside the writable roots, and a confined shell denying a path
 *   outside the workspace is the designed escalation path — the denial surface
 *   offers one retry under a wider mode, and that offer is correct there.
 * - **Under `read-only`.** That mode denies *every* write by construction
 *   (`fs-sandbox`'s `checkedTarget`: `read-only` throws before any containment
 *   question is asked), so an in-workspace denial under it is the mode working.
 * - **A runner failure.** The executor refuses to call a run denied when the
 *   runner itself failed (`denied: !runnerFailed && …`), and a value that
 *   carries `runnerFailed: true` is left alone for the same reason.
 *
 * What is left is exactly the anomaly: **a denial under `workspace-write` of a
 * path inside the session's own workspace**, which is the one combination the
 * harness is supposed to make impossible. The mode comes off the value (the
 * executor stamped the mode it actually ran under, so no policy lookup can
 * disagree with it), and the containment test needs the workspace root, which
 * comes from the policy resolver at the call site —
 * {@link classifyWorkspaceDenial} takes it as a fact rather than reading it, so
 * the recognition stays a pure function of its inputs.
 *
 * **The in-workspace half of that test is keyed on the command's own text**, and
 * deliberately not on the stderr the denial was inferred from: the regex looks
 * for drive-qualified or UNC path literals in the call's `command` argument, and
 * the family is recognized only when **every** such literal it finds lies under
 * the workspace root. A command that names an outside path as well — an
 * interpreter shipped under `C:\Program Files`, an output directory on another
 * volume — is refused rather than guessed at, and so is a command that names
 * only relative paths: in both cases the plugin cannot say *which* path was
 * denied, and silence is the fail-closed direction. The paths it did key on are
 * carried into the advisory, so the reader can see the reasoning rather than
 * take it on faith.
 *
 * **The platform gate is real here, and unlike the native-init family it cannot
 * be dropped.** The mechanism is Windows ACE inheritance: the backend writes the
 * grant once, on the workspace root, and relies on the operating system to
 * propagate it to descendants, which needs `WRITE_DAC` on each descendant at
 * that moment. Every other backend applies its policy per call to the process
 * (landlock rules, a bwrap profile, a seatbelt profile) and has no descendant to
 * miss, so the same value on those hosts is a different story. `win32` is
 * therefore part of recognition, passed in rather than read, and the suite runs
 * this family with the platform fact supplied.
 *
 * @module
 */

/** Which provisioning operation failed, and which diagnosis follows from it. */
export type FailureClass =
  /**
   * `SetNamedSecurityInfoW` returned `ERROR_ACCESS_DENIED` (5): the merged
   * DACL + label write was refused. All three environments in the module doc
   * land here — the `mkdir`-inherited Modify workspace, the data-volume
   * directory with no ACE naming the caller, and the directory owned by another
   * account — because the failure text cannot separate them. The first two are
   * the same rights situation (the caller owns it; `WRITE_OWNER` is the whole of
   * what is missing) and share the unelevated remedy; the third is missing
   * `WRITE_DAC` as well, which is why the advisory hands over the ownership
   * check and forks the command on it.
   */
  | 'apply-denied'
  /** `SetNamedSecurityInfoW` failed with a Win32 code other than `ERROR_ACCESS_DENIED`. */
  | 'apply-other'
  /** `GetNamedSecurityInfoW` failed: the security descriptor could not even be read. */
  | 'read-denied'

/** The environment failure family a recognized failure belongs to. */
export type FailureFamily =
  /** The Windows sandbox could not provision its workspace (ACL / mandatory label). */
  | 'acl-provisioning'
  /** The persistent PTY shell could not start under a confining sandbox mode. */
  | 'pty-startup'
  /** A confined Windows child died while its native images were initializing. */
  | 'native-init'
  /** A confined command was denied a path inside its own workspace (Windows ACL). */
  | 'workspace-denial'

/** One recognized provisioning failure, with the producer's own fields kept. */
export interface ProvisioningFailure {
  /** Which family this failure belongs to. */
  readonly family: 'acl-provisioning'
  /** Which diagnosis follows from the api/code pair. */
  readonly klass: FailureClass
  /** The API whose checked result failed, exactly as the producer names it. */
  readonly api: string
  /** The Win32 error code as reported. */
  readonly win32Code: number
  /** The producer's detail, e.g. `grantWrite(D:\ws)`; empty when it supplied none. */
  readonly detail: string
  /** The detail's `label(...)` head, when it has that shape. */
  readonly label?: string
  /** The directory the detail names, when it has that shape. */
  readonly path?: string
}

/** The exact text `dsh-terminal-bash` throws when the shell exits during startup. */
export const PTY_STARTUP_EXIT = 'PTY shell exited during startup'

/**
 * The persistent-shell startup failure. It carries no producer fields: the
 * producer's entire message is {@link PTY_STARTUP_EXIT}, and what makes the
 * diagnosis actionable (the effective sandbox mode) comes from the policy
 * resolver at the call site rather than from the error text.
 */
export interface PtyStartupFailure {
  /** Which family this failure belongs to. */
  readonly family: 'pty-startup'
  /** The producer's message, kept as the constant so nothing can drift. */
  readonly line: string
}

/**
 * `STATUS_DLL_INIT_FAILED`, the code a Windows process is terminated with when
 * the loader fails while initializing it — before its entry point runs.
 *
 * Written unsigned here, which is how the NTSTATUS is named; a tool result
 * usually carries it as the 32-bit signed number (`-1073741502`), and
 * {@link classifyNativeInitDeath} accepts either because it compares the
 * normalized 32-bit pattern.
 */
export const STATUS_DLL_INIT_FAILED = 0xC0000142

/** The `kind` discriminator the shipped shell tools put on a finished foreground run. */
const FOREGROUND = 'foreground'

/**
 * The code a confined Windows child died with, and the forms the caller may have
 * to quote it in.
 *
 * There is no `path` and no `api` here: the producer of this failure is the
 * operating system's loader, which reports only the status. What the diagnosis
 * needs beyond the code — the effective sandbox mode — comes from the policy
 * resolver at the call site, exactly as it does for the PTY family.
 */
export interface NativeInitFailure {
  /** Which family this failure belongs to. */
  readonly family: 'native-init'
  /** The exit code exactly as the tool reported it, so it can be quoted back verbatim. */
  readonly rawExitCode: number
  /** The same code normalized to its unsigned 32-bit form, for comparison and printing. */
  readonly exitCode: number
}

/**
 * The mode in which a write **inside** the workspace is supposed to succeed.
 *
 * It is the only mode this family is recognized under, and that is a fact about
 * the other two rather than about this one: `read-only` denies every write by
 * construction, and `danger-full-access` spawns nothing through the sandbox at
 * all — so a denial under either is the mode doing its job, and the one place a
 * denial is an anomaly is here.
 */
export const DENIAL_MODE = 'workspace-write'

/**
 * The facts the workspace-denial recognition needs beyond the result value.
 *
 * Both are passed in rather than read here, for the reason the other families
 * state in their own words: a gate that trusts the shape of its input is the
 * gate that reports a cause from the wrong world. The type is also what keeps
 * the platform fact honest — the Android/Cygwin-style "`process.platform` is
 * win32" belief cannot be smuggled in as a default.
 */
export interface WorkspaceDenialFacts {
  /** The host's `process.platform`, as the caller read it. */
  readonly platform: string
  /** The session's workspace root, as the policy resolver reported it. */
  readonly workspaceRoot: string
}

/**
 * A confined command that was denied a path inside its own workspace.
 *
 * The producer fields are kept verbatim rather than paraphrased, so the advisory
 * can show the reader the exact facts the recognition keyed on — which matters
 * more here than anywhere else in this module, because the family's claim
 * ("this path is inside your workspace") is a statement about two strings.
 */
export interface WorkspaceDenialFailure {
  /** Which family this failure belongs to. */
  readonly family: 'workspace-denial'
  /** The mode the denied call ran under, as the executor stamped it on the value. */
  readonly mode: string
  /** The command's exit status, or `null` when the tool reported none. */
  readonly exitCode: number | null
  /** The in-workspace absolute paths the call named, in the order they appear. */
  readonly paths: readonly string[]
  /** The workspace root those paths were tested against, as it was given. */
  readonly workspaceRoot: string
}

/** Any failure this plugin recognizes, tagged by family. */
export type RecognizedFailure =
  | ProvisioningFailure
  | PtyStartupFailure
  | NativeInitFailure
  | WorkspaceDenialFailure

/**
 * The producer's format is fixed by `Win32Error`
 * (`packages/subprocess/win32-process/src/errors.ts`):
 * `` `${api} failed (Win32 ${code})${detail ? `: ${detail}` : ''}` ``.
 * The pattern is written against that shape, but it is anchored on the API
 * names rather than on surrounding text, so it survives the `Error: ` envelope
 * a tool result adds and any prefix a provider wraps around it.
 */
const SIGNATURE = /\b(SetNamedSecurityInfoW|GetNamedSecurityInfoW) failed \(Win32 (\d+)\)(?:: *([^\r\n]*))?/

/** `ERROR_ACCESS_DENIED`. */
const ACCESS_DENIED = 5

/** Split the producer's `label(path)` detail; any other shape yields nothing. */
function splitDetail(detail: string): { label?: string, path?: string } {
  const match = /^([A-Za-z][A-Za-z0-9_-]*)\((.*)\)$/.exec(detail.trim())
  if (match === null) return {}
  const label = match[1]
  const path = match[2]
  if (label === undefined || path === undefined) return {}
  return { label, path }
}

/**
 * Classify one failure message against the ACL family.
 * @param message - the failure text, from the result's `error.message` or its rendered content.
 * @returns the recognized failure, or undefined when this is not a provisioning failure.
 */
export function classifyProvisioningFailure(message: string): ProvisioningFailure | undefined {
  const match = SIGNATURE.exec(message)
  if (match === null) return undefined
  const api = match[1]
  const code = Number(match[2])
  if (api === undefined || !Number.isInteger(code)) return undefined
  const detail = (match[3] ?? '').trim()
  const klass: FailureClass = api === 'GetNamedSecurityInfoW'
    ? 'read-denied'
    : code === ACCESS_DENIED ? 'apply-denied' : 'apply-other'
  return { family: 'acl-provisioning', klass, api, win32Code: code, detail, ...splitDetail(detail) }
}

/**
 * Classify one failure message as the persistent-shell startup failure.
 *
 * Recognition is by **whole line**, because the producer's message is a bare
 * sentence with no fields of its own: a line equal to
 * {@link PTY_STARTUP_EXIT} — with only the `Error: ` envelope a tool result adds
 * in front of it — is the producer. A longer line that happens to contain the
 * sentence is something quoting it (a transcript, a log the failing command
 * printed, a pasted issue body), and advising about the sandbox there would be
 * advice about the wrong thing.
 * @param message - the failure text, from the result's `error.message` or its rendered content.
 * @returns the recognized failure, or undefined when this is not one.
 */
export function classifyPtyStartupFailure(message: string): PtyStartupFailure | undefined {
  for (const raw of message.split('\n')) {
    const line = raw.trim()
    if (line === PTY_STARTUP_EXIT || line === `Error: ${PTY_STARTUP_EXIT}`) {
      return { family: 'pty-startup', line: PTY_STARTUP_EXIT }
    }
  }
  return undefined
}

/**
 * Classify one **successful** execution's canonical value as a Windows native-init
 * death.
 *
 * This is the only family read from a result the pipeline calls a success, and
 * that is a fact about the producer rather than a choice: the code reaches the
 * tool result as an ordinary nonzero exit status (upstream's runner-failure rules
 * admit only exit `127` with the `windows-acl-run: ` signature, so this one is
 * never reclassified), and the renderer reports nonzero exits without erroring.
 * `ToolExecutionFailure` carries no value at all, so there is nothing to read on
 * the error path — a session sees this failure exactly when its shell tool
 * reports a command that "ran".
 *
 * Recognized structurally, never from text: the value must be the foreground
 * shell projection (`kind: 'foreground'`) with an integer `exitCode` whose 32-bit
 * pattern is {@link STATUS_DLL_INIT_FAILED}. A command's own output claiming the
 * code cannot reach this function, and neither can a value some other tool built
 * with an `exitCode` field.
 * @param value - the settled execution's canonical value (`ToolExecutionSuccess.value`).
 * @returns the recognized failure, or undefined when this is not one.
 */
export function classifyNativeInitDeath(value: unknown): NativeInitFailure | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const probe = value as { kind?: unknown, exitCode?: unknown }
  if (probe.kind !== FOREGROUND) return undefined
  const raw = probe.exitCode
  if (typeof raw !== 'number' || !Number.isInteger(raw)) return undefined
  // `>>> 0` maps the signed form Node reports on Windows onto the unsigned
  // NTSTATUS, and leaves a value that is already unsigned alone.
  const exitCode = raw >>> 0
  if (exitCode !== STATUS_DLL_INIT_FAILED) return undefined
  return { family: 'native-init', rawExitCode: raw, exitCode }
}

/**
 * The one-line failure the producer wrote, for quoting back verbatim.
 * @param failure - a recognized failure.
 * @returns the message text the producing layer would have produced.
 */
export function failureLine(failure: RecognizedFailure): string {
  if (failure.family === 'pty-startup') return failure.line
  if (failure.family === 'native-init') return `[exit code: ${String(failure.rawExitCode)}]`
  if (failure.family === 'workspace-denial') {
    const status = failure.exitCode === null ? '' : `[exit code: ${String(failure.exitCode)}] `
    return `${status}sandbox: { mode: "${failure.mode}", denied: true }`
  }
  const suffix = failure.detail.length === 0 ? '' : `: ${failure.detail}`
  return `${failure.api} failed (Win32 ${failure.win32Code})${suffix}`
}

/**
 * The drive-qualified and UNC path literals in one command line.
 *
 * Deliberately crude, in the direction that keeps the diagnosis honest. A
 * literal is taken to end at the first character a shell token cannot carry
 * unquoted, so a path containing a space is recovered as its first segment — a
 * **prefix** of the real path, which preserves the containment answer for every
 * path that lies under the root (a prefix of a descendant is still a descendant)
 * and refuses the test for paths whose root itself contains a space. A path that
 * appears twice is returned once.
 * @param command - the `command` argument of the failing shell call.
 * @returns the literals found, in order, without trailing separators.
 */
export function windowsPathsIn(command: string): string[] {
  const found: string[] = []
  for (const match of command.matchAll(/(?:[A-Za-z]:[\\/]|\\\\)[^\s"'`|<>;&,]*/g)) {
    const literal = match[0].replace(/[\\/]+$/, '')
    if (literal.length >= 3 && !found.includes(literal)) found.push(literal)
  }
  return found
}

/**
 * Whether one path lies at or under one root, the way Windows compares them.
 * @param root - the workspace root.
 * @param path - the candidate path.
 * @returns true when `path` is `root` itself or a descendant of it.
 */
export function isInsideWorkspace(root: string, path: string): boolean {
  const canon = (value: string): string => value.replaceAll('/', '\\').replace(/\\+$/, '').toLowerCase()
  const base = canon(root)
  const target = canon(path)
  if (base.length === 0 || target.length === 0) return false
  return target === base || target.startsWith(`${base}\\`)
}

/**
 * Whether one settled value carries the executors' workspace-denial stamp.
 *
 * The **structural half** of the fourth family's recognition, split out so that
 * "this is not a denial at all" (silent, and the overwhelming majority of
 * successful calls) stays distinguishable from "this is a denial and the plugin
 * could not finish placing it" — the case the disclosure rule requires the host
 * log to account for. It reads the value the executors wrote, never a line of
 * rendered text, and it is deliberately platform-blind: the platform gate is a
 * fact the classifier takes as an argument, and a stamp test that baked it in
 * could not be used to decide whether a missing platform fact is worth saying
 * out loud.
 *
 * What it does **not** decide is which path was denied — that needs the call's
 * arguments and the workspace root, and belongs to
 * {@link classifyWorkspaceDenial}. A stamp alone is the sanctioned outcome in
 * three other situations (outside the workspace, under `read-only`, a runner
 * failure); this function excludes the third by itself and leaves the first two
 * to the classifier, which is the only place they can be separated.
 * @param value - a settled execution's canonical value.
 * @returns true when the value is a foreground shell projection stamped
 *   `denied: true` under `workspace-write` with no runner failure.
 */
export function hasWorkspaceDenialStamp(value: unknown): boolean {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const probe = value as { kind?: unknown, sandbox?: unknown }
  if (probe.kind !== FOREGROUND) return false
  const sandbox = probe.sandbox
  if (sandbox === null || typeof sandbox !== 'object') return false
  const { mode, denied, runnerFailed } = sandbox as { mode?: unknown, denied?: unknown, runnerFailed?: unknown }
  return mode === DENIAL_MODE && denied === true && runnerFailed !== true
}

/**
 * Classify one **successful** execution's canonical value as a workspace-internal
 * denial, and recover the paths the call named.
 *
 * Four facts, in the order they narrow: the call ran on Windows (the mechanism
 * is ACE inheritance, which no other backend has); the value carries the
 * executor's denial stamp ({@link hasWorkspaceDenialStamp}); the call's
 * `command` argument carries at least one absolute Windows path literal; and
 * **all** of them lie under the workspace root. The last is the one that
 * separates this family from the sanctioned escalation path — a command naming
 * any path outside its own workspace is refused rather than guessed at, because
 * the plugin cannot say which path the sandbox refused.
 * @param value - the settled execution's canonical value (`ToolExecutionSuccess.value`).
 * @param args - the settled call's parsed arguments (`ToolExecution.arguments`).
 * @param facts - the host platform and the session's workspace root.
 * @returns the recognized failure, or undefined when this is not one.
 */
export function classifyWorkspaceDenial(
  value: unknown,
  args: unknown,
  facts: WorkspaceDenialFacts,
): WorkspaceDenialFailure | undefined {
  if (facts.platform !== 'win32') return undefined
  if (!hasWorkspaceDenialStamp(value)) return undefined
  const probe = value as { exitCode?: unknown }
  const command = (args as { command?: unknown } | null | undefined)?.command
  if (typeof command !== 'string') return undefined
  const named = windowsPathsIn(command)
  if (named.length === 0) return undefined
  if (!named.every(path => isInsideWorkspace(facts.workspaceRoot, path))) return undefined
  const exitCode = typeof probe.exitCode === 'number' && Number.isInteger(probe.exitCode) ? probe.exitCode : null
  return {
    family: 'workspace-denial',
    mode: DENIAL_MODE,
    exitCode,
    paths: named,
    workspaceRoot: facts.workspaceRoot,
  }
}
