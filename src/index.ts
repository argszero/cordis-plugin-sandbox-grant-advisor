/**
 * `sandbox-grant-advisor`: turn an environment failure that has no path forward
 * into a diagnosis the model — and the user reading the transcript — can act on.
 *
 * ## The five failures it recognizes
 *
 * **Workspace provisioning (Windows ACL).** Four reports of one signature
 * (`#7538`, `#7622`, `#7646`, `#7720`) describe the same shape: the host-side write grant
 * for a sandboxed workspace cannot be applied, every sandboxed command then
 * fails identically **before it runs**, and the error text is a bare Win32 line:
 *
 *   SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\ws)
 *
 * The grant is materialized lazily on the first confined call and nothing is
 * cached when it throws, so the failure repeats per command rather than once
 * (850 calls / 39 sessions in `#7622`; 52,588 output tokens with no output in
 * `#7538`). The remedy the backend documents — the directory must grant the
 * caller `WRITE_OWNER` — never reaches the user, so sessions escape into
 * `danger-full-access` or die on the model's output cap.
 *
 * `#7720` sharpens where this lands: because the grant is materialized at
 * sandbox *initialization*, that failure takes **every** shell tool with it, not
 * one operation — the reporter could not run `netstat` or `icacls` to diagnose
 * the failure they were looking at. It also contributes the two remedies that
 * look right and are not (`takeown /R /D Y`, `icacls /reset /T /C`), which the
 * ACL advisory now names along with the reason each fails.
 *
 * **Persistent shell startup (#7638).** With the `minimal` preset on Windows the
 * only shell tool is a persistent PTY (`dsh-terminal-bash` +
 * `dsh-tool-pwsh-persistent`), and under a *confining* sandbox mode every call
 * fails instantly with
 *
 *   PTY shell exited during startup
 *
 * — the backend cannot create the pseudo-console inside the sandbox, so the
 * child exits before its first prompt. Retrying never helps, the message points
 * at no cause, and because `minimal` mounts no fallback shell tool the session
 * has no command execution left at all. The reporter's own three-arm control
 * makes the sandbox mode the discriminator: minimal × confining fails, minimal ×
 * `danger-full-access` succeeds, `standard` (one-shot shell) × confining
 * succeeds.
 *
 * **A confined child that never started (native init, `#7876` + `#7877`, plus
 * `#8990` / `#8991` / `#9186`).** The third family is not a message at all: one
 * exit code — `0xC0000142` `STATUS_DLL_INIT_FAILED` — describing a child that died
 * while the loader was initializing its native images, before its entry point,
 * with three measured producers behind it. In `#7877` it is an MSYS2/Git-Bash
 * program: under the restricted token bash cannot create its own signal pipe
 * (`couldn't create signal pipe, Win32 error 5`), so it dies in the same phase,
 * while `cmd.exe` and `pwsh` run fine under the identical mode. For `#8193` and
 * `#8208` it is the sandbox runner's own **console**: the confined child inherits
 * one from the runner, a restricted token may inherit a console but not create
 * one, so a runner that owns none — a GUI-subsystem image, or a real `node.exe`
 * spawned with `DETACHED_PROCESS` — leaves the child to ask for one of its own.
 * `#9186` isolated the third to a single input by driving the sandbox API with the
 * DACLs untouched: a capability SID in the token's own restricting list — added
 * only under `workspace-write` — kills every program, `whoami.exe` and `cmd.exe`
 * included, while the `read-only` list starts them normally. Retrying is the one
 * thing that cannot work, and the code tells the model nothing on its own: the
 * same value is also produced by a token built **without** the logon-SID +
 * EVERYONE keep-alive pair, so it cannot name its own direction.
 *
 * This family is read from the **canonical value of a successful result**, which
 * is why the seam below now inspects both outcomes. The producer never marks it
 * an error: upstream's runner-failure rules admit only exit `127` with the
 * `windows-acl-run: ` signature (`packages/sandbox/sandbox-local/src/index.ts`),
 * `classifyRunnerFailure` skips every other code before it looks at stderr
 * (`packages/sandbox/sandbox/src/diagnostics.ts`), and the renderer reports a
 * nonzero exit as `[exit code: N]` rather than as `isError`
 * (`packages/shell/tool-pwsh/src/render.ts`). Every version of this plugin
 * before `0.6.0` read error results only and was structurally blind to it. See
 * `src/signature.ts` for why the read is `ToolExecutionSuccess.value` — the
 * tool's own canonical output, never a line of rendered text — and which three
 * narrowings keep the recognition from firing on something else.
 *
 * **Denied inside the workspace (Windows ACL, `#423`).** The fourth family is
 * the other half of the backend the first one explains, and it is the first
 * whose remedy is withheld on purpose. There the grant could not be applied at
 * all; here it *was* applied — on the workspace root, once — and Windows ACE
 * inheritance silently skipped objects whose DACL the caller could not write.
 * The backend's provisioning check short-circuits on the root (`hasExactGrant`
 * returns early once the root carries the ACE, `sandbox-windows-acl/src/acl.ts`),
 * so those descendants are never revisited and the same command fails forever,
 * while a directory the harness itself created works. It arrives at the same
 * seam as the native-init family and for the same structural reason: a denied
 * command exits nonzero and the shipped shell tools report that as a finished
 * run, so the fact is in `ToolExecutionSuccess.value` rather than in an error.
 * Unlike that family it needs no bespoke code — the executors stamp the denial
 * onto the value as a structured triple (`sandbox: { mode, denied, enforcement? }`,
 * produced by matching the backend's own refusal dialect in the captured
 * stderr), so this plugin reads the harness's own reading of its own sandbox.
 * See `src/signature.ts` for the facts that narrow it, and in particular for
 * why a denial is the *designed* outcome in three other situations (outside the
 * workspace, under `read-only`, a runner failure) and must never be advised.
 *
 * **The private temp root inside the workspace (`temp-root-inside-workspace`,
 * `#9175`).** The fifth family is the only one that takes **every** command with
 * it — `echo test` included, with no subprocess output at all, while the file
 * tools keep working — and it is not a failure of anything the session asked for:
 * `workspace-write` materializes a private, revocable temp capability under a
 * random child of `os.tmpdir()`, and the backend refuses to do so when that temp
 * root lies inside the workspace carrying the standing grant. The refusal is the
 * backend's own capability-disjointness assertion
 * (`sandbox-windows-acl/src/path-boundary.ts`), thrown by **two producers** that
 * this plugin distinguishes: the session-scoped provider, while it assembles the
 * runner argv (no child ever existed, which is why the call shows no output), and
 * the windows-acl runner, before it spawns (stderr behind `windows-acl-run: `,
 * exit 127, reclassified by the seam into a `SandboxUnavailableError`). Both are
 * read from `result.error.message`, since both *throw* — a command that prints
 * the sentence finishes as a run and cannot reach this family.
 *
 * This family is also the only one that is diagnosed **twice, by design**. A
 * session in that state has no shell left, so discovering the condition from the
 * first failed command is already late; the plugin therefore reports it
 * *pre-flight*, once per agent, on the first tracked call — before anything has
 * failed — and again beside the refusal itself if it happens. The pre-flight half
 * is the only prediction in this plugin, so it states the three facts it computed
 * (host, mode, both directories) and the one step that falsifies it. See
 * `src/temp-root.ts` for why that computation is a re-implementation of the
 * backend's rule rather than an import.
 *
 * ## Where it acts, and why there
 *
 * One listener on the public `tools/post-execute` waterfall
 * (`@deepseek-ai/dsh-tools`). Admissibility was decided by which half of the
 * defect this seam can reach: the failure text (the provider propagates its
 * error unchanged, and the tool pipeline turns it into an `isError` result) or,
 * for the native-init family, the canonical value a successful result carries,
 * an agent identity to attribute it to (`exec.agent`), and a channel that speaks
 * to the model in the same step (`PostToolDecision`'s `additionalContexts`,
 * a durable user-role message).
 *
 * `ctx.sandbox.confine(argv, policy, signal)` sees the confinement failure too,
 * and cannot do this: its signature carries no agent, so a wrapper could detect
 * the condition and never deliver a word about it to the session that is stuck.
 *
 * The PTY family needs one fact the failure text does not carry — the effective
 * sandbox mode — and takes it from `ctx.sandboxPolicy.resolve({ session })`:
 * the same resolver the terminal layer calls before spawning, with the same
 * session. See `src/mode.ts` for why that lookup is guarded rather than
 * imported, and what happens when it cannot answer.
 *
 * ## What it does
 *
 * 1. **One durable advisory per agent, per family.** On the first recognized
 *    failure of a family, the failing tool result is enriched with a user-role
 *    notice. For the ACL family it names the missing right (`WRITE_OWNER` on the
 *    directory, not `SeSecurityPrivilege`), gives the unelevated one-line
 *    `icacls` remedy, gives the discriminator that separates a Modify-only
 *    directory from a wrong prerequisite, and names the two remedies that look
 *    right and are not (`takeown`, `icacls /reset`), each with its reason. For the PTY family it names the
 *    combination that fails (persistent PTY × a confining mode), states the
 *    resolved mode, says plainly that no command can fix it, and hands the
 *    user-side preset choice over. For the native-init family it states the
 *    resolved mode, says the process never reached its entry point, enumerates
 *    the three producers measured under a confining mode with the check that
 *    separates them (what program the reader ran; whether this host is the
 *    packaged desktop binary, which the plugin **measures and reports** rather
 *    than assumes), and carries the one conversion a model can actually make —
 *    rewrite the work as PowerShell or `cmd` when the program that could not
 *    start was an MSYS2 one. For the workspace-denial family it prints the path
 *    it keyed on beside the root it tested it against, says that retrying is
 *    provably useless (the root-only provisioning check never revisits the
 *    object), gives the two-sided reachability rule, names the label variant of
 *    the same shape, and prints **no** repair command — the obvious one is
 *    refused by Windows with `ERROR_NONE_MAPPED (1332)`, and this project has no
 *    Windows host to verify a line on. For the temp-root family it is the family
 *    whose remedy **nothing inside the session can carry out** — the refusal took
 *    command execution away — so it quotes both directories the producer printed,
 *    names which of the two carriers refused, and hands the environment change
 *    (`%TMP%` / `%TEMP%`, or a workspace that does not contain the temp root) to
 *    the user, with no grant command anywhere in it: nothing was denied, so there
 *    is nothing to grant. All five ride `additionalContexts`, so the
 *    model sees the diagnosis beside the failure rather than only in a log it
 *    never reads.
 * 2. **A bounded fail-fast, ACL family only.** With `enforceAfter` set, a call
 *    this plugin has *watched fail* this way is refused at `tools/pre-execute`
 *    once the environment has failed at least that many times. It is off by
 *    default: the useful signal here is the diagnosis, and a plugin that blocks
 *    command execution for a reason it merely recognizes is a risk, not a
 *    feature. See the README for why the blocking half is deliberately narrow
 *    and why it does not cover the two mode-gated families.
 * 3. **A disclosure when it withholds.** The PTY and native-init advisories are
 *    only sent when the resolved mode actually confines; if the mode is not
 *    confining, or cannot be
 *    resolved at all, the failure is left exactly as it was **and the host log
 *    says so once**. The workspace-denial advisory is withheld the same way when
 *    the workspace root — the fact the containment claim is tested against —
 *    cannot be resolved. Silence alone would make "the sandbox is not the cause" and
 *    "this plugin could not tell" indistinguishable from the outside. A denial
 *    the classifier *can* place outside the workspace is a different case and is
 *    left silent on purpose: that is the sanctioned escalation path, not a
 *    puzzle, and a note about it would be noise.
 * 4. **A pre-flight report of the one standing condition, temp-root family
 *    only.** That family's condition exists *before* it fails, so the plugin
 *    answers it once, on the first tracked call of a Windows agent, from the
 *    public `ctx.sandboxPolicy.resolve({ session })` — the same resolver the
 *    enforcing providers are handed. A session whose workspace contains the temp
 *    root under `workspace-write` is told so before its first command instead of
 *    after it, which matters here more than anywhere else because the failure
 *    removes the only thing that could have investigated it. The verdict is
 *    memoized per agent (`clear` as well as `reported`), so a host outside the
 *    condition pays for the lookup once and never again; a Windows host where it
 *    cannot be made at all says so on the host log rather than passing as clear.
 *
 * ## Honest boundaries
 *
 * - **The Windows path cannot be witnessed on macOS**, where this plugin was
 *   built and tested. What is tested is the decision layer: classification,
 *   once-per-agent-per-family delivery, the sandbox-mode gate and its
 *   fail-closed behaviour, the fail-fast budget, and the wiring to the real
 *   `ToolRuntime` — against synthetic results carrying the producers' exact
 *   error shapes, with the formats taken from
 *   `packages/subprocess/win32-process/src/errors.ts` and
 *   `packages/terminal/terminal-bash/src/{index,session}.ts`. The native-init
 *   family is exercised the same way and needs no Windows to be faithful, because
 *   what it reads is a number in a JSON value: the test builds the shipped shell
 *   tools' own foreground projection with the reported codes, including the
 *   signed form the reporter saw (`-1073741502`) and the real MSYS2 stderr, so the
 *   recognition runs against the producer's data rather than against a message
 *   this plugin invented. The workspace-denial family is exercised the same way:
 *   the test builds the executors' own `sandbox` stamp and the shipped foreground
 *   projection, supplies `win32` as the platform fact, and covers both the
 *   recognized case and each of the narrowings that must stay silent. The
 *   temp-root family needs no Windows either, and needs even less invention than
 *   the others: what it recognizes is a sentence one line long, and the
 *   pre-flight half is exercised by pointing the policy stand-in at a root that
 *   really does contain the host's own `os.tmpdir()` — so the containment the
 *   advice claims is computed by the same function the backend uses, on real
 *   paths, rather than asserted.
 * - **It does not repair anything.** No ACL is written, no privilege is
 *   requested, nothing is elevated, no environment variable is set for another
 *   process, no preset is installed and no mode is changed: the remedies are the
 *   user's (or, for the one in-session conversion, the model's own rewrite).
 * - **It complements, rather than replaces, `repeat-guard-escalation`.** That
 *   guard keys on *call identity* (identical arguments retried); this one keys
 *   on the *environment signature*, which is how several different commands can
 *   share one cause. They can be mounted together.
 * - **The real fix is upstream**, in all five families: the ACL failure should
 *   name
 *   the outstanding condition at the site that knows it (`grantWrite` computes
 *   `hasExactGrant`/`hasExactDeny`/`hasExactLabel` and discards which was
 *   false), the PTY startup path should either report "this sandbox mode is
 *   incompatible with the PTY backend" or fall back to a one-shot shell, and the
 *   sandbox runner should be launched with the environment its own execution
 *   needs (`ELECTRON_RUN_AS_NODE` when argv[0] is an Electron binary) or with a
 *   documented, checkable refusal for MSYS2 programs. The workspace-denial family
 *   is the same shape once more: `grantWrite` returns early when the *root*
 *   already carries the ACE, so the descendants that missed the propagation are
 *   never repaired — the check would have to look past the root, or the denial
 *   surface would have to say *which* path was refused instead of only that one
 *   was. The temp-root family is the one whose assertion is already exact and
 *   already names both operands: what it does not name is the **lever**, so the
 *   fix there is at the reporting end — say which of the two paths the user can
 *   move (they are not equally movable: the workspace is often the one they
 *   chose, while the temp root is `GetTempPathW`'s answer) and how. This plugin
 *   is the stopgap.
 *
 * @module @argszero/cordis-plugin-sandbox-grant-advisor
 */

import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { boundContextSummary, createUserMessage } from '@deepseek-ai/dsh-llm'
import type { UserMessage } from '@deepseek-ai/dsh-llm'
import type { PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { tmpdir } from 'node:os'
import { advisoryText, ACL_DISCUSSIONS, denialText, DISCUSSIONS_OF, NATIVE_INIT_DISCUSSIONS, PTY_DISCUSSIONS, TEMP_ROOT_DISCUSSIONS, tempRootPreflightAdvisory, WORKSPACE_DENIAL_DISCUSSIONS } from './advice.js'
import type { AdvisoryContext } from './advice.js'
import {
  classifyNativeInitDeath,
  classifyProvisioningFailure,
  classifyPtyStartupFailure,
  classifyTempRootRefusal,
  classifyWorkspaceDenial,
  hasWorkspaceDenialStamp,
} from './signature.js'
import type {
  FailureFamily,
  NativeInitFailure,
  ProvisioningFailure,
  PtyStartupFailure,
  RecognizedFailure,
  TempRootFailure,
  WorkspaceDenialFailure,
} from './signature.js'
import { confines, resolveSandboxMode, resolveWorkspaceRoot } from './mode.js'
import type { SandboxModeName } from './mode.js'
import {
  advisedOf,
  callKey,
  observe,
  observeSuccess,
  recordAdvice,
  recordDenial,
  recordStanding,
  recordWithheld,
  shouldDeny,
  standingOf,
} from './state.js'
import type { AgentState } from './state.js'
import { tempRootInsideWorkspace } from './temp-root.js'

export const name = 'sandbox-grant-advisor'

/** The tool pipeline this plugin observes and (optionally) gates. */
export const inject = ['tools']

/**
 * The producer kind every message this plugin writes carries.
 *
 * It is deliberately its own kind rather than the retired `plugin` wrapper: the
 * current session format admits only a producer-owned kind — a message whose
 * `source.kind` is the string `plugin` is refused on the way in
 * (`packages/session/session-format-v3-to-v4/src/message-sources.ts`) — and the
 * source union is documented as merge-extensible, one kind per producer.
 */
export const SOURCE_KIND = 'sandbox-grant-advisor'

/** Default fail-fast threshold: 0, i.e. the blocking half is off. */
export const DEFAULT_ENFORCE_AFTER = 0

/** Default denial budget once the blocking half is enabled. */
export const DEFAULT_MAX_DENIALS = 2

/**
 * The family the optional blocking half applies to.
 *
 * The ACL remedy is a command the user can run while the session continues; the
 * PTY remedy is a preset swap between sessions and the native-init remedy is a
 * user-side launch fix (or a rewrite the model makes itself), so refusing calls
 * is only useful in the first case — see `denialText` in `src/advice.ts`.
 */
export const ENFORCED_FAMILY = 'acl-provisioning'

/** Configures what is watched and whether the blocking half runs. */
export interface Config {
  /**
   * ACL provisioning failures after which an identical, already-failing call is
   * denied before dispatch. `0` (the default) disables the half entirely; the
   * advisory half is unaffected and always on. The blocking half applies to the
   * ACL family alone: it does not cover the persistent-shell or native-init
   * families, whose remedies are not a command the session can wait out.
   */
  enforceAfter?: number
  /**
   * How many denials one agent may spend. Defaults to 2. Bounded on purpose:
   * an unbounded refusal turns a stuck session into an unfinishable one.
   */
  maxDenials?: number
  /** Tool-name wildcard patterns to watch; empty means every tool. */
  include?: string[]
  /** Tool-name wildcard patterns never watched. */
  exclude?: string[]
  /** URL quoted in the advisory as the upstream thread; optional. */
  href?: string
}

/** Compile one `*`-wildcard pattern to an anchored RegExp; all else is literal. */
function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[|\\{}()[\]^$+?.]/g, String.raw`\$&`)
  return new RegExp(`^${escaped.replaceAll('*', '.*')}$`)
}

/**
 * Validate a count-like option fail-loud, so a typo cannot silently disable the
 * blocking half the operator asked for.
 * @param label - the option name, for the message.
 * @param value - the resolved value.
 * @param minimum - the smallest legal value.
 * @returns the value, once validated.
 */
function integerAtLeast(label: string, value: number | undefined, minimum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum) {
    throw new Error(`sandbox-grant-advisor: \`${label}\` must be an integer >= ${minimum} (got ${String(value)})`)
  }
  return value as number
}

/**
 * The plain text of a failed result, from the authoritative field first.
 *
 * `error.message` is what the producing layer recorded and survives content
 * rewriting by other post-execute listeners; the rendered text is the fallback,
 * so a result whose content was replaced (spill policies, hooks) is still
 * classified from its message.
 * @param result - the failed tool result.
 * @returns the text to classify.
 */
function failureText(result: Extract<ToolExecutionResult, { isError: true }>): string {
  const rendered = result.content
    .filter(block => block.type === 'text')
    .map(block => block.text)
    .join('\n')
  return result.error.message.length > 0 ? `${result.error.message}\n${rendered}` : rendered
}

/**
 * The one-line host-side account of a recognized ACL failure.
 * @param failure - the recognized failure.
 * @returns a single log line.
 */
function aclHostLine(failure: ProvisioningFailure): string {
  const where = failure.detail.length === 0 ? '' : ` at ${failure.detail}`
  return `sandbox-grant-advisor: workspace ACL provisioning failed (${failure.api} Win32 `
    + `${String(failure.win32Code)})${where} — sandboxed commands will keep failing until the directory grants `
    + `this account Full control; advisory delivered to the model (discussions ${ACL_DISCUSSIONS})`
}

/**
 * The one-line host-side account of a recognized persistent-shell failure.
 * @param mode - the resolved sandbox mode the failing call ran under.
 * @returns a single log line.
 */
function ptyHostLine(mode: SandboxModeName): string {
  return `sandbox-grant-advisor: persistent shell exited during startup under sandbox mode `
    + `"${mode}" — a PTY backend cannot start under a confining mode, and retrying cannot help; advisory `
    + `delivered to the model (discussion ${PTY_DISCUSSIONS})`
}

/**
 * The one-line host-side account of a recognized native-init death.
 *
 * It names the two things a maintainer needs to place the report — the code and
 * the mode the call ran under — and deliberately not a cause: the code alone
 * cannot say which producer it was, and a log line that guesses is the same
 * defect as an advisory that guesses.
 * @param failure - the recognized failure.
 * @param mode - the resolved sandbox mode the failing call ran under.
 * @returns a single log line.
 */
function nativeInitHostLine(failure: NativeInitFailure, mode: SandboxModeName): string {
  return `sandbox-grant-advisor: sandboxed command reported exit ${String(failure.rawExitCode)} `
    + `(0x${failure.exitCode.toString(16).toUpperCase()} STATUS_DLL_INIT_FAILED) under sandbox mode "${mode}" — the child died before `
    + `its entry point, so retrying cannot help; advisory delivered to the model (discussions ${NATIVE_INIT_DISCUSSIONS})`
}

/**
 * The one-line host-side account of a refused temp root.
 *
 * It carries both directories and the carrier, and deliberately no verdict about
 * which of them a user should move: the plugin cannot know whether the workspace
 * or the temp root is the one they chose, and the advisory hands the choice over
 * rather than making it here.
 * @param failure - the recognized failure.
 * @returns a single log line.
 */
function tempRootHostLine(failure: TempRootFailure): string {
  const carrier = failure.carrier === 'runner' ? 'the windows-acl runner' : 'the session-scoped provider'
  return `sandbox-grant-advisor: ${carrier} refused to start a sandboxed command because its private temp `
    + `root ${failure.tempRoot} lies inside the workspace ${failure.workspaceRoot} — a capability-disjointness `
    + `invariant, so no permission grant applies and retrying cannot help; advisory delivered to the model `
    + `(discussion ${TEMP_ROOT_DISCUSSIONS})`
}

/**
 * The one-line host-side account of the standing condition, delivered pre-flight.
 * @param workspaceRoot - the root the policy resolver reported.
 * @param tempRoot - the temp root the executor would use.
 * @returns a single log line.
 */
function tempRootPreflightHostLine(workspaceRoot: string, tempRoot: string): string {
  return `sandbox-grant-advisor: this session's workspace ${workspaceRoot} contains the sandbox's temp root `
    + `${tempRoot} under sandbox mode "workspace-write" — the ACL runner will refuse every command before it `
    + `spawns, so the condition is reported before the first one fails; pre-flight advisory delivered to the `
    + `model (discussion ${TEMP_ROOT_DISCUSSIONS})`
}

/**
 * Wrap one notice as a user-role message.
 *
 * The double cast encodes a documented fact the installed type cannot express:
 * the message source union is **merge-extensible** — "each producer declares its
 * own `kind` in its own module; there is no shared catch-all `plugin` kind", and
 * "consumers fall through unknown kinds" — while the union shipped in the peer
 * package is a closed list written before this producer existed. A plugin cannot
 * augment an interface it does not own, and the session format admits any
 * non-empty kind except the retired `plugin` wrapper
 * (`packages/session/session-format-v3-to-v4/src/message-sources.ts`), which is
 * asserted by `test/plugin.spec.mjs` against the message this function returns.
 * @param text - the notice body.
 * @param summary - one-line account for the transcript row.
 * @returns the message, identified and frozen by the harness factory.
 */
function notice(text: string, summary: string): UserMessage {
  return createUserMessage({
    content: [{ type: 'text', text }],
    source: {
      kind: SOURCE_KIND,
      form: 'notice',
      summary: boundContextSummary(summary),
    } as unknown as UserMessage['source'],
  })
}

/** Keep this plugin's notices ahead of any other context on the same result. */
function prepend(ours: UserMessage, theirs: readonly UserMessage[] | undefined): UserMessage[] {
  return [ours, ...theirs ?? []]
}

/** The one-line transcript summary for a recognized failure. */
function summaryOf(failure: RecognizedFailure, mode?: SandboxModeName): string {
  if (failure.family === 'pty-startup') {
    return `persistent shell exited during startup under sandbox mode "${String(mode)}"`
  }
  if (failure.family === 'native-init') {
    return `sandboxed command never started (exit ${String(failure.rawExitCode)}, STATUS_DLL_INIT_FAILED) `
      + `under sandbox mode "${String(mode)}"`
  }
  if (failure.family === 'workspace-denial') {
    const subject = failure.paths[0] ?? 'a path in the workspace'
    return `denied inside the workspace (${subject}) under sandbox mode "${failure.mode}"`
  }
  if (failure.family === 'temp-root-inside-workspace') {
    const carrier = failure.carrier === 'runner' ? 'the runner' : 'the provider'
    return `sandbox temp root lies inside the workspace — refused by ${carrier}`
  }
  return `workspace ACL provisioning failed (Win32 ${String(failure.win32Code)})`
}

/**
 * The outcome of the standing temp-root check.
 *
 * Three answers rather than a boolean, because two of the three "no" cases are
 * different facts and only the caller knows where they have to go: `clear` is a
 * decision that this session is not in the condition, and `unknown` is the
 * plugin being unable to decide at all. Folding them together would make "the
 * sandbox is fine" and "this plugin could not tell" read the same from the
 * outside — the disclosure rule this plugin keeps for every other family.
 */
type StandingCheck =
  /** The session is in the condition: its workspace contains the sandbox's temp root. */
  | { readonly ok: true, readonly workspaceRoot: string, readonly tempRoot: string }
  /** Decided, and the session is not in the condition. */
  | { readonly ok: false, readonly why: 'clear' }
  /** Not decidable on this host, and why. */
  | { readonly ok: false, readonly why: 'unknown', readonly detail: string }

/**
 * Decide whether one agent's session is already in the temp-root condition.
 *
 * The platform gate comes first, so a session on a host the rule cannot apply to
 * never pays for the policy lookup — the invariant belongs to the Windows ACL
 * backend's two capabilities, and every other backend has no such pair. After
 * that it is the same request the enforcing providers are handed, and the same
 * fail-closed posture `src/mode.ts` documents: a mode or a root that cannot be
 * resolved is *not* an invitation to assume the deployment default, because a
 * session that overrode its mode would then be reported as confined.
 *
 * A path that does not resolve makes {@link tempRootInsideWorkspace} answer
 * "no violation", which is the fail-closed direction here for the same reason it
 * is there: the prediction can only ever stay silent.
 * @param ctx - the plugin's context.
 * @param agent - the agent whose session is being placed.
 * @returns the violation, a decided clear, or the reason nothing could be decided.
 */
function standingCondition(ctx: Context, agent: Agent): StandingCheck {
  if (process.platform !== 'win32') return { ok: false, why: 'clear' }
  const mode = resolveSandboxMode(ctx, agent)
  if (!mode.ok) return { ok: false, why: 'unknown', detail: mode.withheld }
  const root = resolveWorkspaceRoot(ctx, agent)
  if (!root.ok) return { ok: false, why: 'unknown', detail: root.withheld }
  const tempRoot = tmpdir()
  if (!tempRootInsideWorkspace({
    platform: process.platform,
    mode: mode.mode,
    workspaceRoot: root.workspaceRoot,
    tempRoot,
  })) {
    return { ok: false, why: 'clear' }
  }
  return { ok: true, workspaceRoot: root.workspaceRoot, tempRoot }
}

/**
 * Install the advisor.
 * @param ctx - context carrying the tool pipeline.
 * @param config - resolved options; validated fail-loud here.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const enforceAfter = integerAtLeast('enforceAfter', config.enforceAfter ?? DEFAULT_ENFORCE_AFTER, 0)
  const maxDenials = integerAtLeast('maxDenials', config.maxDenials ?? DEFAULT_MAX_DENIALS, 1)
  const includePatterns = (config.include ?? []).map(wildcardToRegExp)
  const excludePatterns = (config.exclude ?? []).map(wildcardToRegExp)
  const href = config.href

  /** One state per agent; a WeakMap keeps a finished agent's state collectable. */
  const states = new WeakMap<Agent, AgentState>()

  /**
   * The executions this plugin denied, so the post-execute listener never reads
   * its own denial as an environment failure. A denial's text quotes the Win32
   * line on purpose (that is what the model must see), which makes it
   * indistinguishable from the real thing by content alone — the identity of
   * the execution object, shared by reference across both seams, is what
   * separates them.
   */
  const ownDenials = new WeakSet<object>()

  /** Whether a tool participates; untracked calls are transparent. */
  function tracked(toolName: string): boolean {
    if (includePatterns.length > 0 && !includePatterns.some(pattern => pattern.test(toolName))) return false
    return !excludePatterns.some(pattern => pattern.test(toolName))
  }

  /**
   * Leave a recognized failure exactly as it is, and say so once on the host.
   *
   * Withholding is a decision, not an absence: the transcript shows a bare error
   * either way, so the difference between "this is not the sandbox's doing" and
   * "this plugin could not tell" has to be recorded where a maintainer reads it.
   * Once per agent, because a loop can produce dozens of these. The cited thread
   * is the *family's* — a withheld native-init death and a withheld PTY startup
   * failure are different reports, and pointing a maintainer at the wrong one
   * would be its own small misdiagnosis.
   * @param agent - the agent whose failure was withheld.
   * @param state - the agent's state, to keep the note to one.
   * @param why - what stopped the advisory.
   * @param family - the recognized family that was withheld. Only families whose
   *   gate can fail closed reach this function, so the thread it cites is exact.
   * @returns undefined, so callers can `return withhold(...)`.
   */
  function withhold(
    agent: Agent,
    state: AgentState | undefined,
    why: string,
    family: FailureFamily,
  ): undefined {
    if (state?.withheld === true) return undefined
    states.set(agent, recordWithheld(state))
    const discussions = DISCUSSIONS_OF[family]
    ctx.logger.warn(
      `sandbox-grant-advisor: ${family} failure recognized but no advisory sent — ${why}; the raw `
      + `error is left exactly as it is, so this is NOT a claim that the sandbox is unrelated (discussions ${discussions})`,
    )
    return undefined
  }

  /**
   * Read one settled call: advance the state, and decide what the model must be
   * told — the failure it just hit, or the standing condition this session is
   * already in.
   *
   * The order is not arbitrary. A call that really is one of the five failures
   * carries the producer's own line, which the pre-flight report cannot have, so
   * the failures are asked first and the standing check speaks only on a call
   * that produced no diagnosis at all. In a session the standing condition is
   * true of, that is the first tool call of any kind — including a file read,
   * because this family is not discovered by running a command: it is a
   * relationship between two directories, and by the time a command could show
   * it there is no command left to run.
   * @param exec - the call that just ran.
   * @param result - its settled outcome.
   * @returns the notice to attach, or undefined.
   */
  function inspect(exec: ToolExecution, result: ToolExecutionResult): UserMessage | undefined {
    const agent = exec.agent
    if (agent === undefined || !tracked(exec.name)) return undefined
    if (ownDenials.has(exec)) {
      ownDenials.delete(exec)
      return undefined
    }
    const key = callKey(exec.name, exec.arguments)
    const previous = states.get(agent)
    return inspectOutcome(agent, previous, exec, result, key) ?? inspectStanding(agent)
  }

  /**
   * Classify one settled call against the five failure families.
   *
   * Everything here is driven by the settled result, and every branch that
   * recognizes one of them claims the family's once-per-agent advisory for this
   * agent before returning.
   * @param agent - the agent whose call ran.
   * @param previous - the agent's state before this call, if any.
   * @param exec - the call that just ran.
   * @param result - its settled outcome.
   * @param key - the identity of the call.
   * @returns the notice to attach, or undefined.
   */
  function inspectOutcome(
    agent: Agent,
    previous: AgentState | undefined,
    exec: ToolExecution,
    result: ToolExecutionResult,
    key: string,
  ): UserMessage | undefined {
    if (result.isError !== true) {
      // A result the pipeline calls a success is not automatically a working
      // environment: the native-init death arrives exactly here, as the
      // canonical value of a command that "finished" with a loader status. It is
      // read from `result.value` and never from the rendered text, so a command
      // whose own output mentions the code cannot be mistaken for it.
      const death = classifyNativeInitDeath(result.value)
      if (death !== undefined) return adviseGated(agent, previous, death, key, exec.name)
      // The workspace-denial family is the other value-read one, and it is read
      // only when the host is Windows: the mechanism it explains is ACE
      // inheritance, which no other backend has, so on macOS/Linux the same
      // stamp is a different story and is left alone with no note at all (that
      // is the designed denial path there, not a puzzle). The platform test
      // comes first so a non-Windows host never pays for the policy lookup.
      if (process.platform === 'win32' && hasWorkspaceDenialStamp(result.value)) {
        return adviseWorkspaceDenial(agent, previous, result.value, exec.arguments, key, exec.name)
      }
      if (previous !== undefined) states.set(agent, observeSuccess(previous, key))
      return undefined
    }
    // Three text families read two different fields, on purpose. The ACL
    // signature carries an API name plus a Win32 code, which a command's own
    // output does not fabricate, so that family may read the merged text
    // (`error.message` with the rendered content as its fallback). The
    // persistent-shell signature is a bare sentence, and the temp-root signature
    // is a sentence with two operands — and for both of those the rendered
    // content is exactly where a runner-failure path could carry a command's own
    // output, so those two read `error.message` alone, the field the layer that
    // threw them filled in. A sentence quoted from a log must never make this
    // plugin tell a working session that its shell is dead, or that its sandbox
    // cannot start.
    //
    // Honest about the limit: with the current `dsh-tools` runtime the rendered
    // content of an error result is derived from `error.message`, so today the
    // reads agree and the choice is not observable from outside — an injection
    // arm that swaps in the merged text leaves the suite green, and that is
    // recorded rather than papered over. The narrower read is kept because the
    // agreement is the runtime's rendering choice, not a promise this plugin can
    // rely on: a tool whose `render` produces output of its own is exactly the
    // case the narrower rule exists for.
    const failure = classifyProvisioningFailure(failureText(result))
      ?? classifyPtyStartupFailure(result.error.message)
      ?? classifyTempRootRefusal(result.error.message)
    if (failure === undefined) return undefined
    if (failure.family === 'pty-startup') return adviseGated(agent, previous, failure, key, exec.name)
    if (failure.family === 'temp-root-inside-workspace') {
      // No gate and no policy lookup here, unlike the two mode-gated families:
      // the producer's sentence carries both operands, and the mode is a fact of
      // the producer's own call site — the assertion exists only on the
      // `workspace-write` path, so a refusal cannot come from another mode.
      if (!claimAdvice(agent, previous, failure, key)) return undefined
      ctx.logger.warn(tempRootHostLine(failure))
      return notice(advisoryText(failure, advisoryContext(exec.name)), summaryOf(failure))
    }

    if (!claimAdvice(agent, previous, failure, key)) return undefined
    ctx.logger.warn(aclHostLine(failure))
    return notice(advisoryText(failure, advisoryContext(exec.name)), summaryOf(failure))
  }

  /**
   * Report the standing temp-root condition once per agent, ahead of any failure.
   *
   * This is the plugin's only prediction, and three things about it are chosen
   * rather than convenient. It is asked **once per agent** and the verdict is
   * memoized either way, so a host that is clear of the condition pays for one
   * resolution and never again — the alternative, re-asking on every tracked
   * call, would put a policy lookup in the path of every Windows tool call to
   * answer a question whose answer cannot change within a session. It is asked
   * only when nothing above recognized a failure, so it never displaces the
   * producer's own line. And when a **Windows** host cannot answer at all — no
   * policy service, no session, a resolver that throws — that is said on the
   * host log rather than passed off as clear: silence there would read the same
   * as "this session is fine", which is the disclosure rule this plugin keeps
   * everywhere, and on no other host does the question arise.
   * @param agent - the agent whose call just settled.
   * @returns the pre-flight notice, or undefined.
   */
  function inspectStanding(agent: Agent): UserMessage | undefined {
    if (standingOf(states.get(agent)) !== 'pending') return undefined
    const check = standingCondition(ctx, agent)
    states.set(agent, recordStanding(states.get(agent), check.ok ? 'reported' : 'clear'))
    if (!check.ok) {
      if (check.why === 'unknown') {
        ctx.logger.warn(
          'sandbox-grant-advisor: the standing temp-root condition could not be checked — '
          + `${check.detail}; nothing was reported, and this is NOT a claim that the session is clear of it `
          + `(discussion ${TEMP_ROOT_DISCUSSIONS})`,
        )
      }
      return undefined
    }
    ctx.logger.warn(tempRootPreflightHostLine(check.workspaceRoot, check.tempRoot))
    return notice(
      tempRootPreflightAdvisory(check.workspaceRoot, check.tempRoot, href),
      'sandbox temp root lies inside the workspace — commands will be refused',
    )
  }

  /**
   * Diagnose one recognized failure of a **mode-gated** family.
   *
   * Both families the plugin gates on the sandbox mode — the persistent shell
   * and the native-init death — need the same three decisions before anything is
   * said, and they need them in the same order, so they share one implementation
   * rather than one each: the effective mode is resolved from the agent's own
   * session, a mode that does not confine withholds the advisory (the harness
   * does not spawn commands through the sandbox there, so this is not these
   * families' story), and a mode that cannot be resolved withholds it too rather
   * than falling back to a guess. In both withholding cases the failure is left
   * untouched and the host log accounts for the silence once.
   * @param agent - the agent whose call failed.
   * @param previous - the agent's state before this call, if any.
   * @param failure - the recognized failure, already known to be a gated family.
   * @param key - the identity of the failing call.
   * @param tool - the failing tool's name, for the advisory context.
   * @returns the notice to attach, or undefined.
   */
  function adviseGated(
    agent: Agent,
    previous: AgentState | undefined,
    failure: PtyStartupFailure | NativeInitFailure,
    key: string,
    tool: string,
  ): UserMessage | undefined {
    const resolution = resolveSandboxMode(ctx, agent)
    if (!resolution.ok) return withhold(agent, previous, resolution.withheld, failure.family)
    const mode = resolution.mode
    if (!confines(mode)) {
      const what = failure.family === 'pty-startup' ? 'the shell' : 'the command'
      return withhold(agent, previous, `the failing call ran under \`${mode}\`, where ${what} is not spawned `
        + 'through the sandbox', failure.family)
    }
    if (!claimAdvice(agent, previous, failure, key)) return undefined
    ctx.logger.warn(failure.family === 'pty-startup' ? ptyHostLine(mode) : nativeInitHostLine(failure, mode))
    return notice(advisoryText(failure, advisoryContext(tool, mode)), summaryOf(failure, mode))
  }

  /**
   * Record one recognized failure and claim the once-per-agent advisory for its
   * family.
   * @param agent - the agent whose call failed.
   * @param previous - the agent's state before this call, if any.
   * @param failure - the recognized failure.
   * @param key - the identity of the failing call.
   * @returns true when this call is the one that must carry the diagnosis.
   */
  function claimAdvice(
    agent: Agent,
    previous: AgentState | undefined,
    failure: RecognizedFailure,
    key: string,
  ): boolean {
    const advanced = observe(previous, failure.family, failure, key)
    const first = !advisedOf(advanced, failure.family)
    states.set(agent, first ? recordAdvice(advanced, failure.family) : advanced)
    return first
  }

  /**
   * Diagnose one denial whose target lies **inside** the agent's own workspace.
   *
   * The fourth family reads the executor's structured stamp rather than a
   * message, so what is left here is the one fact the stamp cannot carry: the
   * workspace root, which the containment claim has to be tested against. It is
   * resolved from the agent's own session (the same resolver the enforcing
   * providers are handed), and a root that cannot be resolved withholds the
   * advisory rather than guessing — but only after the stamp has been seen, so
   * an ordinary successful call costs no note. Once the root is known the
   * classifier decides; a value that is a denial but names no in-workspace path
   * is the designed escalation path and is left silent on purpose, which is why
   * the `undefined` from the classifier is *not* routed through `withhold`.
   * @param agent - the agent whose call was denied.
   * @param previous - the agent's state before this call, if any.
   * @param value - the settled call's canonical value.
   * @param args - the settled call's parsed arguments.
   * @param key - the identity of the denied call.
   * @param tool - the denied tool's name, for the advisory context.
   * @returns the notice to attach, or undefined.
   */
  function adviseWorkspaceDenial(
    agent: Agent,
    previous: AgentState | undefined,
    value: unknown,
    args: unknown,
    key: string,
    tool: string,
  ): UserMessage | undefined {
    const resolution = resolveWorkspaceRoot(ctx, agent)
    if (!resolution.ok) return withhold(agent, previous, resolution.withheld, 'workspace-denial')
    const failure = classifyWorkspaceDenial(value, args, {
      platform: process.platform,
      workspaceRoot: resolution.workspaceRoot,
    })
    if (failure === undefined) return undefined
    if (!claimAdvice(agent, previous, failure, key)) return undefined
    ctx.logger.warn(workspaceDenialHostLine(failure))
    return notice(advisoryText(failure, advisoryContext(tool)), summaryOf(failure))
  }

  /**
   * The one-line host-side account of a recognized workspace-internal denial.
   *
   * It carries the path the plugin keyed on, because this family's whole claim
   * is that one named path lies inside one named root — a maintainer reading the
   * log is entitled to see both halves of the string comparison rather than a
   * verdict about it.
   * @param failure - the recognized failure.
   * @returns a single log line.
   */
  function workspaceDenialHostLine(failure: WorkspaceDenialFailure): string {
    const subject = failure.paths[0] ?? '<no path recovered>'
    const more = failure.paths.length > 1 ? ` (+${String(failure.paths.length - 1)} more inside the same root)` : ''
    return `sandbox-grant-advisor: confined command denied ${subject}${more}, which is INSIDE the workspace `
      + `${failure.workspaceRoot}, under sandbox mode "${failure.mode}" — the root-only grant skipped this object and `
      + `is never revisited, so retrying cannot help; advisory delivered to the model (discussion ${WORKSPACE_DENIAL_DISCUSSIONS})`
  }

  /**
   * The advisory context for one failing call.
   *
   * Built here rather than at each call site so the optional fields are only
   * present when they are known — `exactOptionalPropertyTypes` would otherwise
   * accept an explicit `undefined` that the consumer would have to un-learn.
   * @param tool - the failing tool's name.
   * @param mode - the resolved sandbox mode, for the family that needs it.
   * @returns the context to pass to `advisoryText`.
   */
  function advisoryContext(tool: string, mode?: SandboxModeName): AdvisoryContext {
    return {
      ...href === undefined ? {} : { href },
      tool,
      ...mode === undefined ? {} : { mode },
    }
  }

  // Observe-and-enrich, never veto by itself: delegate first, then fold this
  // plugin's notice onto whatever came back. `additionalContexts` rides both
  // decision variants, so a result another listener blocked still carries the
  // diagnosis.
  ctx.on('tools/post-execute', async (exec, result, next): Promise<PostToolDecision> => {
    let message: UserMessage | undefined
    try {
      message = inspect(exec, result)
    } catch (error: unknown) {
      // A broken advisor must not become a broken tool call.
      ctx.logger.warn(`sandbox-grant-advisor: result left alone after internal error: ${String(error)}`)
    }
    const downstream = await next()
    if (message === undefined) return downstream
    if (downstream.kind === 'block') {
      return {
        kind: 'block',
        feedback: downstream.feedback,
        additionalContexts: prepend(message, downstream.additionalContexts),
      }
    }
    return { ...downstream, additionalContexts: prepend(message, downstream.additionalContexts) }
  })

  // The optional blocking half. Registered only when asked for: with the default
  // `enforceAfter: 0` this plugin never sits in a waterfall it can veto from.
  if (enforceAfter === 0) return

  ctx.on('tools/pre-execute', (exec, next): Promise<PreToolDecision> => {
    try {
      const agent = exec.agent
      if (agent === undefined || !tracked(exec.name)) return next()
      const state = states.get(agent)
      const key = callKey(exec.name, exec.arguments)
      if (!shouldDeny(state, ENFORCED_FAMILY, key, enforceAfter, maxDenials)) return next()
      if (state === undefined) return next()
      const record = state.families[ENFORCED_FAMILY]
      if (record === undefined) return next()
      // `denialText` speaks the ACL family's language (the `icacls` line), so the
      // record is asked to be that family's before it is used: the family tag on
      // a record and the key it is stored under are not the same fact, and this
      // is the one place where confusing them would put the wrong remedy in
      // front of the model.
      const failure = record.last
      if (failure.family !== 'acl-provisioning') return next()
      // Tag before delegating, and spend the budget immediately: the denial must
      // be accounted for even if a later listener replaces this decision.
      ownDenials.add(exec)
      states.set(agent, recordDenial(state, ENFORCED_FAMILY))
      return Promise.resolve({
        kind: 'deny',
        reason: denialText(failure, record.observations, record.denials + 1, maxDenials),
      })
    } catch (error: unknown) {
      ctx.logger.warn(`sandbox-grant-advisor: call allowed after internal error: ${String(error)}`)
      return next()
    }
  })
}
