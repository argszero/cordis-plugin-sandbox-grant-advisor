/**
 * `sandbox-grant-advisor`: turn an environment failure that has no path forward
 * into a diagnosis the model — and the user reading the transcript — can act on.
 *
 * ## The seven failures it recognizes
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
 * EVERYONE keep-alive pair, so it cannot name its own direction. `0.18.0` adds the
 * axis that comparison misses and the second candidate behind it: `#9336` filed the
 * case where a console-less host separates the modes exactly as the restricting
 * list does — every interpreter dying under `workspace-write` and starting under
 * `read-only` from the desktop's chain, while the same argv passes in both modes
 * from a console-bearing one — so the check runs in two steps and `#9238`'s
 * console-topology matrix is what supplies the second; and the token's **default
 * DACL** is named as the second candidate the report raised, with the asymmetry that
 * makes it one (`workspace-write` is the only mode whose default DACL names a
 * synthetic SID) and the reason it must not be deleted to test it. `0.23.0` promotes
 * that candidate: `#8497` filed it and this repository's issue #1 measured it by rewriting
 * only the SID the merge names, and
 * the arm that names the capability SID AND `Everyone` together recovers — so the
 * input is a property of the merged ACE's trustee rather than the presence of a
 * synthetic one. `0.24.0` then narrows that to what the same reporter measured next,
 * a **conjunction of three** — the named SID must be an enabled group of the token,
 * must also be carried in the restricting list, and the list must still carry the
 * logon SID and `Everyone` — and **withdraws** the restricting-list rule the plugin
 * announced in `0.20.0`, whose own reporter retracted it before the publish. It is
 * bounded by the console as a *conjunction* (either recovers alone) and by the build
 * axis left open. The same report isolates
 * producer 2 one input narrower by varying only the image the runner is hosted by —
 * the packaged Electron binary against a real `node.exe` — and names the line where
 * that image is chosen: `[process.execPath, runner.js]`, whose docstring and test
 * both assert the interpreter is `node`, which the packaged build is the one form to
 * falsify.
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
 * **Denied inside the workspace (Windows ACL, `#423`; the breadth of its second
 * branch widened in `#9559`).** The fourth family is
 * the other half of the backend the first one explains, and it is the first
 * whose remedy is withheld on purpose. There the grant could not be applied at
 * all; here it *was* applied — on the workspace root, once — and Windows ACE
 * inheritance silently skipped objects whose DACL the caller could not write.
 * The backend's provisioning check short-circuits on the root (`hasExactGrant`
 * returns early once the root carries the ACE, `sandbox-windows-acl/src/acl.ts`),
 * so those descendants are never revisited and the same command fails forever,
 * while a directory the harness itself created works. `#9559` measured the widest
 * form of that skip on a pre-existing project tree: a child holding **neither**
 * half of the write — no capability ACE and no label — with the root itself still
 * writable, so the two breadths the advisory forks on are not the whole answer and
 * one `icacls` read of a child has to finish the placement. It arrives at the same
 * seam as the native-init family and for the same structural reason: a denied
 * command exits nonzero and the shipped shell tools report that as a finished
 * run, so the fact is in `ToolExecutionSuccess.value` rather than in an error.
 * Unlike that family it needs no bespoke code — the executors stamp the denial
 * onto the value as a structured triple (`sandbox: { mode, denied, enforcement? }`,
 * produced by matching the backend's own refusal dialect in the captured
 * stderr), so this plugin reads the harness's own reading of its own sandbox.
 * See `src/signature.ts` for the facts that narrow it, and in particular for
 * why a denial is the *designed* outcome in three other situations (outside the
 * workspace, under `read-only`, a runner failure) and must never be advised; and
 * for the fourth narrowing, `isWorkspaceRoot` — the account is about a
 * DESCENDANT that missed an inherited ACE, so a denial naming the root itself is
 * declined rather than explained.
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
 *    is nothing to grant. For the CIM/WMI family it names the code and the
 *    resolved mode, quotes the backend's own README as the mechanism rather than
 *    claiming it, hands over the measured native substitute for every command the
 *    report measured one for, says plainly which two commands have none, and
 *    states the two silent shapes — an empty CIM result and `Get-PSDrive`'s zero
 *    columns — as rules, because neither raises an error and an agent will act on
 *    either. All six ride `additionalContexts`, so the
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
 * - **The real fix is upstream**, in all six families: the ACL failure should
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
 * **The CIM/WMI boundary of the restricted token (`cim-wmi-denial`, `#9272`).**
 * The sixth family is the only one whose mechanism the harness **already
 * documents**: under a confining mode every WMI query and every cmdlet built on
 * one is refused with `WBEM_E_ACCESS_DENIED` (`0x80041003`), because the
 * restricted token's lists do not carry the SIDs the WMI namespace security
 * check wants — the Windows ACL package's README says so, its token builder
 * repeats it, and two arms of its runner suite pin it. The plugin carries the
 * family anyway for the reason the ACL family carries a documented
 * prerequisite: the *error* does not name it, and the moment the diagnosis is
 * needed is the moment a CIM command has just failed for no visible reason.
 * What the advisory adds is what the report asked for first and the
 * documentation does not supply — a measured **native substitute** for each
 * command that stops working (`netstat -ano`, `Get-Process`, `Get-Service`,
 * `[System.IO.DriveInfo]`, `Get-Counter`, the registry, with the two commands
 * that have no measured replacement named as such) — plus the two shapes that
 * answer with a **wrong value and no error at all**: `Get-PSDrive`'s usage
 * columns silently falling back to `0`, and every CIM call under
 * `-ErrorAction SilentlyContinue` returning an empty result, which an agent
 * reads as "nothing is listening" when the query never ran. Read from the
 * canonical value of a **successful** result, in that value's own `stderr` — the
 * same seam as the native-init family, because a cmdlet error is a nonzero exit
 * and the renderer reports those without erroring. Like the other Windows-only
 * value-read family it is gated on the platform and on the resolved mode, and it
 * names no repair: no ACE closes it, no elevation reaches it, and the one narrow
 * allowance a reader proposes is a change to the token's own lists, priced by
 * nobody — the same absence of Authenticated Users that refuses the namespace is
 * listed upstream as what closes the `C:\`-root tree-creation escape. The
 * advisory quotes upstream's sentence as the authority and says what it adds,
 * rather than presenting a documented boundary as a discovery.
 *
 * **A refusal that withholds its own cause (the ACL `AggregateError` wrapper,
 * `#9460`).** The seventh family is the only one whose *line* is the finding: it
 * is the message of an `AggregateError` thrown when the Windows ACL backend's
 * own fail-closed cleanup failed with the grant that had just failed. Node
 * builds that message from the argument the thrower passed, **not** from its
 * members, so the inner failure — the Win32 code, the API name, and the
 * directory being edited — is nowhere in the text; it is in `errors`, which
 * nothing on the model's side reads. The account in `#9460` is exactly that
 * shape, and so is the reporter's inference from the Config schema: a visible
 * `probeTimeoutMs` invited "the probe timed out", but this backend's Windows
 * chain is a single rung selected without probing and its grant path contains no
 * probe at all, so no timer can produce the sentence. The mechanism a reader
 * *can* rule in or out needs no ACL work whatsoever and is named FIRST in the
 * advisory: every grant and every revocation runs under one per-path lock whose
 * file is created before any security descriptor is touched, so a lock root that
 * cannot be created fails the grant **and** its cleanup together and yields this
 * exact sentence having attempted no ACL operation. Because the line names
 * neither the code nor the directory, the advisory ships no grant command — one
 * aimed at the wrong directory is worse than none — and hands over the listing
 * that names the directory instead, then the backend's own repair skill, with
 * the version boundary that introduced it.
 *
 * @module @argszero/cordis-plugin-sandbox-grant-advisor
 */
import type { Context } from '@deepseek-ai/cordis';
export declare const name = "sandbox-grant-advisor";
/** The tool pipeline this plugin observes and (optionally) gates. */
export declare const inject: string[];
/**
 * The producer kind every message this plugin writes carries.
 *
 * It is deliberately its own kind rather than the retired `plugin` wrapper: the
 * current session format admits only a producer-owned kind — a message whose
 * `source.kind` is the string `plugin` is refused on the way in
 * (`packages/session/session-format-v3-to-v4/src/message-sources.ts`) — and the
 * source union is documented as merge-extensible, one kind per producer.
 */
export declare const SOURCE_KIND = "sandbox-grant-advisor";
/** Default fail-fast threshold: 0, i.e. the blocking half is off. */
export declare const DEFAULT_ENFORCE_AFTER = 0;
/** Default denial budget once the blocking half is enabled. */
export declare const DEFAULT_MAX_DENIALS = 2;
/**
 * The family the optional blocking half applies to.
 *
 * The ACL remedy is a command the user can run while the session continues; the
 * PTY remedy is a preset swap between sessions and the native-init remedy is a
 * user-side launch fix (or a rewrite the model makes itself), so refusing calls
 * is only useful in the first case — see `denialText` in `src/advice.ts`.
 */
export declare const ENFORCED_FAMILY = "acl-provisioning";
/** Configures what is watched and whether the blocking half runs. */
export interface Config {
    /**
     * ACL provisioning failures after which an identical, already-failing call is
     * denied before dispatch. `0` (the default) disables the half entirely; the
     * advisory half is unaffected and always on. The blocking half applies to the
     * ACL family alone: it does not cover the persistent-shell or native-init
     * families, whose remedies are not a command the session can wait out.
     */
    enforceAfter?: number;
    /**
     * How many denials one agent may spend. Defaults to 2. Bounded on purpose:
     * an unbounded refusal turns a stuck session into an unfinishable one.
     */
    maxDenials?: number;
    /** Tool-name wildcard patterns to watch; empty means every tool. */
    include?: string[];
    /** Tool-name wildcard patterns never watched. */
    exclude?: string[];
    /** URL quoted in the advisory as the upstream thread; optional. */
    href?: string;
}
/**
 * Install the advisor.
 * @param ctx - context carrying the tool pipeline.
 * @param config - resolved options; validated fail-loud here.
 */
export declare function apply(ctx: Context, config?: Config): void;
