/**
 * What the model — and through it the user — is told about a recognized
 * environment failure, and what is deliberately withheld.
 *
 * The text is assembled here as pure functions so every sentence can be pinned
 * by a test, one family at a time. The three families are shaped by the same
 * question — is this the sandbox's doing, and what can the reader do about it —
 * and they answer it differently:
 *
 * - **The ACL failure** (`acl-provisioning`) *is* fixable by the caller, so its
 *   advice names the right the caller is missing and gives the command.
 *   The reported failures are `ERROR_ACCESS_DENIED` from a *merged* DACL + SACL
 *   write; the missing right is `WRITE_OWNER` on the directory — an object right
 *   the caller can grant itself with `icacls`, unelevated. It is **not**
 *   `SeSecurityPrivilege`, the token privilege the reports naturally reach for;
 *   `whoami /priv` cannot show the difference, and elevation is the wrong lever.
 *   The remedy is the **narrowest** form of that grant — `(WO)` alone, which is
 *   literally the right the backend's prerequisite names — with Full control
 *   offered as the broad alternative; and the advisory carries the **version
 *   boundary** the label introduced (`0.1.7-alpha.1`), because that is what
 *   separates "this is the label failure" from "this is something else", and
 *   because rolling back is the reach it invites while making the very problem
 *   it closed come back.
 *
 *   **The remedy is forked on ownership, because one command cannot serve both
 *   environments.** The reports split into two rights situations behind an
 *   identical error: a workspace **the caller owns** (`#7622`, `#7646`, `#7720`,
 *   `#7750`, `#7804`), where the owner's implicit `WRITE_DAC` satisfies the DACL
 *   half and `(WO)` is the whole of what is missing — so the `icacls /grant`
 *   that supplies it *can itself run*, unelevated; and a directory **the caller
 *   does not own** (`#7771`: owner `BUILTIN\Administrators`, held deny-only for
 *   their token), where `WRITE_DAC` is missing too, so `icacls /grant` is denied
 *   for the very command that would fix it, and `(WO)` alone would not be enough
 *   even if it went through. The classifier cannot tell these apart — the text is
 *   identical — so the advisory does what it can do instead of guessing: it hands
 *   over the **ownership check** (`(Get-Acl "<dir>").Owner`) as the branch
 *   selector, then gives each branch the command that actually works there, and
 *   says why the other branch's command is not a fallback. A single unconditional
 *   one-liner would send the second environment to a command that is refused
 *   before it runs — the same defect this module exists to answer, a remedy that
 *   does not work delivered confidently.
 * - **The persistent-shell failure** (`pty-startup`) is *not* fixable by the
 *   caller — least of all by the model, which has no shell to run anything in.
 *   So its advice says so and stops: the remedy is a user-side preset choice,
 *   and the model's instruction is to stop retrying and use its file tools.
 *   Handing the model a command here would be advice to run something that
 *   cannot run, and naming a one-shot shell tool would be advice to call a tool
 *   the failing composition does not mount.
 * - **The native-init death** (`native-init`) is the one whose remedy is **split**:
 *   the *class* is not the model's to fix, but one of its two measured producers
 *   is. A confined child that died with `STATUS_DLL_INIT_FAILED` never ran
 *   anything, so retrying the same call is pure waste — but if the program that
 *   could not start was an MSYS2/Git-Bash one, the same work expressed with
 *   PowerShell or `cmd` runs fine under the identical mode, and the model *can*
 *   make that change because the model is the one that wrote the command. So the
 *   advice carries a stop instruction, the one in-session conversion, and the
 *   user-side remedy for the other producer. What it deliberately does **not** do
 *   is guess which producer this is: the code alone cannot say, and the two
 *   checks it hands over are facts the reader holds (what program they ran;
 *   whether this is the packaged desktop app, which the plugin reports rather
 *   than assumes).
 *
 * Both give a **discriminator, not just a remedy**: applying a fix without
 * confirming the cause teaches nothing when the fix does not work. For the ACL
 * family that is `icacls <dir>`, looking for an ACE that names the caller's own
 * SID and grants `(F)` — which separates "Modify-only directory" from "the
 * documented prerequisite is wrong", the open question upstream. For the PTY
 * family it is the **effective sandbox mode**, which is why that advisory is
 * only ever built with the mode the call actually ran under. For the native-init
 * family it is two checks the reader performs — which program could not start,
 * and whether this host is the packaged desktop app — because the code alone
 * cannot separate the producers and a guess would send half its readers to the
 * wrong remedy.
 *
 * @module
 */

import type { ProvisioningFailure, PtyStartupFailure, NativeInitFailure, RecognizedFailure } from './signature.js'
import { failureLine, STATUS_DLL_INIT_FAILED } from './signature.js'
import type { SandboxModeName } from './mode.js'

/** The upstream threads the ACL advisory is a stopgap for. */
export const ACL_DISCUSSIONS = '#7538 / #7622 / #7646 / #7720 / #7750 / #7735 / #7771 / #7804 / #7816'

/** The upstream thread the persistent-shell advisory is a stopgap for. */
export const PTY_DISCUSSIONS = '#7638'

/** The upstream threads the native-init-death advisory is a stopgap for. */
export const NATIVE_INIT_DISCUSSIONS = '#7876 / #7877'

/** The documented prerequisite, quoted from the backend's README. */
export const PREREQUISITE = 'granted directories must be caller-owned and grant `WRITE_OWNER`'

/**
 * Where a user's own preset changes actually live.
 *
 * This is deliberately **not** the legacy `$DSH_HOME/.agent-presets/<id>/`
 * directory: that shape predates declarative presets and **nothing reads it any
 * more** (the registry "neither scans directories nor accepts preset paths").
 * A preset is a `@deepseek-ai/dsh-agent-preset` row, and changing one means
 * overriding or inserting that row in a patch layer, which is what this path
 * names. Advising a folder the harness stopped reading would be the same defect
 * this plugin exists to answer — a remedy that does not work, delivered
 * confidently.
 */
export const PROFILE_PATCH = '$DSH_HOME/profiles/<profile>/cordis.patch.yml'

/** The machine-wide patch layer, for a change that should hold in every profile. */
export const GLOBAL_PATCH = '$DSH_HOME/cordis.patch.yml'

/** The row id the shipped `minimal` preset is declared under. */
export const MINIMAL_PRESET_ROW = 'preset-minimal'

/** The one-shot shell tool the `standard` preset mounts on Windows. */
export const ONE_SHOT_SHELL = '@deepseek-ai/dsh-tool-pwsh'

/**
 * The two remedies that look like the fix and are not.
 *
 * Both were applied by the reporter of `#7720` before finding the one that
 * works, and both are the *natural* reach: making yourself the owner and
 * resetting the directory's ACL are how one normally repairs a Windows
 * permission problem. They fail here for two different reasons, and naming the
 * reason is what makes this section worth its lines — a reader who already
 * tried them learns why, and a reader who has not is spared the attempt. See
 * {@link nonFixes} for when this is emitted.
 */
export const NOT_FIXES = [
  'takeown /F "<dir>" /R /D Y',
  'icacls "<dir>" /reset /T /C',
] as const

/** Placeholder the user replaces with the directory the error named. */
const PLACEHOLDER = '<the directory from the error line above>'

/** What the caller knows about the failing call, beyond the failure text. */
export interface AdvisoryContext {
  /** URL quoted in place of the discussions list; optional. */
  readonly href?: string
  /** The tool whose call failed, quoted back so the advice is about that call. */
  readonly tool?: string
  /**
   * The sandbox mode the failing call ran under. Required by the
   * `pty-startup` family — the whole diagnosis is the mode — and by the
   * `native-init` family, whose gate is the same question; unused by the ACL
   * family.
   */
  readonly mode?: SandboxModeName
  /**
   * Whether this process is an Electron binary (`process.versions.electron`).
   * Used by the `native-init` family to report — not to assume — which of its
   * producers this host can have; absent means "ask the live process", so a
   * caller cannot accidentally state a fact it did not measure.
   */
  readonly electronHost?: boolean
}

/**
 * Whether this process is running on an Electron binary.
 *
 * In the packaged desktop the harness host *is* Electron, started with
 * `ELECTRON_RUN_AS_NODE=1` so it behaves as Node — which is why the variable is
 * defined here and why its presence is the discriminator the `#7876` producer
 * turns on: `sandbox-local` launches the sandbox runner as `process.execPath`,
 * and in that build the exec path is the Electron executable.
 * @returns true when `process.versions.electron` is set.
 */
function electronHost(): boolean {
  return process.versions.electron !== undefined
}

/**
 * The diagnosis paragraph for one class of failure.
 * @param failure - the recognized failure.
 * @returns one paragraph, honest about what is and is not known.
 */
function diagnosis(failure: ProvisioningFailure): string {
  switch (failure.klass) {
    case 'apply-denied':
      return [
        'Why it is refused while the directory looks writable: that call is a MERGED write — the DACL and the',
        'mandatory-integrity label go out as one `SetNamedSecurityInfoW`. The label lives in the SACL, and the',
        "owner's implicit rights cover only READ_CONTROL and WRITE_DAC, so the label half additionally needs",
        'WRITE_OWNER on the directory. A workspace created with `mkdir` normally inherits',
        '"Authenticated Users: Modify" (`0x1301bf`) from the drive root — and that mask has neither right; on a data',
        'volume there may be no ACE naming you at all, so that inherited entry is the whole of your access. The two',
        'halves go out as one call, so a refused label discards the write grant with it, and the sandbox then',
        'refuses to start any command in the workspace instead of running it unconfined.',
        'This is a directory ACL fact, not a token privilege: `whoami /priv` will not show it, and',
        'SeSecurityPrivilege is the wrong lever here.',
      ].join('\n')
    case 'read-denied':
      return [
        'Why it is refused: the harness could not even read the directory\'s security descriptor, so the grant',
        'never got as far as writing one. That read wants READ_CONTROL, which the directory is not granting this',
        'account either.',
      ].join('\n')
    case 'apply-other':
      return [
        'Why it is refused: this is the same merged write, but the Win32 code is not ERROR_ACCESS_DENIED (5), so',
        'the missing-rights story above does not apply verbatim — a missing path, a non-directory target, or a',
        'filesystem that does not carry ACLs are all possibilities. The commands below are safe to try; if the',
        'code persists, it is a different failure and worth reporting with the code.',
      ].join('\n')
  }
}

/**
 * The "this is not the fix" lines for one class of failure.
 *
 * Emitted only for `apply-denied`, the class whose whole diagnosis is the
 * missing `WRITE_OWNER` right — because only there is the claim true:
 *
 * - `read-denied` wants `READ_CONTROL`, and taking ownership *does* carry it,
 *   so calling `takeown` a non-fix there would be false.
 * - `apply-other` already says the missing-rights story does not apply
 *   verbatim, so a section that presupposes it would contradict its own
 *   diagnosis.
 *
 * A negative claim still has to be earned: the failure to avoid is advice that
 * is confidently wrong in the other direction. That is why the `takeown` line
 * claims only what is true in **both** ownership branches: it supplies the DACL
 * half and never `WRITE_OWNER`, so it is not the fix by itself — while still
 * being a legitimate first step (with elevation) where the caller is not the
 * owner. Calling it useless outright would have been the mirror-image error.
 * @param failure - the recognized provisioning failure.
 * @param path - the directory the error named, or the placeholder.
 * @returns the section's lines, or an empty array for a class it does not fit.
 */
function nonFixes(failure: ProvisioningFailure, path: string): string[] {
  if (failure.klass !== 'apply-denied') return []
  return [
    'What will NOT fix it on its own — both look like the right move, and both were tried and reported:',
    `  takeown /F "${path}" /R /D Y`,
    "    makes you the owner, and ownership's implicit rights are READ_CONTROL and WRITE_DAC only — so it",
    '    supplies the DACL half and still not WRITE_OWNER, the right this call needs. In the second branch above',
    '    it is a legitimate first step with elevation; it is never the fix by itself.',
    `  icacls "${path}" /reset /T /C`,
    '    restores inheritance, and inheritance is what supplied the Modify-only ACE above.',
    '',
  ]
}

/**
 * When the label half arrived, and why an older build is not the remedy.
 *
 * Emitted for every class: the boundary is a fact about the package
 * `sandbox-windows-acl` (whose `DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION`
 * flag is what needs `WRITE_OWNER`), not about which of its two calls failed, so
 * it is true wherever this module is willing to speak at all. It is also the one
 * fact neither report could get from the error: the failure looks identical on a
 * line where the label does not exist yet, and the build that introduced it is
 * the natural thing to reach for and the wrong one to reach for.
 * @returns the section's lines.
 */
function versionBoundary(): string {
  return [
    'A version boundary worth knowing before reaching for an older build: the label half is new to this package.',
    'Up to `0.1.6-alpha.x` the backend touched the DACL only (flag 4), so a Modify-only workspace provisioned',
    'fine; `0.1.7-alpha.1` is where the mandatory label — and with it the SACL, flag 20 — arrives. On a',
    '`0.1.6-alpha.x`-or-older line this exact failure therefore belongs to a different cause space, while on any',
    '`0.1.7-*` line it is this one. Rolling back is not the fix either: the label is what confines deletes to the',
    'workspace, and reverting it reintroduces the escape it closed.',
  ].join('\n')
}

/**
 * Build the advisory attached to the failing tool result.
 *
 * The family decides everything: one function so a caller does not have to
 * remember which family needs which fact, and so the mode requirement of the
 * two gated families is enforced by construction rather than by convention.
 * @param failure - the recognized failure.
 * @param context - what the caller knows about the failing call.
 * @returns the user-role notice text, with any remedy ready to paste.
 * @throws when a mode-gated failure is advised without its resolved sandbox mode.
 */
export function advisoryText(failure: RecognizedFailure, context: AdvisoryContext = {}): string {
  if (failure.family === 'pty-startup') {
    if (context.mode === undefined) {
      throw new Error('sandbox-grant-advisor: the persistent-shell advisory requires the resolved sandbox mode')
    }
    return ptyAdvisory(failure, context.mode, context.tool, context.href)
  }
  if (failure.family === 'native-init') {
    if (context.mode === undefined) {
      throw new Error('sandbox-grant-advisor: the native-init advisory requires the resolved sandbox mode')
    }
    return nativeInitAdvisory(failure, context.mode, context.electronHost ?? electronHost(), context.href)
  }
  return aclAdvisory(failure, context.href)
}

/**
 * Build the advisory for a workspace-provisioning failure.
 * @param failure - the recognized failure.
 * @param href - optional URL shown for the upstream thread.
 * @returns the user-role notice text, with the fix commands ready to paste.
 */
function aclAdvisory(failure: ProvisioningFailure, href?: string): string {
  const path = failure.path ?? PLACEHOLDER
  const where = href === undefined ? `tracked upstream (discussions ${ACL_DISCUSSIONS})` : `tracked upstream: ${href}`
  return [
    'Sandbox provisioning failed — no sandboxed command can run in this workspace until its ACL applies.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}`,
    '',
    diagnosis(failure),
    '',
    versionBoundary(),
    '',
    'Confirm the cause (unelevated) — `icacls` is a normal user command:',
    `  icacls "${path}"`,
    'Look for an ACE that names YOUR OWN account (run `whoami` if unsure) with (F) / Full control or',
    '(WO) / Write owner. If the strongest entry naming you is (M) / Modify — or no entry names you at all and',
    'your access comes from an inherited `Authenticated Users:(M)` — that is this failure.',
    '',
    'Ownership decides which of the two commands below can work, so read it first — PowerShell 5.1 or later:',
    `  (Get-Acl "${path}").Owner      # compare with: whoami`,
    'If that is not your own account, take the second branch: the first one is refused before it runs.',
    '',
    'IF YOU OWN THE DIRECTORY — the usual workspace, whether on the system drive or a data volume:',
    '  one unelevated line, then run the command again:',
    `  PowerShell: icacls "${path}" /grant "$env:USERNAME:(OI)(CI)(WO)"`,
    `  cmd:        icacls "${path}" /grant "%USERNAME%:(OI)(CI)(WO)"`,
    'WRITE_OWNER is exactly the right the prerequisite names, so this grants nothing the harness did not ask for,',
    'and (OI)(CI) makes the ACE inheritable, so one command reaches the workspace\'s existing subdirectories.',
    'Full control works just as well — the same line with `F` in place of `(WO)`:',
    `  icacls "${path}" /grant "$env:USERNAME:(OI)(CI)F"`,
    'Why `(WO)` is the whole of what is missing there: an owner holds READ_CONTROL and WRITE_DAC implicitly,',
    'and WRITE_DAC is what `icacls /grant` itself needs — so the DACL half of the merged write already has what',
    'it wants, and WRITE_OWNER is the single missing piece.',
    '',
    'IF YOU DO NOT OWN IT — a directory an installer or another account created, e.g. owner',
    '`BUILTIN\\Administrators`:',
    '  the line above cannot run at all. Changing a DACL takes WRITE_DAC, which you hold neither as owner nor',
    '  through any ACE, so `icacls /grant` is refused with `Access is denied` — for the very command that would',
    '  fix it. The merged write wants WRITE_DAC and WRITE_OWNER together, so `(WO)` alone would not be enough',
    '  here even if it went through. Run the grant once from an account that already holds both — that is, from an',
    '  ELEVATED prompt:',
    `  icacls "${path}" /grant "<your-account>:(OI)(CI)F"`,
    'Full control is used because it is the rights set covering both halves; the other reach both reports name is',
    'to take ownership first, which also needs elevation (it wants SeTakeOwnership), after which the unelevated',
    '`(WO)` line above applies:',
    `  icacls "${path}" /setowner "<your-account>"`,
    'Or sidestep the ACL entirely: create the workspace under `%USERPROFILE%` — a directory created there',
    'inherits Full control for you — and open the session on that one.',
    '',
    ...nonFixes(failure, path),
    'How to read this: the harness documents the prerequisite (' + PREREQUISITE + ') and this',
    'error does not name it yet, so the advice is delivered here instead. This is a stopgap, ' + where + '.',
    'What it is NOT: this plugin neither edits ACLs nor elevates — the command above is yours to run.',
    'Your file read/write tools still work; only sandboxed command execution is blocked.',
  ].join('\n')
}

/**
 * Build the advisory for a confined Windows child that never reached its entry
 * point.
 *
 * Three things this text must not do: retry silently (the identical call cannot
 * start), hand the model a command to run (there may be no working shell to run
 * it in — that is what died), or assert which producer this is. The code is a
 * loader status and says nothing about the sandbox by itself, so the diagnosis
 * is the *class* ("the process never started") plus the two producers that have
 * been measured under this harness, each with the check that distinguishes it.
 * One of those checks the plugin answers itself and reports as a fact — whether
 * this process is an Electron binary — rather than assuming, because a reader
 * told "this is the packaged desktop" without evidence would be reading a guess
 * dressed as a finding.
 * @param failure - the recognized failure.
 * @param mode - the resolved sandbox mode the failing call ran under.
 * @param onElectron - whether this process is an Electron binary.
 * @param href - optional URL shown for the upstream threads.
 * @returns the user-role notice text.
 */
function nativeInitAdvisory(
  failure: NativeInitFailure,
  mode: SandboxModeName,
  onElectron: boolean,
  href?: string,
): string {
  const where = href === undefined ? `tracked upstream (discussions ${NATIVE_INIT_DISCUSSIONS})` : `tracked upstream: ${href}`
  return [
    'Sandboxed command never started — the process died while its native libraries were loading.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}        (0xC0000142 STATUS_DLL_INIT_FAILED)`,
    `The call ran under sandbox mode \`${mode}\`, where the harness starts every command through its`,
    'restricted-token runner.',
    '',
    `0x${failure.exitCode.toString(16).toUpperCase()} is STATUS_DLL_INIT_FAILED: the Windows loader terminated the process while it was`,
    'initializing its DLLs and C runtime, which is BEFORE the program\'s entry point. A command that ran and',
    'then failed exits with its own status and prints its own output; this one produced neither. The number',
    'is also not a portable exit status — those are 0-255, and this is a 32-bit NTSTATUS. Nothing in the code',
    'says "sandbox" by itself; what makes the sandbox a candidate is the mode above, under which every',
    'command is spawned through the ACL runner.',
    '',
    'Two producers have been measured under a confining Windows mode. Check which one this is:',
    '  1. An MSYS2 / Git-Bash program — `bash.exe`, `sh.exe`, or anything from a Git for Windows or MSYS2',
    '     distribution. Under the restricted token its runtime cannot create the pipe it uses for signals,',
    '     and it aborts in the loader phase (`couldn\'t create signal pipe, Win32 error 5`), while `cmd.exe`',
    '     and PowerShell run fine in the same workspace under the same mode (#7877).',
    '     If that is what could not start: write the same work as a PowerShell or `cmd` command instead and',
    '     continue — do not retry the MSYS2 program.',
    '  2. The packaged desktop application\'s sandbox runner. `dsh-sandbox-local` starts the runner as',
    '     `[process.execPath, runner.js]`, and in the packaged build `process.execPath` is the Electron',
    '     executable, which starts as an *application* unless the child\'s environment carries',
    '     `ELECTRON_RUN_AS_NODE=1` — so the runner never runs and every confined command reports this code',
    '     with no output at all (#7876).',
    onElectron
      ? '     This process IS an Electron binary (`process.versions.electron` is set), so that producer applies here:'
      : '     This process is NOT an Electron binary (`process.versions.electron` is unset), so the runner is a real',
    onElectron
      ? '     run the same command with `danger-full-access`, or from an unpacked `node apps/cli/lib/bin.js web`'
      : '     Node binary here and that producer cannot be the cause. If the program was not an MSYS2 one either,',
    onElectron
      ? '     host where the runner is a real Node binary. If it works there, the runner never ran and this is the cause.'
      : '     this failure is outside both measured producers: stop and hand it to the user.',
    '',
    'Do not retry this call: the environment has not changed, and the identical call produces the identical',
    'code. Convert the work only in case 1; otherwise stop and hand it to the user.',
    '',
    'Honest boundary — 0xC0000142 has producers this list does not have: a program that cannot load one of',
    'its own DLLs dies this way too, and the sandbox backend\'s own source records that a child started with',
    'a hidden console window does as well (which is why that backend avoids `CREATE_NO_WINDOW`). This is not',
    'a claim that the sandbox caused the failure — the code cannot say that. What is claimed is narrower and',
    'checkable: the process never reached its entry point, and under this mode these two producers are known.',
    '',
    'This is a stopgap, ' + where + '. What it is NOT: this plugin neither changes an environment nor',
    'widens the sandbox — the checks above are yours to make, and `danger-full-access` is not offered as a fix.',
  ].join('\n')
}

/**
 * Build the advisory for a persistent-shell startup failure.
 *
 * The one thing this text must never do is hand the model a command to run:
 * there is no shell to run it in. That is why the remedy is addressed to the
 * user (preset choice), while the model's instruction is to stop — the
 * alternative, naming a one-shot shell tool, would be advice to call a tool the
 * failing composition does not mount (`minimal` mounts exactly one platform
 * shell, the persistent PTY: the design note
 * `.agents/notes/implemented/simplification/2026-09-03-minimal-profiles-persistent-shell-only.md`).
 * @param failure - the recognized failure.
 * @param mode - the resolved sandbox mode the failing call ran under.
 * @param tool - the tool whose call failed, when the caller knows it.
 * @param href - optional URL shown for the upstream thread.
 * @returns the user-role notice text.
 */
function ptyAdvisory(failure: PtyStartupFailure, mode: SandboxModeName, tool?: string, href?: string): string {
  const where = href === undefined ? `tracked upstream (discussion ${PTY_DISCUSSIONS})` : `tracked upstream: ${href}`
  const call = tool === undefined ? 'This tool' : `The \`${tool}\` tool`
  return [
    'Persistent shell failed to start — command execution is unavailable in this session, and retrying cannot fix it.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}`,
    '',
    `${call} is a PERSISTENT PTY session (a shell that stays alive between calls), and this session's sandbox mode is`,
    `\`${mode}\` — not \`danger-full-access\`. A confining mode spawns the shell through the sandbox, and there the`,
    'terminal backend cannot create the pseudo-console at all, so the child exits before its first prompt. The same',
    'shell works under `danger-full-access`, and the one-shot shell tool works under the same confining mode:',
    'persistent PTY × confining sandbox is the combination that fails.',
    '',
    'Do NOT retry, and do not look for a command that fixes it: every attempt will fail identically, and there is no',
    'shell to run a command in. Use your file read/write tools instead, and hand the choice below to the user.',
    '',
    'What unblocks the session — the user\'s decision, not the model\'s:',
    '  1. switch the agent preset to `standard`, whose shell tool is a one-shot subprocess (no PTY) and works',
    '     under the sandbox; or',
    `  2. override the \`${MINIMAL_PRESET_ROW}\` row in your profile patch — \`${PROFILE_PATCH}\`, or`,
    `     \`${GLOBAL_PATCH}\` for every profile — replacing its \`persistent-shell\` group with`,
    `     \`${ONE_SHOT_SHELL}\` (a one-shot subprocess, no PTY); the patch layer is yours, so an upgrade`,
    '     will not overwrite it; or',
    '  3. run the session with `danger-full-access`, which drops the very confinement the sandbox exists to give.',
    '     Prefer 1 or 2.',
    '',
    'How to read this: the failure names no cause and points at no remedy, so the diagnosis is delivered here instead.',
    'This is a stopgap, ' + where + '. Unless the mode is `danger-full-access`, this plugin stays silent, because a',
    'shell can fail to start for other reasons and a confident wrong cause is worse than no answer.',
  ].join('\n')
}

/**
 * Build the pre-dispatch denial for the optional fail-fast half.
 *
 * The blocking half is deliberately **ACL-only**, and this function's parameter
 * type is where that is enforced. The two mode-gated families get an advisory
 * and nothing else, for a reason that is about the remedy rather than about the
 * failure:
 * the ACL remedy is a command the user can run *while the session continues*,
 * so refusing further identical calls cannot make the session unfinishable —
 * spending the budget always lets the call through, and a repaired environment
 * is discovered by exactly that. The PTY remedy is a preset swap, which happens
 * between sessions, and the native-init remedy is a launch fix on the user's
 * side (the one in-session part — rewriting an MSYS2 command — the model does by
 * calling a different tool invocation, which has a different call key and is
 * therefore never the call being refused); refusing calls could only pad a
 * session that is already unable to do the thing being refused.
 * @param failure - the recognized failure.
 * @param observed - how many provisioning failures this agent has produced.
 * @param denial - this denial's 1-based ordinal.
 * @param maxDenials - the denial budget.
 * @returns the corrective text the model receives in place of a tool result.
 */
export function denialText(
  failure: ProvisioningFailure,
  observed: number,
  denial: number,
  maxDenials: number,
): string {
  const suffix = maxDenials - denial
  return [
    `Blocked by sandbox-grant-advisor: this exact call has already failed ${String(observed)} times with the`,
    'same workspace-provisioning error, and the environment has not changed since:',
    `  ${failureLine(failure)}`,
    '',
    'Retrying cannot succeed — the sandbox cannot start a command until the directory grant applies.',
    'Stop, and either apply the fix or hand the problem to the user:',
    failure.path === undefined ? '' : `  icacls "${failure.path}" /grant "$env:USERNAME:(OI)(CI)(WO)"`,
    '',
    suffix > 0
      ? `This is automatic block ${String(denial)} of ${String(maxDenials)}; after that the call is allowed again.`
      : `This is automatic block ${String(denial)} of ${String(maxDenials)} — the last one; further identical calls are allowed again.`,
  ].filter(line => line !== '').join('\n')
}
