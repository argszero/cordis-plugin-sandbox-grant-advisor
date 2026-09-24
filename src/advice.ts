/**
 * What the model — and through it the user — is told about a recognized
 * environment failure, and what is deliberately withheld.
 *
 * The text is assembled here as pure functions so every sentence can be pinned
 * by a test, one family at a time. The two families are shaped by the same two
 * questions, and they answer them differently:
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
 * - **The persistent-shell failure** (`pty-startup`) is *not* fixable by the
 *   caller — least of all by the model, which has no shell to run anything in.
 *   So its advice says so and stops: the remedy is a user-side preset choice,
 *   and the model's instruction is to stop retrying and use its file tools.
 *   Handing the model a command here would be advice to run something that
 *   cannot run, and naming a one-shot shell tool would be advice to call a tool
 *   the failing composition does not mount.
 *
 * Both give a **discriminator, not just a remedy**: applying a fix without
 * confirming the cause teaches nothing when the fix does not work. For the ACL
 * family that is `icacls <dir>`, looking for an ACE that names the caller's own
 * SID and grants `(F)` — which separates "Modify-only directory" from "the
 * documented prerequisite is wrong", the open question upstream. For the PTY
 * family it is the **effective sandbox mode**, which is why that advisory is
 * only ever built with the mode the call actually ran under.
 *
 * @module
 */

import type { ProvisioningFailure, PtyStartupFailure, RecognizedFailure } from './signature.js'
import { failureLine } from './signature.js'
import type { SandboxModeName } from './mode.js'

/** The upstream threads the ACL advisory is a stopgap for. */
export const ACL_DISCUSSIONS = '#7538 / #7622 / #7646 / #7720 / #7750 / #7735'

/** The upstream thread the persistent-shell advisory is a stopgap for. */
export const PTY_DISCUSSIONS = '#7638'

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
   * `pty-startup` family — the whole diagnosis is the mode — and unused by the
   * ACL family.
   */
  readonly mode?: SandboxModeName
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
        'filesystem that does not carry ACLs are all possibilities. The one-line fix below is safe to try; if the',
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
 * is confidently wrong in the other direction.
 * @param failure - the recognized provisioning failure.
 * @param path - the directory the error named, or the placeholder.
 * @returns the section's lines, or an empty array for a class it does not fit.
 */
function nonFixes(failure: ProvisioningFailure, path: string): string[] {
  if (failure.klass !== 'apply-denied') return []
  return [
    'What will NOT fix it — both look like the right move, and both were tried and reported:',
    `  takeown /F "${path}" /R /D Y`,
    "    makes you the owner, but ownership's implicit rights are READ_CONTROL and WRITE_DAC only.",
    '    The owner does not implicitly hold WRITE_OWNER, which is the right this call needs.',
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
 * PTY family is enforced by construction rather than by convention.
 * @param failure - the recognized failure.
 * @param context - what the caller knows about the failing call.
 * @returns the user-role notice text, with any remedy ready to paste.
 * @throws when a PTY failure is advised without its resolved sandbox mode.
 */
export function advisoryText(failure: RecognizedFailure, context: AdvisoryContext = {}): string {
  if (failure.family === 'pty-startup') {
    if (context.mode === undefined) {
      throw new Error('sandbox-grant-advisor: the persistent-shell advisory requires the resolved sandbox mode')
    }
    return ptyAdvisory(failure, context.mode, context.tool, context.href)
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
    'Fix it (unelevated, one line) and then run the command again:',
    `  PowerShell: icacls "${path}" /grant "$env:USERNAME:(OI)(CI)(WO)"`,
    `  cmd:        icacls "${path}" /grant "%USERNAME%:(OI)(CI)(WO)"`,
    'WRITE_OWNER is exactly the right the prerequisite names, so this grants nothing the harness did not ask for,',
    'and (OI)(CI) makes the ACE inheritable, so one command reaches the workspace\'s existing subdirectories.',
    'Full control works just as well — the same line with `F` in place of `(WO)`:',
    `  icacls "${path}" /grant "$env:USERNAME:(OI)(CI)F"`,
    'Both assume you own the directory: owner-implicit rights cover the DACL half of the merged write, so',
    'WRITE_OWNER is the single missing piece. A directory owned by someone else is a bigger change than a',
    'one-liner — that is the harness\'s documented prerequisite, and it is why this failure is loud instead of',
    'silently skipped.',
    '',
    ...nonFixes(failure, path),
    'How to read this: the harness documents the prerequisite (' + PREREQUISITE + ') and this',
    'error does not name it yet, so the advice is delivered here instead. This is a stopgap, ' + where + '.',
    'What it is NOT: this plugin neither edits ACLs nor elevates — the command above is yours to run.',
    'Your file read/write tools still work; only sandboxed command execution is blocked.',
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
 * type is where that is enforced. The PTY family gets an advisory and nothing
 * else, for a reason that is about the remedy rather than about the failure:
 * the ACL remedy is a command the user can run *while the session continues*,
 * so refusing further identical calls cannot make the session unfinishable —
 * spending the budget always lets the call through, and a repaired environment
 * is discovered by exactly that. The PTY remedy is a preset swap, which happens
 * between sessions; refusing calls could only pad a session that is already
 * unable to do the thing being refused.
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
