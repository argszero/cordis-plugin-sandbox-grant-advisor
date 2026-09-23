/**
 * What the model — and through it the user — is told about a provisioning
 * failure, and what is deliberately withheld.
 *
 * The text is assembled here as pure functions so every sentence can be pinned
 * by a test. Two properties matter more than the wording:
 *
 * - **It names the right the caller is missing.** The reported failures are
 *   `ERROR_ACCESS_DENIED` from a *merged* DACL + SACL write. The missing right
 *   is `WRITE_OWNER` on the directory — an object right the caller can grant
 *   itself with `icacls`, unelevated. It is **not** `SeSecurityPrivilege`, the
 *   token privilege the reports naturally reach for; `whoami /priv` cannot show
 *   the difference, and elevation is the wrong lever.
 * - **It gives a discriminator, not just a remedy.** Applying a fix without
 *   confirming the cause teaches nothing when the fix does not work. The
 *   one-line check (`icacls <dir>`, looking for an ACE that names the caller's
 *   own SID and grants `(F)`) separates "Modify-only directory" from "the
 *   documented prerequisite is wrong", which is the open question upstream.
 *
 * @module
 */

import type { ProvisioningFailure } from './signature.js'
import { failureLine } from './signature.js'

/** The upstream threads this advisory is a stopgap for. */
export const DISCUSSIONS = '#7538 / #7622 / #7646'

/** The documented prerequisite, quoted from the backend's README. */
export const PREREQUISITE = 'granted directories must be caller-owned and grant `WRITE_OWNER`'

/** Placeholder the user replaces with the directory the error named. */
const PLACEHOLDER = '<the directory from the error line above>'

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
        '"Authenticated Users: Modify" (`0x1301bf`) from the drive root — and that mask has neither right.',
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
 * Build the advisory attached to the failing tool result.
 * @param failure - the recognized failure.
 * @param href - optional URL shown for the upstream thread.
 * @returns the user-role notice text, with the fix commands ready to paste.
 */
export function advisoryText(failure: ProvisioningFailure, href?: string): string {
  const path = failure.path ?? PLACEHOLDER
  const where = href === undefined ? `tracked upstream (discussions ${DISCUSSIONS})` : `tracked upstream: ${href}`
  return [
    'Sandbox provisioning failed — no sandboxed command can run in this workspace until its ACL applies.',
    '',
    'What was reported:',
    `  ${failureLine(failure)}`,
    '',
    diagnosis(failure),
    '',
    'Confirm the cause (unelevated) — `icacls` is a normal user command:',
    `  icacls "${path}"`,
    'Look for an ACE that names YOUR OWN account (run `whoami` if unsure) with (F) / Full control.',
    'If the strongest entry naming you is (M) / Modify, that is this failure.',
    '',
    'Fix it (unelevated, one line) and then run the command again:',
    `  PowerShell: icacls "${path}" /grant "$env:USERNAME:(OI)(CI)F"`,
    `  cmd:        icacls "${path}" /grant "%USERNAME%:(OI)(CI)F"`,
    '',
    'How to read this: the harness documents the prerequisite (' + PREREQUISITE + ') and this',
    'error does not name it yet, so the advice is delivered here instead. This is a stopgap, ' + where + '.',
    'What it is NOT: this plugin neither edits ACLs nor elevates — the command above is yours to run.',
    'Your file read/write tools still work; only sandboxed command execution is blocked.',
  ].join('\n')
}

/**
 * Build the pre-dispatch denial for the optional fail-fast half.
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
    failure.path === undefined ? '' : `  icacls "${failure.path}" /grant "$env:USERNAME:(OI)(CI)F"`,
    '',
    suffix > 0
      ? `This is automatic block ${String(denial)} of ${String(maxDenials)}; after that the call is allowed again.`
      : `This is automatic block ${String(denial)} of ${String(maxDenials)} — the last one; further identical calls are allowed again.`,
  ].filter(line => line !== '').join('\n')
}
