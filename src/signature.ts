/**
 * Recognize the two environment failures this plugin explains, and refuse
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
 * One signature covers two environments, and the text is identical in both, so
 * the classifier cannot and must not try to tell them apart: a workspace the
 * caller created with `mkdir` that inherits "Authenticated Users: Modify" from
 * the drive root (`#7622`, `#7646`, `#7720`), and a directory on a data volume
 * where **no ACE names the caller at all** so that the inherited entry is the
 * whole of their access (`#7750` on D:/E:, `#7735`'s second defect). Both are
 * the same gate — `WRITE_OWNER` on the directory — and the same one-line remedy
 * satisfies both, which is why they share a class and the advisory names both
 * shapes instead of guessing which one it is looking at. What the text *does*
 * carry that the failure does not is the version boundary: the merged
 * DACL + label write exists only from `0.1.7-alpha.1` on
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
 * @module
 */

/** Which provisioning operation failed, and which diagnosis follows from it. */
export type FailureClass =
  /**
   * `SetNamedSecurityInfoW` returned `ERROR_ACCESS_DENIED` (5): the merged
   * DACL + label write was refused. Both environments in the module doc land
   * here — the `mkdir`-inherited Modify workspace and the data-volume directory
   * with no ACE naming the caller — because the failure text cannot separate
   * them and the remedy is the same `WRITE_OWNER` grant.
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

/** Any failure this plugin recognizes, tagged by family. */
export type RecognizedFailure = ProvisioningFailure | PtyStartupFailure

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
 * The one-line failure the producer wrote, for quoting back verbatim.
 * @param failure - a recognized failure.
 * @returns the message text the producing layer would have produced.
 */
export function failureLine(failure: RecognizedFailure): string {
  if (failure.family === 'pty-startup') return failure.line
  const suffix = failure.detail.length === 0 ? '' : `: ${failure.detail}`
  return `${failure.api} failed (Win32 ${failure.win32Code})${suffix}`
}
