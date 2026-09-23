/**
 * Recognize the Windows ACL provisioning failure that has no path forward.
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
 * Recognizing the string is therefore the whole job of this module, and the
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
 * @module
 */

/** Which provisioning operation failed, and which diagnosis follows from it. */
export type FailureClass =
  /** `SetNamedSecurityInfoW` returned `ERROR_ACCESS_DENIED` (5): the merged DACL + label write was refused. */
  | 'apply-denied'
  /** `SetNamedSecurityInfoW` failed with a Win32 code other than `ERROR_ACCESS_DENIED`. */
  | 'apply-other'
  /** `GetNamedSecurityInfoW` failed: the security descriptor could not even be read. */
  | 'read-denied'

/** One recognized provisioning failure, with the producer's own fields kept. */
export interface ProvisioningFailure {
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
 * Classify one failure message.
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
  return { klass, api, win32Code: code, detail, ...splitDetail(detail) }
}

/**
 * The one-line failure the producer wrote, for quoting back verbatim.
 * @param failure - a recognized failure.
 * @returns the message text a `Win32Error` would have produced.
 */
export function failureLine(failure: ProvisioningFailure): string {
  const suffix = failure.detail.length === 0 ? '' : `: ${failure.detail}`
  return `${failure.api} failed (Win32 ${failure.win32Code})${suffix}`
}
