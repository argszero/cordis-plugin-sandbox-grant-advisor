/**
 * The producer's side of the three value-read families — the native-init death,
 * the workspace-internal denial, and the CIM/WMI refusal — shared by the pure
 * arms and the integration arms.
 *
 * It lives in its own module so that `signature.spec.mjs` can pin the real shape
 * without importing the harness — which mounts a cordis context — and so that
 * the value the behaviour suite feeds the pipeline is built by the same code the
 * pure arms assert against. A shape written twice is a shape that drifts.
 *
 * Where the numbers come from: `#7876` and `#7877` both report
 * `0xC0000142` `STATUS_DLL_INIT_FAILED`, the second as the signed `-1073741502`
 * a tool result carries. The stderr line is `#7877`'s, pasted verbatim.
 *
 * @module test/foreground
 */

/**
 * `STATUS_DLL_INIT_FAILED` as the tool result reports it.
 *
 * The signed 32-bit form the reporter in #7877 actually pasted (`-1073741502`),
 * not the unsigned NTSTATUS spelling: a fixture that only ever used the pretty
 * form would leave the sign handling untested, and the sign is the one part of
 * this value a platform difference can change.
 */
export const NATIVE_DEATH = -1073741502

/**
 * The stderr #7877 reports, verbatim, from the MSYS2 runtime under the
 * restricted token. It is the whole visible difference between the two
 * producers of the same code — this one prints, the Electron runner does not.
 */
export const MSYS2_STDERR = '0 [main] bash (32652) D:\\Git\\bin\\..\\usr\\bin\\bash.exe: *** fatal error '
  + "- couldn't create signal pipe, Win32 error 5"

/**
 * The canonical foreground projection of one shell call, exactly the shape the
 * shipped shell tools declare as their `output.schema` value
 * (`PwshForegroundResult` in `packages/shell/tool-pwsh/src/index.ts`, mirrored
 * by `dsh-tool-bash`): the fields the native-init family reads, plus the ones a
 * real result carries so the fixture is not a shape only this test believes in.
 * @param exitCode - the command's exit status as the tool reports it.
 * @param stderr - the captured standard error, when the producer wrote any.
 * @returns a value a shell tool would really have produced.
 */
export function foreground(exitCode, stderr = '') {
  return {
    kind: 'foreground',
    exitCode,
    signal: null,
    timedOut: false,
    aborted: false,
    timeoutMs: 120_000,
    stdout: { text: '', truncated: false },
    stderr: { text: stderr, truncated: false },
  }
}

/**
 * The stderr `#9272` reports, as PowerShell renders a refused CIM query.
 *
 * Two halves, and the difference between them is the family's whole
 * discriminator: the first line and the `CategoryInfo` label are **localized**
 * (the reporter's install prints `拒绝访问`, an English one prints
 * `Access denied`), while the `FullyQualifiedErrorId` line carries the status
 * verbatim. The fixture keeps the reporter's own language rather than
 * translating it, because a fixture that only ever used the English sentence
 * would leave the reason the classifier keys on the code — and not on the words —
 * untested.
 *
 * The record is the shape `pwsh -Command 'Get-CimInstance …'` produces on an
 * unhandled cmdlet error: the message, the source line, the caret, the category,
 * and the error id. A stderr line is the unit here, as it is for the MSYS2
 * fixture above.
 */
export const CIM_DENIED_STDERR = [
  'Get-CimInstance : 拒绝访问',
  '所在位置 行:1 字符: 1',
  '+ Get-CimInstance Win32_OperatingSystem',
  '+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~',
  '    + CategoryInfo          : PermissionDenied: (root\\cimv2:Win32_OperatingSystem) [Get-CimInstance], CimException',
  '    + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand',
].join('\n')

/**
 * The canonical foreground value of a refused CIM query.
 *
 * The exit status is `1` because that is what `pwsh -Command` returns for an
 * unhandled cmdlet error — and the point of the family is that this status is
 * reported rather than errored, so it reaches the session as the value of a
 * successful call. The report does not quote the number, and nothing in the
 * recognition reads it: the classifier keys on the stderr record, and the status
 * is only quoted back. That is stated rather than left implicit, so the day a
 * reader wonders whether `1` was measured, this is the answer.
 * @param options - `exitCode` and `stderr`, both defaulted to the reported case.
 * @returns a value the shipped shell tools would really have produced.
 */
export function cimDenied(options = {}) {
  const { exitCode = 1, stderr = CIM_DENIED_STDERR } = options
  return foreground(exitCode, stderr)
}

/**
 * The workspace root the harness's policy stand-in reports.
 *
 * A drive-qualified Windows root, because that is what the family's containment
 * test is written against: a POSIX root would make every arm pass by accident
 * through the separator/case folding rather than through the rule.
 */
export const WORKSPACE_ROOT = 'D:\\ws'

/** A path the workspace-denial fixture names, inside {@link WORKSPACE_ROOT}. */
export const INSIDE = `${WORKSPACE_ROOT}\\logs\\app.log`

/** A path the same fixture can name instead, outside {@link WORKSPACE_ROOT}. */
export const OUTSIDE = 'C:\\Program Files\\tools\\node.exe'

/**
 * The stderr a `workspace-acl` backend refuses with, taken from the dialect list
 * `bash-sandbox`'s `classifyDenial` matches (`'access is denied'` and friends).
 *
 * It is here because the executors' `denied` flag is *their* reading of this
 * text in the captured stderr, so a fixture that stamped `denied: true` without
 * any stderr would be a shape the harness cannot actually produce — and the
 * family's whole claim is that it reads the harness's own reading.
 */
export const DENIED_STDERR = 'mkdir: cannot create directory \'D:\\ws\\logs\': Access is denied.'

/**
 * The executors' own denial stamp, exactly the shape `tool-bash` / `tool-pwsh`
 * project onto a settled value (`sandbox: { mode, denied, enforcement }`).
 *
 * The default is the recognized case; every field is a parameter because the
 * suite's arms are precisely the values that must NOT be recognized (a denial
 * under `read-only`, a runner failure, a missing stamp), and building them by
 * hand at each call site is how the fixture and the producer drift apart.
 * @param options - `mode`, `denied`, `runnerFailed`, `exitCode`, `stderr`,
 *   `enforcement`; all optional and defaulted to the recognized case.
 * @returns a value the shipped shell tools would really have produced.
 */
export function denied(options = {}) {
  const {
    mode = 'workspace-write',
    denied: flag = true,
    exitCode = 1,
    stderr = DENIED_STDERR,
    enforcement = 'full',
    runnerFailed,
  } = options
  return {
    ...foreground(exitCode, stderr),
    sandbox: {
      mode,
      denied: flag,
      enforcement,
      ...runnerFailed === undefined ? {} : { runnerFailed },
    },
  }
}
