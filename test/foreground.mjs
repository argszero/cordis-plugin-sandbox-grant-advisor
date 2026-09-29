/**
 * The producer's side of the two value-read families — the native-init death and
 * the workspace-internal denial — shared by the pure arms and the integration
 * arms.
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
