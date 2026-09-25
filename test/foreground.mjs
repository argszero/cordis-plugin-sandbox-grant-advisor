/**
 * The producer's side of the native-init family, shared by the pure arms and the
 * integration arms.
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
