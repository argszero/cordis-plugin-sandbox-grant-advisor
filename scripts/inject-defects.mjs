/**
 * Defect injection: mutate the source, rebuild, run the suite, and require that
 * the mutation is caught. An arm whose mutation leaves the suite green is
 * SILENT — it proves nothing.
 *
 * The suite imports `lib/*.js`, not `src/*.ts`, so every arm rebuilds with tsc
 * first; a mutation that fails to type-check proves nothing either and is
 * reported separately.
 *
 * Run from the plugin root: `node tmp/inject.mjs`.
 */
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

const MUTATIONS = [
  {
    name: 'the mode gate is gone — no mode confines, so the PTY family advises under danger-full-access',
    file: 'src/mode.ts',
    arms: 'pty-startup.spec.mjs',
    edits: [["  return mode !== 'danger-full-access'", '  return false']],
  },
  {
    name: 'PTY family matched as a substring instead of a whole line',
    file: 'src/signature.ts',
    arms: 'signature.spec.mjs',
    edits: [['if (line === PTY_STARTUP_EXIT || line === `Error: ${PTY_STARTUP_EXIT}`) {', 'if (line.includes(PTY_STARTUP_EXIT)) {']],
  },
  {
    name: 'the preset remedy names the legacy directory the harness stopped reading',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["export const PROFILE_PATCH = '$DSH_HOME/profiles/<profile>/cordis.patch.yml'", "export const PROFILE_PATCH = '<DSH_HOME>/.agent-presets/<id>/'"]],
  },
  {
    name: 'the two families share one bookkeeping slot instead of one each',
    file: 'src/index.ts',
    arms: 'pty-startup.spec.mjs',
    edits: [
      ['const first = !advisedOf(advanced, failure.family)', "const first = !advisedOf(advanced, 'acl-provisioning')"],
      ['states.set(agent, first ? recordAdvice(advanced, failure.family) : advanced)', "states.set(agent, first ? recordAdvice(advanced, 'acl-provisioning') : advanced)"],
    ],
  },
  {
    // EQUIVALENT MUTANT, recorded rather than hidden: with the current
    // `dsh-tools` runtime the rendered content of an error result is derived
    // from `error.message`, so the narrower read and the merged read agree and no
    // fixture can tell them apart (a custom `render` is ignored on the error
    // path — measured). Kept in the list because "we tried to make this arm bite
    // and could not" is a fact about the arm, not a reason to omit it.
    name: 'the PTY family reads the merged text instead of `error.message`',
    file: 'src/index.ts',
    arms: 'pty-startup.spec.mjs',
    equivalent: 'the runtime derives error content from the message, so the two reads are indistinguishable from outside',
    edits: [['?? classifyPtyStartupFailure(result.error.message)', '?? classifyPtyStartupFailure(failureText(result))']],
  },
  {
    name: 'the non-fix section is emitted for the wrong class (the gate names read-denied)',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["if (failure.klass !== 'apply-denied') return []", "if (failure.klass !== 'read-denied') return []"]],
  },
  {
    name: 'the non-fix section presents itself as the remedy instead of the thing that does not work',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["'What will NOT fix it — both look like the right move, and both were tried and reported:',", "'If that fails, try one of these instead:',"]],
  },
  {
    name: 'the ACL advisory is delivered on every failure instead of once per agent',
    file: 'src/index.ts',
    arms: 'plugin.spec.mjs',
    edits: [['const first = !advisedOf(advanced, failure.family)', 'const first = true']],
  },
]

let silent = 0
let unbuildable = 0
for (const mutation of MUTATIONS) {
  const path = join(ROOT, mutation.file)
  const original = readFileSync(path, 'utf8')
  let mutated = original
  let anchored = true
  for (const [find, replace] of mutation.edits) {
    if (!original.includes(find)) {
      anchored = false
      console.log(`SKIP (anchor missing): ${mutation.name}`)
    }
    mutated = mutated.replace(find, replace)
  }
  if (!anchored) continue

  const build = () => {
    try {
      execFileSync('npx', ['tsc'], { cwd: ROOT, stdio: 'pipe' })
      return true
    } catch {
      return false
    }
  }

  writeFileSync(path, mutated)
  let built = false
  let failed = false
  let output = ''
  try {
    built = build()
    if (built) {
      try {
        execFileSync('node', ['--test', `test/${mutation.arms}`], { cwd: ROOT, stdio: 'pipe' })
      } catch (error) {
        failed = true
        output = String(error.stdout ?? '') + String(error.stderr ?? '')
      }
    }
  } finally {
    // The source is restored and rebuilt whatever happened: an injector that can
    // leave a mutation in the tree is worse than no injector.
    writeFileSync(path, original)
    build()
  }

  if (!built) {
    unbuildable += 1
    console.log(`UNBUILDABLE (proves nothing): ${mutation.name}`)
    continue
  }
  const caught = failed && new RegExp(`fail [1-9]`).test(output)
  if (!caught && mutation.equivalent === undefined) silent += 1
  const label = caught ? 'CAUGHT' : mutation.equivalent === undefined ? 'SILENT' : 'EQUIVALENT'
  console.log(`${label}: ${mutation.name} (${mutation.arms})${caught || mutation.equivalent === undefined ? '' : ` — ${mutation.equivalent}`}`)
}
console.log(`SILENT ARMS: ${silent === 0 ? 'none' : String(silent)}; UNBUILDABLE: ${String(unbuildable)}`)
