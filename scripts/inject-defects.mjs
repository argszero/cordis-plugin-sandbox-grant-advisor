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
    edits: [["'What will NOT fix it on its own — both look like the right move, and both were tried and reported:',", "'If that fails, try one of these instead:',"]],
  },
  {
    name: 'the remedy stops forking — the not-owner environment is sent the unelevated one-liner that is refused there',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [['`  icacls "${path}" /grant "<your-account>:(OI)(CI)F"`,', '`  icacls "${path}" /grant "$env:USERNAME:(OI)(CI)(WO)"`,']],
  },
  {
    name: 'the ownership check is dropped, leaving the reader two commands and no way to choose',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [['`  (Get-Acl "${path}").Owner      # compare with: whoami`,', "'  (see the branches below)',"]],
  },
  {
    name: 'the elevation the not-owner branch needs is dropped from the instruction',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '  ELEVATED prompt:',", "    '  prompt:',"]],
  },
  {
    name: 'the not-owner branch loses why the narrow grant cannot be enough there',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '  fix it. The merged write wants WRITE_DAC and WRITE_OWNER together, so `(WO)` alone would not be enough',\n    '  here even if it went through. Run the grant once from an account that already holds both — that is, from an',", "    '  fix it. Run the grant once from an account that already holds both — that is, from an',"]],
  },
  {
    name: 'the version boundary is withheld from the classes that do not see ERROR_ACCESS_DENIED',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [['    versionBoundary(),', "    failure.klass === 'apply-denied' ? versionBoundary() : '',"]],
  },
  {
    name: 'the recommended remedy silently broadens to Full control',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      '`  PowerShell: icacls "${path}" /grant "$env:USERNAME:(OI)(CI)(WO)"`,\n    `  cmd:        icacls "${path}" /grant "%USERNAME%:(OI)(CI)(WO)"`,',
      '`  PowerShell: icacls "${path}" /grant "$env:USERNAME:(OI)(CI)F"`,\n    `  cmd:        icacls "${path}" /grant "%USERNAME%:(OI)(CI)F"`,',
    ]],
  },
  {
    name: 'the ACL advisory is delivered on every failure instead of once per agent',
    file: 'src/index.ts',
    arms: 'plugin.spec.mjs',
    edits: [['const first = !advisedOf(advanced, failure.family)', 'const first = true']],
  },
  {
    name: 'the loader-status read moves onto the error path, so the third family is blind again',
    file: 'src/index.ts',
    arms: 'native-init.spec.mjs',
    edits: [['      const death = classifyNativeInitDeath(result.value)', '      const death = classifyNativeInitDeath(undefined)']],
  },
  {
    name: 'the code is classified as the neighbouring missing-DLL status instead of the reported one',
    file: 'src/signature.ts',
    arms: 'native-init.spec.mjs',
    edits: [['export const STATUS_DLL_INIT_FAILED = 0xC0000142', 'export const STATUS_DLL_INIT_FAILED = 0xC0000135']],
  },
  {
    name: 'the foreground discriminator is dropped, so any value with that exit code is claimed',
    file: 'src/signature.ts',
    arms: 'native-init.spec.mjs',
    edits: [['  if (probe.kind !== FOREGROUND) return undefined', '  /* the projection is not checked */']],
  },
  {
    name: 'the sign is not normalized, so the code the reporter pasted is not recognized',
    file: 'src/signature.ts',
    arms: 'native-init.spec.mjs',
    edits: [['  const exitCode = raw >>> 0', '  const exitCode = raw']],
  },
  {
    name: 'the host check is assumed instead of measured — every host is told it is the packaged desktop',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [['context.electronHost ?? electronHost()', 'true']],
  },
  {
    // The defect 0.7.1 exists to remove: the Electron reader was sent to a
    // widened mode, which on that platform removes the sandbox from every shell
    // call — and #8193 measured the real fix (a node host) while asking that it
    // be the one offered.
    name: 'the Electron remedy loses the host that fixes it and falls back to naming a wider mode',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["          '     `resources/runtime/primary-runtime/dependencies/node/bin/node.exe`, and the same runtime installed',", "          '     run the same command with `danger-full-access`, and the same runtime installed',"]],
  },
  {
    name: 'the warning that unsetting ELECTRON_RUN_AS_NODE breaks the desktop runner is dropped',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "          '     from every shell call. Do not unset `ELECTRON_RUN_AS_NODE` instead either — the desktop runner IS',\n          '     that Electron binary, so dropping the variable would take `runner.js` down with it (#8193 records',\n          '     this interaction with #8174).',",
      "          '     platform it silently removes the sandbox from every shell call.',",
    ]],
  },
  {
    name: 'the honest boundary drops the piped path, so the flag list reads as two sets instead of three',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    'flags actually passed are three sets and none of them is `CREATE_NO_WINDOW` — `0` on the piped path,',", "    'flags actually passed are two sets and none of them is `CREATE_NO_WINDOW` —',"]],
  },
  {
    name: 'the console mechanism is replaced by the refuted token story',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '     executable. The mechanism behind this one is the runner\\'s CONSOLE, not its token: the confined',", "    '     executable. The restricted token is derived from the Electron process image, so the child dies.',"]],
  },
  {
    name: 'the withdrawal is undone and the false "runner never started" cause is restored',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '     (a) the host binary is a GUI-subsystem program, which never owns a console — the packaged desktop,',", "    '     (a) the runner does not start at all: the Electron binary begins as an application, so nothing on the',\n    '         runner path ran (#7876); the host binary is a GUI-subsystem program — the packaged desktop,',"]],
  },
  {
    name: 'the condition on the remedy is dropped, so a real node host reads as sufficient',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '     ONE CONDITION RIDES WITH THAT: the runner must be spawned WITH a console, i.e. not with',", "    '     A real node host is all that is needed:',"]],
  },
  {
    name: 'the rejected DETACHED_PROCESS arm is presented as a remedy',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    'One arm of this family was applied, measured, and rejected — named so a reader does not reach for it:',", "    'One arm of this family was applied and measured, and it is offered here:',"]],
  },
  {
    name: 'the grant reads as machine-wide, so a reader thinks one command repairs every workspace',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    'The grant is still scoped to THIS directory and its children: another workspace root on the same volume is',", "    'The grant covers the whole volume, so no second workspace root needs the line again:',"]],
  },
  {
    name: 'the advisory sends the reader to retry with a harmless command',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    'The failure belongs to the WORKSPACE, not to the command: under this mode a command that only reads',", "    'A command that only reads should still work, so start with one of those:',"]],
  },
  {
    name: 'the advisory asserts one producer instead of enumerating the measured two',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    'Two producers have been measured under a confining Windows mode. Check which one this is:',", "    'This was an MSYS2 program:',"]],
  },
  {
    // 0.9.0's first addition: #8272 read the skill's name in a README while
    // running 0.1.7-rc.2 and reported a dropped `files` entry. Measuring both
    // published tarballs shows the skill is new in 0.2.0, so an advisory that
    // sends the reader to repair a packaging glob sends them to the wrong repair.
    name: 'the skill boundary is stated as a dropped packaging entry instead of a later line',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    'dropped from the `0.1.7` file list, because there was nothing in `0.1.7` to drop.',", "    'dropped from the `0.1.7` file list, so upgrade or repair the glob to get it back.',"]],
  },
  {
    // 0.9.0's second addition: #8275 reads the label as a layer that can be
    // declined. The token is lowered to Low too, and the object's Low label is
    // what lets that child write — an advisory that calls the label independent
    // hands the reader a degradation that leaves the workspace unwritable.
    name: 'the label is presented as an independent layer that can be declined alone',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '  not leave a working workspace: the backend lowers the confined token to Low before any child starts, and its',", "    '  not leave a working workspace: the label is an independent second layer of defence, and the backend\\'s',"]],
  },
  {
    name: 'the weaker-grant section is emitted for every class instead of the one it is about',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    ...(failure.klass === 'apply-denied' ? [...degradedGrant(), ''] : []),", "    ...degradedGrant(),"]],
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
