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
    edits: [[
      "    'The creation flags this harness actually passes are three sets and none of them is `CREATE_NO_WINDOW` —',",
      "    'The creation flags this harness actually passes are two sets and none of them is `CREATE_NO_WINDOW` —',",
    ], [
      "    '`0` on the piped path, `CREATE_SUSPENDED` on the inherited-job path, and',",
      "    '`CREATE_SUSPENDED` on the inherited-job path, and',",
    ]],
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
    name: 'the advisory asserts one producer instead of enumerating the measured three',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    'Three producers have been measured under a confining Windows mode. Check which one this is:',", "    'This was an MSYS2 program:',"]],
  },
  {
    // 0.16.0's addition: #9186's producer is the restricting list, and the one
    // check a reader can run is the mode switch. An advisory that asserts the
    // producer instead of handing over that comparison removes the only
    // discriminator the status code does not already supply.
    name: 'the restricting-list producer is asserted rather than handed over as a mode switch',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '     CHECK: hold the command and the tool fixed and change only the MODE. If `read-only` starts the command',", "    '     This is producer 3, the restricting list, so the mode is not worth comparing any further.',"]],
  },
  {
    // The same producer's honesty boundary: the code runs in BOTH directions, so
    // a text that says the code names its own direction is a confident wrong
    // cause for the one question the report could not answer.
    name: 'the code is said to name its own direction, so too-few and too-many entries read alike',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    'cannot tell you which mistake was made. Only a comparison can, and the cheapest one is producer 3\\'s mode',", "    'cannot tell you which mistake was made, but the status code already tells you it was too many, so producer 3\\'s mode',"]],
  },
  {
    // The cause the report's own control arm retires. Leaving it in place sends
    // pure-native programs' readers to a runtime that has nothing to do with it.
    name: 'the .NET self-contained cause is left standing instead of retired by the control arm',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '     One thing this is NOT: `.NET`. Pure-native programs die here identically, so the \"self-contained .NET',", "    '     One thing this is NOT: a missing runtime. The \"self-contained .NET runtime\" cause the reports found',"]],
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
  {
    // 0.10.0's first addition: #8312 reports the other end of the same backend.
    // The grant is not a per-session effect — an advisory that reads as if the
    // harness takes it back when it exits sends the reader past the one fact the
    // reports could only learn from a broken build in another project.
    name: 'the grant reads as temporary, as if the harness took it back on exit',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '  The three entries are STANDING, deliberately, and nothing revokes them. The workspace grant is a reuse cache:',", "    '  The three entries are removed when the harness exits. The workspace grant is a reuse cache:',"]],
  },
  {
    name: 'the advisory ships a removal command for the label it cannot remove',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    '  WRITE_OWNER — the same right this whole failure is about. This advisory hands over no removal command: the',", "    '  WRITE_OWNER — the same right this whole failure is about. Remove it with `icacls \"<dir>\" /setintegritylevel',"]],
  },
  {
    name: 'the persistent-shell failure is called intermittent instead of deterministic per mode and host',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [["    'Which sessions fail inside that combination is not chance — it is deterministic per (session mode × the host',", "    'Which sessions fail inside that combination looks like chance — it comes and goes, an intermittent flake whose host',"]],
  },
  {
    // The bundle patch is published prose with no compiler over it: the release
    // that added threads to the second and third families updated the advisory and
    // the manifest and left this file describing three families as two, because
    // the only assertion on it was that it exists and names the package. This arm
    // keeps the new assertion honest.
    name: 'the mount instructions drop one of the second family\'s threads',
    file: 'cordis.patch.yml',
    arms: 'packaging.spec.mjs',
    edits: [['(#7638, #8322, #9170)', '(#8322, #9170)']],
  },
  {
    // The third family's own new threads: 0.16.0 added three reports to the
    // advisory and this prose has no compiler over it, so the same arm that keeps
    // the second family honest has to cover the new ones too.
    name: 'the mount instructions drop the third family\'s newest threads',
    file: 'cordis.patch.yml',
    arms: 'packaging.spec.mjs',
    edits: [['#8334, #8990, #8991, #9186):', '#8334):']],
  },
  {
    // Both of the fourth family's threads, not only the first: the family gained a
    // second report, and a patch that names one of them describes a smaller family
    // than the plugin covers. Every mention has to go — the id is cited twice, so
    // removing one of them still leaves the patch naming the thread and reads
    // SILENT (measured in this round's first version of the arm).
    name: 'the mount instructions drop the fourth family\'s second thread',
    file: 'cordis.patch.yml',
    arms: 'packaging.spec.mjs',
    edits: [
      ["the FIRST one's backend (#423, #8383,", "the FIRST one's backend (#423,"],
      ["the LABEL branch (#8383, second instance #8421; measured on", "the LABEL branch (second instance #8421; measured on"],
    ],
  },
  {
    // 0.11.0's family is the only Windows-only one that cannot drop its platform
    // gate: what it explains is ACE inheritance, and the same stamped value on a
    // Landlock/Seatbelt/bwrap host is a different story with no missed
    // propagation to repair.
    name: 'the workspace-denial classifier drops its platform gate',
    file: 'src/signature.ts',
    arms: 'signature.spec.mjs',
    edits: [["  if (facts.platform !== 'win32') return undefined", '  /* the platform is not checked */']],
  },
  {
    name: 'the Windows fact is checked after the policy lookup, so every host pays for a family it cannot have',
    file: 'src/index.ts',
    arms: 'workspace-denial.spec.mjs',
    edits: [['if (process.platform === \'win32\' && hasWorkspaceDenialStamp(result.value)) {', 'if (hasWorkspaceDenialStamp(result.value)) {']],
  },
  {
    name: 'a denial is read from any mode, so a read-only refusal is advised as a broken grant',
    file: 'src/signature.ts',
    arms: 'signature.spec.mjs',
    edits: [['  return mode === DENIAL_MODE && denied === true && runnerFailed !== true', '  return denied === true && runnerFailed !== true']],
  },
  {
    // The executor refuses to call a run denied when the runner itself failed, and
    // this plugin must refuse it too: advising a missing inherited grant there
    // would name a cause the value explicitly excludes.
    name: 'the runner-failure exclusion is dropped, so a broken runner reads as a broken grant',
    file: 'src/signature.ts',
    arms: 'workspace-denial.spec.mjs',
    edits: [['  return mode === DENIAL_MODE && denied === true && runnerFailed !== true', '  return mode === DENIAL_MODE && denied === true']],
  },
  {
    // The narrowing that separates this family from the SANCTIONED escalation
    // path: a denial of a path outside the workspace is the sandbox working.
    name: 'the containment test is dropped, so the designed escalation path is advised as a broken grant',
    file: 'src/signature.ts',
    arms: 'workspace-denial.spec.mjs',
    edits: [['  if (!named.every(path => isInsideWorkspace(facts.workspaceRoot, path))) return undefined', '  /* containment is not checked */']],
  },
  {
    // The disclosure rule: a root the resolver cannot report is a decision the host
    // log has to account for, or silence reads as "the sandbox is not the cause".
    name: 'an unresolvable workspace root is withheld silently instead of disclosed',
    file: 'src/index.ts',
    arms: 'workspace-denial.spec.mjs',
    edits: [["    if (!resolution.ok) return withhold(agent, previous, resolution.withheld, 'workspace-denial')", '    if (!resolution.ok) return undefined']],
  },
  {
    // The discriminator's second half, which a check on the ACE alone gets wrong.
    name: 'the two-sided reachability rule is replaced by a single-sided one',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    '  THE TRAP: reading and listing go through the NORMAL token, writing and deleting through the RESTRICTED',",
      "    '  The check is done when `icacls` shows the capability SID, because reading and listing go through the NORMAL',",
    ]],
  },
  {
    // The fork, which is the only thing that makes two indistinguishable halves
    // actionable: breadth is the one fact the reader already owns, and without it
    // a reader repairs the DACL of a label-starved workspace and learns nothing.
    name: 'the breadth fork is dropped, so both halves read as one failure',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    '  - A HANDFUL of stubborn objects while the rest of the tree writes normally → the DACL half. The capability ACE',\n"
      + "    '    did not arrive at those objects; the workspace is otherwise usable. This is the #423 measurement.',\n"
      + "    '  - NOTHING below the root is writable at all, with the root itself the only writable place → the LABEL half',",
      "    '  - Some objects stay stubborn while the rest of the tree writes normally; the capability ACE did not arrive at',\n"
      + "    '    those. Everything below is about that half.',",
    ]],
  },
  {
    // From inside a session the DACL miss and the label miss are
    // indistinguishable, and a reader who repairs the wrong half has learned
    // nothing — so the second branch cannot be dropped back to a footnote.
    name: 'the label half is demoted back to a footnote, leaving the DACL as the whole failure',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    'Half two — the DACL arrived and the LABEL did not (#8383, measured 2026-09-30):',",
      "    'There is nothing else to check here: the DACL half is the whole of this failure.',",
    ]],
  },
  {
    // The label half's permanence, which is the same root-only short-circuit on
    // the other half of the same call. The claim is a statement about the
    // backend, so the mechanism and its check names have to be in the text.
    name: 'the label half loses its permanence mechanism, so it reads as a transient miss',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    '  Why it is permanent: the label goes out in the same single security-descriptor write that carries the grant,',\n"
      + "    '  with the inheritance flag set, but only on the paths the backend enumerates — the workspace root (plus the',\n"
      + "    '  session\\'s private temp directory), with no descendant walk. The root-only idempotency check then requires the',\n"
      + "    '  grant, the world delete-child deny AND the exact label (`hasExactGrant()` + `hasExactDeny()` + `hasExactLabel()`',\n"
      + "    '  all matching) before it returns early, so once the root is labelled the propagation is never attempted again and',\n"
      + "    '  the children that missed it are never revisited — the same root-only short-circuit as the DACL half, on the',\n"
      + "    '  other half of the same call (`packages/sandbox/sandbox-windows-acl/src/acl.ts`: the guard at :386-388, the',\n"
      + "    '  label read at :198-204). A second report met this same half afterwards (#8421): the label written on the root',\n"
      + "    '  alone, the pre-existing subdirectories carrying none of it. That is why this branch is stated as a shape this',\n"
      + "    '  backend produces rather than as one machine\\'s result.',",
      "    '  Why it is permanent: the label is applied to the workspace root and the children are expected to inherit it.',",
    ]],
  },
  {
    // The one form of the measurement that decides it. A grandchild proves
    // nothing — inheritance is per-parent — and a text that accepts one would be
    // inviting the reader to confirm the branch with evidence that cannot.
    name: 'the decisive control is weakened to any descendant, so a grandchild reads as evidence',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    '  keeping: a GRANDCHILD directory having no label proves nothing on its own, because inheritance is per-parent and',\n"
      + "    '  the intermediate directory carries none — only a DIRECT child of the labelled root is evidence.',",
      "    '  keeping: any directory below the root that carries no label is evidence of this half.',",
    ]],
  },
  {
    // The 0.5.0 precedent: an unverified repair command is the defect this plugin
    // exists to answer, and this family has no Windows host behind it at all.
    name: 'the advisory ships the repair command it says it cannot verify',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    '  No repair command is printed here on purpose. This project has no Windows host to verify one on, and shipping',",
      "    '  Repair it from an elevated prompt: `icacls \"<dir>\" /grant \"<account>:(OI)(CI)F\"`. This project has no Windows host to verify one on, and shipping',",
    ]],
  },
  {
    // 0.11.0's conclusion, restored. It is the specific sentence a reader would
    // use to rule `CREATE_NO_WINDOW` out, so the guard has to bite on it even
    // though the surrounding rule survives.
    name: 'the withdrawn conclusion is restored, so the flag list reads as never decisive',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    'a console, so there the console decides. A flag that forces creation is a different animal: it decides even',",
      "    'a console, so it is the console and not the flag list that decides. A flag that forces creation is a different animal: it decides even',",
    ]],
  },
  {
    // The matrix is the whole reason the sentence above was wrong: without the two
    // fatal flags named, the rule has no counterexample and reads as a restatement
    // of what 0.11.0 already said.
    name: 'the #8336 matrix is dropped, leaving the rule without the case that falsifies the old sentence',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    'Low integrity level, varying only the creation flags: `0`, `DETACHED_PROCESS` and `CREATE_NEW_PROCESS_GROUP`',\n    'all reached the program, while `CREATE_NO_WINDOW` and `CREATE_NEW_CONSOLE` both died with the code above.',",
      "    'Low integrity level, varying only the creation flags: some reached the program and some did not.',",
    ]],
  },
  {
    // The suspicion the reports actually reach for. Answering it is the point;
    // dropping the answer restores the silence that made the reports guess.
    name: 'the windowsHide answer is dropped, so the suspicion the reports reach for goes unanswered',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    'One thing that gets suspected and is not the cause: `windowsHide`. It is named here because it is the',",
      "    'A note on other flags is omitted here because it is not the cause: `windowsHide`. It is named here because it is the',",
    ]],
  },
  {
    // The mis-attribution itself: naming `dsh-jobs` is what the reports did, and
    // the advisory must never repeat it as the place the flag lives.
    name: 'the windowsHide site is moved to the component the reports blamed',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    'confined path above. It appears on the ORDINARY subprocess path (`dsh-subprocess-local`: `windowsHide:`',",
      "    'confined path above. It appears in the job runner (`dsh-jobs`: `windowsHide:`',",
    ]],
  },
  {
    // 0.14.0's first addition. The third branch is the only cell of the fourth
    // family whose cause is not a missed propagation and whose remedy is not a
    // repair: a text that stops at the two halves sends a reader whose ROOT is
    // refused to repair descendants that were never the problem.
    name: 'the third breadth branch is dropped, so a refused ROOT reads as one of the propagation halves',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    '  - THE ROOT ITSELF IS REFUSED — nothing writes, the root included, and work that used to succeed here now',\n"
      + "    '    does not → NEITHER half above (#8409). The standing grant is gone from the root\\'s own DACL, and the layer',\n"
      + "    '    that would put it back has stopped looking. Two things about this branch are different in kind from the',\n"
      + "    '    other two: no command reaches it, and it is the one branch of this family with a recovery inside the',\n"
      + "    '    product — both are in half three below.',",
      "    '  - Anything else you see is one of those two; there is no third shape to consider.',",
    ]],
  },
  {
    // The layer the reporter could not see: without it the branch reads as the
    // backend forgetting to re-check the DACL, which is a different (and wrong)
    // repair target — the idempotency check the other two branches turn on is not
    // what is being consulted here.
    name: 'the provider-lifetime map is replaced by the backend\'s own check',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    '  materializes the root ACE ONCE PER PROVIDER LIFETIME and keeps that root in its own in-memory map; every later',\n"
      + "    '  call consults the map and never reads the DACL again, so the exact-ACE check the two halves above turn on is',\n"
      + "    '  not even reached (`packages/sandbox/sandbox-local/src/index.ts`: the guard at :403-421, \"materializes once per',\n"
      + "    '  workspace per server lifetime\" at :359, and the standing edits it skips are called the \"cross-session reuse',\n"
      + "    '  cache\" in `packages/sandbox/sandbox-windows-acl/src/grant.ts:22-31`). The runner path used by agentless',",
      "    '  checks the root again on every call, so the exact-ACE check the two halves above turn on is what decides',\n"
      + "    '  here (`packages/sandbox/sandbox-windows-acl/src/acl.ts`). The runner path used by agentless',",
    ]],
  },
  {
    // The recovery, which is the whole reason this branch is worth separating: it
    // is the user's move and it is the provider, not a command run in the session.
    name: 'the third branch loses its recovery, so the root-refused cell reads as unrepairable',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    '  RECOVERY: this is the only branch of this family a user can leave behind, and the move is the PROVIDER rather',\n"
      + "    '  than a command. RESTART IT — quit and reopen the desktop app, or open the workspace in a fresh one. That',\n"
      + "    '  empties the map, so the next provision reads the DACL, finds the ACE absent and writes it again; the reporter',\n"
      + "    '  measured exactly that (\"restarting the desktop brings it back\"). Nothing reachable from inside this session',",
      "    '  There is no recovery here: this branch is as permanent as the two above and no user action short of a',\n"
      + "    '  reinstall reaches the layer holding the answer. Nothing reachable from inside this session',",
    ]],
  },
  {
    // The citation the label half's second instance hangs on — the branch is a
    // shape this backend produces, and dropping the second report turns it back
    // into one machine's result.
    name: 'the label half drops its second instance and reads as a single machine\'s result',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    '  label read at :198-204). A second report met this same half afterwards (#8421): the label written on the root',",
      "    '  label read at :198-204).',",
    ]],
  },
  {
    // 0.14.0's second addition. The confirmation is evidence for the class whose
    // diagnosis is the missing right; attaching it to a class that never
    // established that right is the failure mode this module is built to avoid.
    name: 'the independent confirmation is emitted for every class instead of the one it is about',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    ...(failure.klass === 'apply-denied' ? writeOwnerEvidence() : []),",
      '    ...writeOwnerEvidence(),',
    ]],
  },
  {
    // What the evidence is evidence OF. A measurement that reads as a token
    // privilege hands the reader back the hypothesis the whole module refuses.
    name: 'the independent confirmation is re-read as a token privilege',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    'SeRelabelPrivilege, no token privilege, no elevation anywhere in that measurement. (That probe is not printed',",
      "    'SeRelabelPrivilege on the account is what it really wants, as the elevation-free result above suggests. (That probe is not printed',",
    ]],
  },
  {
    // The decision the module records in its own prose: the probe is quoted in the
    // README and must not be handed to the model, because a label write is not a
    // read — it succeeds where the caller holds Full control, and then the label
    // and its inheritance are already written.
    name: 'the label-write probe the module refuses to hand over is published in the advisory',
    file: 'src/advice.ts',
    arms: 'signature.spec.mjs',
    edits: [[
      "    'here and is not offered as a check: a label write is not a read — where the caller already holds Full control',",
      "    'here: run `icacls \"<dir>\" /setintegritylevel \"(OI)(CI)Low\"` to see it for yourself — where the caller already holds Full control',",
    ]],
  },
  {
    // The mount instructions are published prose with no compiler over them, and
    // 0.14.0 added a branch and a thread to them. Dropping the newest id leaves a
    // patch that describes a smaller family than the advisory covers.
    name: 'the mount instructions drop the fourth family\'s third branch and its thread',
    file: 'cordis.patch.yml',
    arms: 'packaging.spec.mjs',
    edits: [
      ['# A FOURTH family is the other half of the FIRST one\'s backend (#423, #8383,\n# #8421, #8409).', '# A FOURTH family is the other half of the FIRST one\'s backend (#423, #8383,\n# #8421).'],
      ['THE ROOT ITSELF REFUSED, nothing writable, not even the root', 'A third shape of the same denial'],
      ['restart the desktop\n#     app or open the workspace in a fresh one', 'upgrade the harness\n#     or open the workspace in a fresh one'],
    ],
  },
  {
    // The first family's new thread in the same published surface.
    name: 'the mount instructions drop the independent confirmation and its thread',
    file: 'cordis.patch.yml',
    arms: 'packaging.spec.mjs',
    edits: [[
      '#   - the missing right confirmed from outside (#8426): asking a directory that',
      '#   - one more fact about the missing right: asking a directory that',
    ]],
  },
  {
    // 0.15.0's family. The operands ARE the recognition: the assertion's sentence
    // alone is what a log line, a transcript or a pasted issue body carries, and
    // advising about the sandbox there would be advice about the wrong thing. The
    // message is the only input — the containment it implies is never recomputed —
    // so a match with no operands has nothing to say and must be refused.
    name: 'the temp-root recognition accepts the sentence alone, with no operands',
    file: 'src/signature.ts',
    arms: 'temp-root.spec.mjs',
    edits: [['if (workspaceRoot.length === 0 || tempRoot.length === 0) return undefined', '/* the operands are not required */']],
  },
  {
    // The two carriers fire at different moments and only one of them has
    // anything on stderr; collapsing them makes `#9175`'s two-producer fact
    // unreadable exactly where a maintainer needs it.
    name: 'the two producers collapse into one, so the runner refusal reads as the provider',
    file: 'src/signature.ts',
    arms: 'temp-root.spec.mjs',
    edits: [["const carrier: TempRootCarrier = line.includes(RUNNER_SIGNATURE) ? 'runner' : 'pre-spawn'", "const carrier: TempRootCarrier = 'pre-spawn'"]],
  },
  {
    // The invariant is a Windows ACL capability pair; on Landlock/Seatbelt/bwrap
    // the same two paths are ordinary directories and the claim would be a
    // prediction from a mechanism the host does not have.
    name: 'the pre-flight platform gate is dropped, so every host is told its commands cannot start',
    file: 'src/temp-root.ts',
    arms: 'temp-root.spec.mjs',
    edits: [["  if (facts.platform !== 'win32') return false", '  /* the platform is not checked */']],
  },
  {
    // `read-only` materializes no private temp capability, so the assertion is
    // never reached there and the condition does not exist to report.
    name: 'the pre-flight mode gate is dropped, so a read-only session is warned about a capability it does not have',
    file: 'src/temp-root.ts',
    arms: 'temp-root.spec.mjs',
    edits: [['  if (facts.mode !== PREFLIGHT_MODE) return false', '  /* every mode is treated alike */']],
  },
  {
    // The canonical comparison is the whole value of the prediction: a string
    // prefix disagrees with the executor on a sibling whose name extends the
    // root's, which is the shape a naive test gets wrong.
    name: 'the containment test degrades to a string prefix, so a sibling of the root reads as inside it',
    file: 'src/temp-root.ts',
    arms: 'temp-root.spec.mjs',
    edits: [[
      "  return relation === '' || (!isAbsolute(relation) && relation !== '..' && !relation.startsWith(`..${sep}`))",
      '  return realpathSync.native(candidate).startsWith(realpathSync.native(root))',
    ]],
  },
  {
    // The platform fact comes first so no host pays for a family it cannot have,
    // and so the question is never asked off Windows — where it cannot arise.
    name: 'the pre-flight platform fact is checked after the policy lookup, so every host pays for it',
    file: 'src/index.ts',
    arms: 'temp-root.spec.mjs',
    edits: [["  if (process.platform !== 'win32') return { ok: false, why: 'clear' }", '  /* the host is not consulted */']],
  },
  {
    // The one thing this family must never do: a refusal that precedes any
    // process is not an ACL problem, and a grant line is advice for a problem the
    // reader does not have — the same defect §1's standing-grant section refuses.
    name: 'the temp-root advisory ships a grant command for a refusal that precedes any process',
    file: 'src/advice.ts',
    arms: 'temp-root.spec.mjs',
    edits: [[
      "    '  This is not an ACL problem and no `icacls` grant fixes it: the refusal happens while the sandbox is',",
      "    '  Fix it with `icacls \"<dir>\" /grant \"<account>:(OI)(CI)F\"`: the refusal happens while the sandbox is',",
    ]],
  },
  {
    // The remedy is the environment, and `%TMP%` is the lever the reader has to
    // be handed: `GetTempPathW` reads it first. Naming a variable the platform
    // does not read gives the reader a change that does nothing — the exact
    // "diagnosis with no path forward" this plugin exists to remove.
    name: 'the temp-root remedy names a variable the platform does not read',
    file: 'src/advice.ts',
    arms: 'temp-root.spec.mjs',
    edits: [[
      "    '       cmd:         set TMP=C:\\\\dsh-temp        (then start the harness from that same prompt)',",
      "    '       cmd:         set DSH_TMP=C:\\\\dsh-temp     (then start the harness from that same prompt)',",
    ]],
  },
  {
    // The mount instructions are published prose with no compiler over them, and
    // this family's only thread is the report the whole section exists for.
    name: 'the mount instructions drop the fifth family\'s thread',
    file: 'cordis.patch.yml',
    arms: 'packaging.spec.mjs',
    edits: [['# A FIFTH family is a pre-spawn refusal with no ACL in it at all (#9175): the', '# A FIFTH family is a pre-spawn refusal with no ACL in it at all: the']],
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
