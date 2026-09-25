/**
 * Signature recognition and advisory text — the pure arms.
 *
 * The strings asserted here are the producer's, not this plugin's invention:
 * `Win32Error` (`packages/subprocess/win32-process/src/errors.ts`) formats every
 * failure as `` `${api} failed (Win32 ${code}): ${detail}` ``, and the ACL
 * backend throws it from `acl.ts` with `detail = grantWrite(<path>)`. Pinning
 * the shape in the test is what makes a future change on the producer side
 * visible as a failure here rather than as silence in a user's session.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  advisoryText,
  denialText,
  ACL_DISCUSSIONS,
  NATIVE_INIT_DISCUSSIONS,
  PREREQUISITE,
  PTY_DISCUSSIONS,
} from '../lib/advice.js'
import {
  classifyNativeInitDeath,
  classifyProvisioningFailure,
  classifyPtyStartupFailure,
  failureLine,
  STATUS_DLL_INIT_FAILED,
} from '../lib/signature.js'
import { foreground, MSYS2_STDERR, NATIVE_DEATH } from './foreground.mjs'

/** The exact text reported in #7538 / #7622 / #7646. */
const REPORTED = 'SetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'

test('the reported signature is recognized, with every producer field kept', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure, 'the reported string must classify')
  assert.equal(failure.klass, 'apply-denied')
  assert.equal(failure.api, 'SetNamedSecurityInfoW')
  assert.equal(failure.win32Code, 5)
  assert.equal(failure.detail, 'grantWrite(D:\\ws)')
  assert.equal(failure.label, 'grantWrite')
  assert.equal(failure.path, 'D:\\ws')
})

test('recognition survives the framing a tool result adds', () => {
  for (const wrapped of [
    `Error: ${REPORTED}`,
    `bash failed with exit code 1\nError: ${REPORTED}\nsee log`,
    `[provider] ${REPORTED}`,
  ]) {
    const failure = classifyProvisioningFailure(wrapped)
    assert.ok(failure, `wrapped text must classify: ${wrapped}`)
    assert.equal(failure.path, 'D:\\ws')
  }
})

test('a failure with no detail still classifies, without inventing a path', () => {
  const failure = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 5)')
  assert.ok(failure)
  assert.equal(failure.detail, '')
  assert.equal(failure.label, undefined)
  assert.equal(failure.path, undefined)
  assert.equal(failureLine(failure), 'SetNamedSecurityInfoW failed (Win32 5)')
})

test('the read half and a non-ACCESS_DENIED code are their own classes', () => {
  const read = classifyProvisioningFailure('GetNamedSecurityInfoW failed (Win32 5): grantWrite(C:\\ws)')
  assert.equal(read?.klass, 'read-denied')
  const other = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 1332): grantWrite(D:\\ws)')
  assert.equal(other?.klass, 'apply-other')
  assert.equal(other?.win32Code, 1332)
})

test('failures this plugin must NOT explain are refused, not guessed at', () => {
  // `SetEntriesInAclW` merges entries in process memory: no object, no rights.
  // Advising an ACL fix there would send a user to change the wrong thing.
  for (const message of [
    'SetEntriesInAclW failed (Win32 8): grantWrite(D:\\ws)',
    'LocalFree failed (Win32 6): grantWrite(D:\\ws) descriptor',
    'LockFileEx failed (Win32 33): C:\\lock',
    'SetConsoleCtrlHandler failed (Win32 6)',
    'SetEnvironmentVariableW TMP failed (Win32 5)',
    'Error: EACCES: permission denied, open \'/etc/hosts\'',
    'bash: command not found: icacls',
    'XSetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)',
  ]) {
    assert.equal(classifyProvisioningFailure(message), undefined, `must not classify: ${message}`)
  }
})

test('failureLine reproduces the producer format exactly', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  assert.equal(failureLine(failure), REPORTED)
})

test('the advisory names the right that is actually missing, and the wrong lever', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // The line the user is staring at, quoted verbatim.
  assert.match(text, /SetNamedSecurityInfoW failed \(Win32 5\): grantWrite\(D:\\ws\)/)
  // The missing right and the mask that lacks it. The remedy lines themselves are
  // pinned by the dedicated arm below, which asserts the form actually recommended.
  assert.match(text, /WRITE_OWNER/)
  assert.match(text, /0x1301bf/)
  // The natural-but-wrong hypothesis is addressed rather than ignored.
  assert.match(text, /SeSecurityPrivilege is the wrong lever/)
  assert.match(text, /whoami \/priv/)
  // The documented prerequisite, the upstream threads, and the boundary.
  assert.match(text, new RegExp(PREREQUISITE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.match(text, new RegExp(ACL_DISCUSSIONS.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.match(text, /neither edits ACLs nor elevates/)
})

test('the remedy is the right the prerequisite actually names, and the broad form is offered second', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // The narrow grant: WRITE_OWNER alone, which is what the backend documents —
  // it is the same right the diagnosis named, so the reader can see the one-liner
  // and the explanation are about the same thing.
  assert.match(text, /icacls "D:\\ws" \/grant "\$env:USERNAME:\(OI\)\(CI\)\(WO\)"/)
  assert.match(text, /icacls "D:\\ws" \/grant "%USERNAME%:\(OI\)\(CI\)\(WO\)"/)
  assert.match(text, /exactly the right the prerequisite names/)
  // ...and the inheritable form, so one command reaches existing subdirectories.
  assert.match(text, /\(OI\)\(CI\) makes the ACE inheritable/)
  // Full control still works, and saying so is not a second recipe but the same
  // remedy with more than it needs — hence the derivation, not a second syntax pair.
  assert.match(text, /Full control works just as well — the same line with `F` in place of `\(WO\)`/)
  assert.match(text, /icacls "D:\\ws" \/grant "\$env:USERNAME:\(OI\)\(CI\)F"/)
  // The condition under which the one-liner is enough is stated, not assumed:
  // owner-implicit rights cover the DACL half, and the caller owns the directory
  // in the environments this branch describes. Where the caller does not own it,
  // the advisory branches instead of pretending the condition holds.
  assert.match(text, /an owner holds READ_CONTROL and WRITE_DAC implicitly/)
  assert.match(text, /WRITE_OWNER is the single missing piece/)
  // The order is the claim: the narrow form is the one being recommended.
  assert.ok(
    text.indexOf('(WO)') < text.indexOf('(OI)(CI)F'),
    'the narrow grant must be offered before the broad one, not after it',
  )
})

test('both environments that share this signature are named, because the text cannot tell them apart', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // #7622 / #7646 / #7720: an inherited Modify-only entry.
  assert.match(text, /Authenticated Users: Modify" \(`0x1301bf`\) from the drive root/)
  // #7750 / #7735: a data volume where that inherited entry is all the caller has.
  assert.match(text, /on a data\s+volume there may be no ACE naming you at all/)
  assert.match(text, /that inherited entry is the whole of your access/)
  // And why a refused label costs execution, not just a label: one merged call,
  // atomically rejected, fail-closed.
  assert.match(text, /halves go out as one call, so a refused label discards the write grant/)
  assert.match(text, /refuses to start any command in the workspace instead of running it unconfined/)
  // The discriminator covers both shapes — no ACE naming you is still this failure.
  assert.match(text, /no entry names you at all and/)
})

test('the version boundary the error does not carry is stated, with the build and the flag', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // Where the label arrives — the fact neither report could read off the error.
  assert.match(text, /the label half is new to this package/)
  assert.match(text, /Up to `0\.1\.6-alpha\.x` the backend touched the DACL only \(flag 4\)/)
  assert.match(text, /`0\.1\.7-alpha\.1` is where the mandatory label/)
  assert.match(text, /with it the SACL, flag 20/)
  // It is a *discriminator*: the same string on an older line is another story.
  assert.match(text, /belongs to a different cause space/)
  assert.match(text, /on any\s+`0\.1\.7-\*` line it is this one/)
  // And the reach it invites is refused with the reason: the label is the fix
  // for out-of-workspace deletion, so downgrading trades one defect for another.
  assert.match(text, /Rolling back is not the fix either/)
  assert.match(text, /reverting it reintroduces the escape it closed/)
})

test('the version boundary is emitted in every class this module speaks in', () => {
  // The boundary is a fact about the backend's flag, not about which of its calls
  // failed, so withholding it in the other two classes would hide it exactly where
  // a user is most likely to reach for an older build.
  for (const message of [
    REPORTED,
    'SetNamedSecurityInfoW failed (Win32 1332): grantWrite(D:\\ws)',
    'GetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)',
  ]) {
    const text = advisoryText(classifyProvisioningFailure(message))
    assert.match(text, /0\.1\.7-alpha\.1/, `the boundary must be present for: ${message}`)
    assert.match(text, /Rolling back is not the fix either/, `the boundary's second half must be present for: ${message}`)
  }
})

test('an href replaces the thread line without dropping the fix', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure, { href: 'https://example.invalid/t/1' })
  assert.match(text, /tracked upstream: https:\/\/example\.invalid\/t\/1/)
  assert.match(text, /WRITE_OWNER/)
})

test('the two remedies that look right and are not are named, with the reason each fails', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // Both came from #7720, quoted with the directory the error named.
  assert.match(text, /takeown \/F "D:\\ws" \/R \/D Y/)
  assert.match(text, /icacls "D:\\ws" \/reset \/T \/C/)
  // The reasons are different, and each is the fact that makes the command fail:
  // the owner's implicit rights, and what `/reset` puts back.
  assert.match(text, /ownership's implicit rights are READ_CONTROL and WRITE_DAC only/)
  assert.match(text, /still not WRITE_OWNER, the right this call needs/)
  assert.match(text, /restores inheritance, and inheritance is what supplied the Modify-only ACE/)
  // Both are still promised as *not* the fix, never as the remedy. `takeown` is
  // claimed to fail only as a complete fix — it is a real first step with
  // elevation where the caller is not the owner, and denying that would be the
  // mirror-image error.
  assert.match(text, /What will NOT fix it on its own/)
  assert.match(text, /it is never the fix by itself/)
})

test('the remedy forks on ownership, because one command cannot serve both environments', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure)
  // The branch selector is a check the user runs, not a guess: the text is
  // identical in both environments, so the advisory cannot pick a branch for
  // them — it hands over the ownership read instead.
  assert.match(text, /Ownership decides which of the two commands below can work/)
  assert.match(text, /\(Get-Acl "D:\\ws"\)\.Owner/)
  assert.match(text, /compare with: whoami/)
  assert.match(text, /the first one is refused before it runs/)
  // Branch one: the caller owns it, and the narrow grant runs unelevated.
  assert.match(text, /IF YOU OWN THE DIRECTORY/)
  assert.match(text, /an owner holds READ_CONTROL and WRITE_DAC implicitly/)
  assert.match(text, /WRITE_DAC is what `icacls \/grant` itself needs/)
  // Branch two: an owner that is not the caller — `#7771`'s shape.
  assert.match(text, /IF YOU DO NOT OWN IT/)
  assert.match(text, /`BUILTIN\\Administrators`/)
  assert.match(text, /Changing a DACL takes WRITE_DAC/)
  assert.match(text, /`icacls \/grant` is refused with `Access is denied` — for the very command that would/)
  assert.match(text, /so `\(WO\)` alone would not be enough/)
  // ...and the path out of it: elevation, the two reaches the reports name, and
  // the sidestep that needs no ACL edit at all.
  assert.match(text, /ELEVATED prompt/)
  assert.match(text, /icacls "D:\\ws" \/grant "<your-account>:\(OI\)\(CI\)F"/)
  assert.match(text, /icacls "D:\\ws" \/setowner "<your-account>"/)
  assert.match(text, /it wants SeTakeOwnership/)
  assert.match(text, /after which the unelevated/)
  assert.match(text, /create the workspace under `%USERPROFILE%`/)
  // The fork is a fork: the owner branch is offered as branch one, so the narrow
  // unelevated line still comes before any elevated command.
  assert.ok(
    text.indexOf('IF YOU OWN THE DIRECTORY') < text.indexOf('IF YOU DO NOT OWN IT'),
    'the owner branch must come first — it is the environment the reports describe most often',
  )
})

test('the non-fix section is emitted only where its claim is true', () => {
  // `read-denied` wants READ_CONTROL, which taking ownership does carry — so the
  // section would be false there, not merely unhelpful.
  const read = advisoryText(classifyProvisioningFailure('GetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'))
  assert.doesNotMatch(read, /takeown/)
  assert.doesNotMatch(read, /reset \/T \/C/)
  assert.doesNotMatch(read, /What will NOT fix it/)
  // `apply-other` says the missing-rights story does not apply verbatim, so a
  // section presupposing it would contradict the paragraph above it.
  const other = advisoryText(classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 1332): grantWrite(D:\\ws)'))
  assert.doesNotMatch(other, /takeown/)
  assert.doesNotMatch(other, /What will NOT fix it/)
})

test('the non-fix section follows the placeholder rule too', () => {
  const failure = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 5)')
  assert.ok(failure)
  const text = advisoryText(failure)
  assert.match(text, /takeown \/F "<the directory from the error line above>" \/R \/D Y/)
  assert.doesNotMatch(text, /takeown \/F ""/)
})

test('each class explains itself instead of borrowing another class\'s story', () => {
  const denied = advisoryText(classifyProvisioningFailure(REPORTED))
  const other = advisoryText(classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 1332): grantWrite(D:\\ws)'))
  const read = advisoryText(classifyProvisioningFailure('GetNamedSecurityInfoW failed (Win32 5): grantWrite(D:\\ws)'))
  assert.notEqual(denied, other)
  assert.notEqual(denied, read)
  assert.match(other, /not ERROR_ACCESS_DENIED \(5\)/)
  assert.doesNotMatch(other, /MERGED write — the DACL/)
  assert.match(read, /could not even read the directory's security descriptor/)
  assert.doesNotMatch(read, /MERGED write — the DACL/)
})

test('a failure with no path hands the user a placeholder, not a broken command', () => {
  const failure = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 5)')
  assert.ok(failure)
  const text = advisoryText(failure)
  assert.match(text, /icacls "<the directory from the error line above>"/)
  assert.doesNotMatch(text, /icacls ""/)
})

test('the denial says what happened, how bounded it is, and what to do', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const first = denialText(failure, 2, 1, 2)
  assert.match(first, /already failed 2 times/)
  assert.match(first, /SetNamedSecurityInfoW failed \(Win32 5\): grantWrite\(D:\\ws\)/)
  assert.match(first, /automatic block 1 of 2/)
  // The denial hands over the *same* remedy the advisory recommends, narrow form
  // first: a model told to run a different command than the advisory printed is
  // two answers to one question.
  assert.match(first, /icacls "D:\\ws" \/grant "\$env:USERNAME:\(OI\)\(CI\)\(WO\)"/)
  const last = denialText(failure, 3, 2, 2)
  assert.match(last, /automatic block 2 of 2/)
  assert.match(last, /the last one/, 'the model must know the budget is spent, not expect another block')
  assert.doesNotMatch(last, /after that the call is allowed again/, 'the last block must not promise a further block')
})

test('a denial for a failure with no path omits the fix line rather than faking one', () => {
  const failure = classifyProvisioningFailure('SetNamedSecurityInfoW failed (Win32 5)')
  assert.ok(failure)
  const text = denialText(failure, 2, 1, 1)
  assert.doesNotMatch(text, /icacls/)
  assert.match(text, /Stop, and either apply the fix or hand the problem to the user/)
})

/**
 * The second family's producer strings, taken from the throwing sites:
 * `packages/terminal/terminal-bash/src/session.ts` and `src/index.ts`, both on
 * the `waitReason === 'session_exit'` branch — the report #7638 is against.
 */
const PTY_EXIT = 'PTY shell exited during startup'

test('the persistent-shell failure is recognized, and only as a whole line', () => {
  const failure = classifyPtyStartupFailure(PTY_EXIT)
  assert.ok(failure, 'the reported string must classify')
  assert.equal(failure.family, 'pty-startup')
  assert.equal(failureLine(failure), PTY_EXIT)
  // The envelope a tool result adds is the only decoration that is still the
  // producer speaking.
  assert.ok(classifyPtyStartupFailure(`Error: ${PTY_EXIT}`))

  // Anything else that contains the sentence is quoting it, not producing it:
  // a transcript, a log the failing command printed, a pasted report. The
  // producer's message has no fields, so there is nothing else to anchor on —
  // the whole line IS the signature.
  for (const message of [
    `bash: cat terminal.log | grep -c 'PTY shell exited during startup'`,
    `See #7638: PTY shell exited during startup when minimal meets a sandbox`,
    `${PTY_EXIT} (see docs)`,
    `error: ${PTY_EXIT}`,
    'PTY shell did not reach readiness before startup timeout',
    'PTY session is closing',
    'PTY session has exited',
  ]) {
    assert.equal(classifyPtyStartupFailure(message), undefined, `must not classify: ${message}`)
  }
  // A stack trace after the producer's line is the producer's line: the message
  // a thrown `Error` carries never includes the frames, but an envelope of them
  // does not change which sentence failed.
  assert.ok(classifyPtyStartupFailure(`${PTY_EXIT}\n  at LocalPtySession.initialize`))
})

test('neither family claims the other family\'s message', () => {
  // The entry classifies the ACL family first and the persistent-shell family
  // second, so each producer's text has to belong to exactly one of them —
  // otherwise the second family's diagnosis would never be reached. (A
  // synthetic string carrying BOTH producers' lines is not a message any single
  // producer writes; the ACL branch simply wins it, which is what the entry's
  // order documents.)
  assert.equal(classifyProvisioningFailure(PTY_EXIT), undefined)
  assert.equal(classifyPtyStartupFailure(REPORTED), undefined)
  assert.equal(classifyProvisioningFailure(REPORTED)?.family, 'acl-provisioning')
  assert.equal(classifyPtyStartupFailure(PTY_EXIT)?.family, 'pty-startup')
  // The shell rule is a whole-line rule, not a substring rule: a line that
  // merely contains the ACL producer's API name is not the other family.
  assert.equal(classifyPtyStartupFailure(`Error: ${REPORTED}`), undefined)
})

test('the persistent-shell advisory names the mode, the combination, and the user-side paths', () => {
  const failure = classifyPtyStartupFailure(PTY_EXIT)
  assert.ok(failure)
  const text = advisoryText(failure, { mode: 'workspace-write', tool: 'pwsh' })
  // Sentences are asserted against a whitespace-flattened copy: the advisory is
  // hard-wrapped for a terminal, and a phrase crossing a wrap is still one claim.
  const flat = text.replace(/\s+/g, ' ')
  // The line the user is staring at, quoted verbatim.
  assert.match(flat, /^Persistent shell failed to start[\s\S]*PTY shell exited during startup/)
  // The discriminator the reporter's own control isolated, and the mode actually in force.
  assert.match(flat, /PERSISTENT PTY session/)
  assert.match(flat, /sandbox mode is `workspace-write` — not `danger-full-access`/)
  assert.match(flat, /persistent PTY × confining sandbox is the combination that fails/)
  // The call being advised about, named.
  assert.match(flat, /The `pwsh` tool is a PERSISTENT PTY session/)
  // The instruction the model must follow...
  assert.match(flat, /Do NOT retry, and do not look for a command that fixes it/)
  assert.match(flat, /there is no shell to run a command in/)
  assert.match(flat, /Use your file read\/write tools instead/)
  // ...and the remedy addressed to the user, matching the report's own workarounds.
  assert.match(flat, /switch the agent preset to `standard`/)
  // The override route, named as the patch layer it actually is. This arm is
  // also the regression guard for a remedy that reads plausibly and does not
  // work: `$DSH_HOME/.agent-presets/<id>/` is the pre-declarative preset
  // directory, and nothing reads it any more.
  assert.match(flat, /override the `preset-minimal` row in your profile patch/)
  assert.match(flat, /\$DSH_HOME\/profiles\/<profile>\/cordis\.patch\.yml/)
  assert.match(flat, /\$DSH_HOME\/cordis\.patch\.yml/)
  assert.doesNotMatch(flat, /\.agent-presets/)
  assert.match(flat, /@deepseek-ai\/dsh-tool-pwsh/)
  assert.match(flat, /run the session with `danger-full-access`/)
  assert.match(flat, new RegExp(PTY_DISCUSSIONS))
  // What it must NOT say: the ACL family's story, or a command to paste.
  assert.doesNotMatch(text, /icacls/)
  assert.doesNotMatch(text, /WRITE_OWNER/)
  assert.doesNotMatch(text, /USERNAME/)
  // The negative decision is stated, not implied: silence would read as "not the sandbox".
  assert.match(flat, /this plugin stays silent, because a shell can fail to start for other reasons/)
})

test('the persistent-shell advisory covers the unowned tool and url variants', () => {
  const failure = classifyPtyStartupFailure(PTY_EXIT)
  assert.ok(failure)
  // Without a tool name the advice is still addressed to the call that failed.
  assert.match(advisoryText(failure, { mode: 'read-only' }), /This tool is a PERSISTENT PTY session/)
  // An href replaces the thread line, exactly as in the ACL family.
  const linked = advisoryText(failure, { mode: 'read-only', href: 'https://example.invalid/t/9' })
  assert.match(linked, /tracked upstream: https:\/\/example\.invalid\/t\/9/)
  assert.doesNotMatch(linked, new RegExp(PTY_DISCUSSIONS))
  assert.match(linked, /`read-only`/)
})

test('the persistent-shell advisory refuses to be built without the mode it explains', () => {
  const failure = classifyPtyStartupFailure(PTY_EXIT)
  assert.ok(failure)
  // The gate in `src/index.ts` resolves the mode before it can get here, so this
  // is the invariant that keeps a mode-less advisory from ever existing.
  assert.throws(() => advisoryText(failure), /requires the resolved sandbox mode/)
  assert.throws(() => advisoryText(failure, { tool: 'pwsh' }), /requires the resolved sandbox mode/)
})

test('each family explains itself instead of borrowing the other\'s story', () => {
  const acl = advisoryText(classifyProvisioningFailure(REPORTED))
  const pty = advisoryText(classifyPtyStartupFailure(PTY_EXIT), { mode: 'read-only' })
  assert.notEqual(acl, pty)
  assert.match(pty, /`read-only`/, 'the mode is quoted as resolved, without translation')
  assert.doesNotMatch(pty, /MERGED write|SACL|SeSecurityPrivilege/)
})

test('the loader status is recognized from the canonical value, in both spellings of the sign', () => {
  // #7877 pastes the signed form; the unsigned NTSTATUS spelling is the same
  // number. `>>> 0` is what makes the classifier indifferent to which one arrives.
  for (const exitCode of [-1073741502, 3221225794, 0xC0000142]) {
    const failure = classifyNativeInitDeath(foreground(exitCode))
    assert.ok(failure, `must classify: ${String(exitCode)}`)
    assert.equal(failure.family, 'native-init')
    assert.equal(failure.rawExitCode, exitCode, 'the code as reported is kept, so it can be quoted back')
    assert.equal(failure.exitCode, STATUS_DLL_INIT_FAILED)
    assert.equal(failureLine(failure), `[exit code: ${String(exitCode)}]`)
  }
  assert.equal(STATUS_DLL_INIT_FAILED, 0xC0000142)
})

test('a value that is not the shipped foreground projection is refused', () => {
  // The family is read from a result the pipeline calls a success, so the
  // discriminator that keeps other tools out is the projection's own `kind` —
  // and the neighbouring statuses are other stories this module must not tell.
  for (const value of [
    undefined,
    null,
    'foreground',
    42,
    [],
    {},
    { exitCode: -1073741502 },
    { kind: 'background', exitCode: -1073741502 },
    { kind: 'foreground' },
    { kind: 'foreground', exitCode: null },
    { kind: 'foreground', exitCode: '-1073741502' },
    { kind: 'foreground', exitCode: 1.5 },
    // Other Windows statuses with their own causes: the Cygwin/MSYS2 runtime's
    // deliberate fast-fail, and a missing DLL (a packaging problem, not a
    // sandbox one). Neither is this family.
    { kind: 'foreground', exitCode: -1073740791 }, // 0xC0000409
    { kind: 'foreground', exitCode: -1073741515 }, // 0xC0000135
    { kind: 'foreground', exitCode: 127 }, // the one code the runner-failure rule owns
    { kind: 'foreground', exitCode: 1 },
    { kind: 'foreground', exitCode: 0 },
  ]) {
    assert.equal(classifyNativeInitDeath(value), undefined, `must not classify: ${JSON.stringify(value)}`)
  }
})

test('the native-init advisory names the class, both producers, and their checks', () => {
  const failure = classifyNativeInitDeath(foreground(NATIVE_DEATH, MSYS2_STDERR))
  assert.ok(failure)
  const text = advisoryText(failure, { mode: 'read-only', tool: 'pwsh', electronHost: false })
  const flat = text.replace(/\s+/g, ' ')
  // The code, quoted as the tool reported it and named for what it is.
  assert.match(flat, /\[exit code: -1073741502\]/)
  assert.match(flat, /0xC0000142 STATUS_DLL_INIT_FAILED/)
  // The claim that makes it a diagnosis rather than a restatement: the process
  // never reached its entry point, and the number is not a portable status.
  assert.match(flat, /BEFORE the program's entry point/)
  assert.match(flat, /those are 0-255, and this is a 32-bit NTSTATUS/)
  // The mode the call ran under is stated, and is where the sandbox becomes a
  // candidate rather than an assertion.
  assert.match(flat, /sandbox mode `read-only`/)
  assert.match(flat, /Nothing in the code says "sandbox" by itself/)
  // It enumerates rather than asserts: the header is the claim that this is a
  // list to be checked, not a cause that was identified.
  assert.match(flat, /Two producers have been measured under a confining Windows mode\. Check which one this is:/)
  // Producer 1: the MSYS2 runtime, with the report's own line and the one
  // conversion the model can actually make.
  assert.match(flat, /couldn't create signal pipe, Win32 error 5/)
  assert.match(flat, /#7877/)
  assert.match(flat, /write the same work as a PowerShell or `cmd` command instead/)
  // Producer 2: the packaged desktop runner, with the mechanism and the report's
  // discriminator.
  assert.match(flat, /ELECTRON_RUN_AS_NODE=1/)
  assert.match(flat, /\[process\.execPath, runner\.js\]/)
  assert.match(flat, /#7876/)
  // The measured fact about THIS process, not an assumption about it: this arm
  // runs off the packaged desktop, so the producer that needs Electron is ruled
  // out — and it says why.
  assert.match(flat, /This process is NOT an Electron binary/)
  assert.match(flat, /the runner is a real Node binary here/)
  assert.doesNotMatch(flat, /This process IS an Electron binary/)
  // The instruction, and the boundary that keeps the claim honest.
  assert.match(flat, /Do not retry this call/)
  assert.match(flat, /Convert the work only in case 1; otherwise stop and hand it to the user/)
  assert.match(flat, /producers this list does not have/)
  assert.match(flat, /hidden console window/)
  // What it must NOT say: the other families' stories, or an offer to widen the
  // sandbox as a remedy.
  assert.doesNotMatch(text, /icacls|WRITE_OWNER|SeSecurityPrivilege/)
  assert.doesNotMatch(text, /PTY shell exited during startup/)
  assert.doesNotMatch(flat, /use danger-full-access to fix/)
  assert.match(flat, /`danger-full-access` is not offered as a fix/)
  assert.match(flat, new RegExp(NATIVE_INIT_DISCUSSIONS))
})

test('the Electron fact is reported, so the same code reads differently on the two hosts', () => {
  // The check is a fact the plugin measures rather than one it asks the reader
  // for, so the two answers must actually differ — a producer list that reads the
  // same either way would be a guess wearing a measurement's clothes.
  const failure = classifyNativeInitDeath(foreground(NATIVE_DEATH))
  assert.ok(failure)
  const onElectron = advisoryText(failure, { mode: 'workspace-write', electronHost: true })
  const offElectron = advisoryText(failure, { mode: 'workspace-write', electronHost: false })
  assert.notEqual(onElectron, offElectron)
  assert.match(onElectron.replace(/\s+/g, ' '), /This process IS an Electron binary/)
  assert.doesNotMatch(onElectron.replace(/\s+/g, ' '), /This process is NOT an Electron binary/)
  // Everything else about the two texts is identical: only the finding — and the
  // next step it implies — differs. The rest of the advisory is one text, not two.
  const head = text => text.slice(0, text.indexOf('     This process '))
  const tail = text => text.slice(text.indexOf('Do not retry this call'))
  assert.equal(head(onElectron), head(offElectron))
  assert.equal(tail(onElectron), tail(offElectron))
  // Each branch ends with a next step rather than a dead end: the Electron host
  // gets the report's own discriminator, the other one is told the failure is
  // outside both measured producers.
  assert.match(onElectron.replace(/\s+/g, ' '), /run the same command with `danger-full-access`/)
  assert.match(onElectron.replace(/\s+/g, ' '), /unpacked `node apps\/cli\/lib\/bin\.js web`/)
  assert.match(offElectron.replace(/\s+/g, ' '), /outside both measured producers/)
  // With no explicit answer the plugin asks the live process, which on the host
  // this suite runs on is not Electron — and says so rather than staying silent.
  assert.match(advisoryText(failure, { mode: 'workspace-write' }), /This process is NOT an Electron binary/)
})

test('the native-init advisory refuses to be built without the mode it explains', () => {
  const failure = classifyNativeInitDeath(foreground(NATIVE_DEATH))
  assert.ok(failure)
  assert.throws(() => advisoryText(failure), /requires the resolved sandbox mode/)
  assert.throws(() => advisoryText(failure, { tool: 'pwsh' }), /requires the resolved sandbox mode/)
})

test('the third family names itself, and borrows neither of the other two stories', () => {
  const native = advisoryText(classifyNativeInitDeath(foreground(NATIVE_DEATH)), { mode: 'read-only' })
  assert.match(native, /`read-only`/)
  assert.notEqual(native, advisoryText(classifyProvisioningFailure(REPORTED)))
  assert.notEqual(native, advisoryText(classifyPtyStartupFailure(PTY_EXIT), { mode: 'read-only' }))
  // An href replaces the thread line, exactly as in the other two families.
  const linked = advisoryText(classifyNativeInitDeath(foreground(NATIVE_DEATH)), {
    mode: 'read-only',
    href: 'https://example.invalid/t/11',
  })
  assert.match(linked, /tracked upstream: https:\/\/example\.invalid\/t\/11/)
  assert.doesNotMatch(linked, new RegExp(NATIVE_INIT_DISCUSSIONS))
})

test('the three families share no message: each producer\'s input reaches exactly one classifier', () => {
  assert.equal(classifyProvisioningFailure(PTY_EXIT), undefined)
  assert.equal(classifyPtyStartupFailure(REPORTED), undefined)
  // The native-init family is not text-driven at all, so no message can reach it
  // and no value can reach the other two.
  assert.equal(classifyNativeInitDeath(REPORTED), undefined)
  assert.equal(classifyNativeInitDeath(PTY_EXIT), undefined)
  assert.equal(classifyProvisioningFailure('[exit code: -1073741502]'), undefined)
  assert.equal(classifyPtyStartupFailure('[exit code: -1073741502]'), undefined)
})
