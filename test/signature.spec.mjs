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

import { advisoryText, denialText, ACL_DISCUSSIONS, PREREQUISITE, PTY_DISCUSSIONS } from '../lib/advice.js'
import { classifyProvisioningFailure, classifyPtyStartupFailure, failureLine } from '../lib/signature.js'

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
  // The missing right, the remedy, and the mask that lacks it.
  assert.match(text, /WRITE_OWNER/)
  assert.match(text, /icacls "D:\\ws" \/grant "\$env:USERNAME:\(OI\)\(CI\)F"/)
  assert.match(text, /icacls "D:\\ws" \/grant "%USERNAME%:\(OI\)\(CI\)F"/)
  assert.match(text, /0x1301bf/)
  // The natural-but-wrong hypothesis is addressed rather than ignored.
  assert.match(text, /SeSecurityPrivilege is the wrong lever/)
  assert.match(text, /whoami \/priv/)
  // The documented prerequisite, the upstream threads, and the boundary.
  assert.match(text, new RegExp(PREREQUISITE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.match(text, new RegExp(ACL_DISCUSSIONS.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.match(text, /neither edits ACLs nor elevates/)
})

test('an href replaces the thread line without dropping the fix', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure, { href: 'https://example.invalid/t/1' })
  assert.match(text, /tracked upstream: https:\/\/example\.invalid\/t\/1/)
  assert.match(text, /WRITE_OWNER/)
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
  assert.match(first, /icacls "D:\\ws"/)
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
