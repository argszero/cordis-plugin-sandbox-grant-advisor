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

import { advisoryText, denialText, DISCUSSIONS, PREREQUISITE } from '../lib/advice.js'
import { classifyProvisioningFailure, failureLine } from '../lib/signature.js'

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
  assert.match(text, new RegExp(DISCUSSIONS.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.match(text, /neither edits ACLs nor elevates/)
})

test('an href replaces the thread line without dropping the fix', () => {
  const failure = classifyProvisioningFailure(REPORTED)
  assert.ok(failure)
  const text = advisoryText(failure, 'https://example.invalid/t/1')
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
